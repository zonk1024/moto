from __future__ import unicode_literals

import re

import six
from six.moves.urllib.parse import parse_qs, urlparse
import xmltodict

from moto.core.responses import _TemplateEnvironmentMixin

from .exceptions import BucketAlreadyExists, S3ClientError, InvalidPartOrder
from .models import s3_backend, get_canned_acl, FakeGrantee, FakeGrant, FakeAcl
from .utils import metadata_from_headers
from xml.dom import minidom

REGION_URL_REGEX = r'\.s3-(.+?)\.amazonaws\.com'
DEFAULT_REGION_NAME = 'us-east-1'


def parse_key_name(pth):
    return pth.lstrip("/")


class RequestObject(object):
    """
    A class to parse S3 URLs
    """
    bucket_name_regex = re.compile("(.+).s3(.*).amazonaws.com")
    region_url_regex = r'\.s3-(.+?)\.amazonaws\.com'

    def __init__(self, request, full_url, headers):
        self.request = request
        self.full_url = full_url
        self.headers = headers

    @property
    def is_key_type(self):
        return bool(self.key_name)

    @property
    def is_bucket_type(self):
        return not self.is_key_type

    @property
    def method(self):
        return self.request.method

    @property
    def parsed_url(self):
        if not hasattr(self, '_parsed_url'):
            self._parsed_url = urlparse(self.full_url)
        return self._parsed_url

    @property
    def domain(self):
        return self.parsed_url.netloc

    @property
    def stripped_domain(self):
        return self.domain if not self.domain.startswith('www.') else self.domain[4:]

    @property
    def bucket_name_domain_regex(self):
        return re.search(self.bucket_name_regex, self.stripped_domain)

    @property
    def bucket_name_in_domain(self):
        return bool(self.bucket_name_domain_regex)

    @property
    def bucket_name_in_path(self):
        return not self.bucket_name_in_domain

    @property
    def region(self):
        region_match = re.search(self.region_url_regex, self.stripped_domain)

    @property
    def path(self):
        return self.parsed_url.path.lstrip('/')

    @property
    def query(self):
        return self.parsed_url.query

    @property
    def query_dict(self):
        return parse_qs(self.query, keep_blank_values=True)

    @property
    def bucket_name(self):
        if self.stripped_domain == 's3.amazonaws.com':
            return self.path.lstrip('/').split('/')[0]
        elif self.bucket_name_in_domain:
            return self.bucket_name_domain_regex.groups()[0]
        elif '.' in self.stripped_domain:
            return self.stripped_domain.split('.')[0]

    @property
    def key_name(self):
        if self.bucket_name_in_path:
            return '/'.join(self.path.split('/')[1:])
        return self.path

    @property
    def has_body(self):
        return hasattr(self, 'body')

    @property
    def has_data(self):
        return hasattr(self, 'data')

    @property
    def body(self):
        if self.has_body:
            return self.request.body
        elif self.has_data:
            return self.request.data
        return None

    @property
    def has_form(self):
        return hasattr(self.request, 'form')

    @property
    def form(self):
        if self.has_form:
            return self.request.form
        return None

    @property
    def files(self):
        return self.request.files


class ResponseObject(_TemplateEnvironmentMixin):
    def __init__(self, backend, is_delete_keys=None):
        super(ResponseObject, self).__init__()
        self.backend = backend
        if is_delete_keys:
            self.is_delete_keys = is_delete_keys

    @staticmethod
    def is_delete_keys(path, bucket_name):
        return path == u'/?delete'

    def all_buckets(self):
        # No bucket specified. Listing all buckets
        all_buckets = self.backend.get_all_buckets()
        template = self.response_template(S3_ALL_BUCKETS)
        return template.render(buckets=all_buckets)

    def routed_response(self, request, full_url, headers):
        # TODO: This object should be passed in place of the data it contains
        #       ... keep it DRY
        s3_request = RequestObject(request, full_url, headers)
        if s3_request.is_bucket_type:
            return self.bucket_response(s3_request)
        else:
            return self.key_response(s3_request)

    def bucket_response(self, s3_request):
        try:
            response = self._bucket_response(s3_request)
        except S3ClientError as s3error:
            response = s3error.code, s3_request.headers, s3error.description

        if isinstance(response, six.string_types):
            return 200, s3_request.headers, response.encode("utf-8")
        else:
            status_code, headers, response_content = response
            return status_code, headers, response_content.encode("utf-8")

    def _bucket_response(self, s3_request):
        bucket_name = s3_request.bucket_name
        method = s3_request.method
        querystring = s3_request.query
        region_name = s3_request.region

        if not bucket_name:
            # If no bucket specified, list all buckets
            return self.all_buckets()

        if hasattr(s3_request.request, 'body'):
            # Boto
            body = s3_request.request.body
        else:
            # Flask server
            body = s3_request.request.data
        body = body.decode('utf-8')

        if method == 'HEAD':
            return self._bucket_response_head(s3_request)
        elif method == 'GET':
            return self._bucket_response_get(s3_request)
        elif method == 'PUT':
            return self._bucket_response_put(s3_request)
        elif method == 'DELETE':
            return self._bucket_response_delete(s3_request)
        elif method == 'POST':
            return self._bucket_response_post(s3_request)
        else:
            raise NotImplementedError("Method {0} has not been impelemented in the S3 backend yet".format(method))

    def _bucket_response_head(self, s3_request):
        self.backend.get_bucket(s3_request.bucket_name)
        return 200, s3_request.headers, ""

    def _bucket_response_get(self, s3_request):
        if 'uploads' in s3_request.query_dict:
            for unsup in ('delimiter', 'max-uploads'):
                if unsup in s3_request.query_dict:
                    raise NotImplementedError("Listing multipart uploads with {} has not been implemented yet.".format(unsup))
            multiparts = list(self.backend.get_all_multiparts(s3_request.bucket_name).values())
            if 'prefix' in s3_request.query_dict:
                prefix = s3_request.query_dict.get('prefix', [None])[0]
                multiparts = [upload for upload in multiparts if upload.key_name.startswith(prefix)]
            template = self.response_template(S3_ALL_MULTIPARTS)
            return template.render(
                bucket_name=s3_request.bucket_name,
                uploads=multiparts)
        elif 'location' in s3_request.query_dict:
            bucket = self.backend.get_bucket(s3_request.bucket_name)
            template = self.response_template(S3_BUCKET_LOCATION)
            return template.render(location=bucket.location)
        elif 'lifecycle' in s3_request.query_dict:
            bucket = self.backend.get_bucket(s3_request.bucket_name)
            if not bucket.rules:
                return 404, s3_request.headers, "NoSuchLifecycleConfiguration"
            template = self.response_template(S3_BUCKET_LIFECYCLE_CONFIGURATION)
            return template.render(rules=bucket.rules)
        elif 'versioning' in s3_request.query_dict:
            versioning = self.backend.get_bucket_versioning(s3_request.bucket_name)
            template = self.response_template(S3_BUCKET_GET_VERSIONING)
            return template.render(status=versioning)
        elif 'policy' in s3_request.query_dict:
            policy = self.backend.get_bucket_policy(s3_request.bucket_name)
            if not policy:
                template = self.response_template(S3_NO_POLICY)
                return 404, s3_request.headers, template.render(bucket_name=s3_request.bucket_name)
            return 200, s3_request.headers, policy
        elif 'website' in s3_request.query_dict:
            website_configuration = self.backend.get_bucket_website_configuration(s3_request.bucket_name)
            return website_configuration
        elif 'acl' in s3_request.query_dict:
            bucket = self.backend.get_bucket(s3_request.bucket_name)
            template = self.response_template(S3_OBJECT_ACL_RESPONSE)
            return template.render(obj=bucket)
        elif 'versions' in s3_request.query_dict:
            delimiter = s3_request.query_dict.get('delimiter', [None])[0]
            encoding_type = s3_request.query_dict.get('encoding-type', [None])[0]
            key_marker = s3_request.query_dict.get('key-marker', [None])[0]
            max_keys = s3_request.query_dict.get('max-keys', [None])[0]
            prefix = s3_request.query_dict.get('prefix', [None])[0]
            version_id_marker = s3_request.query_dict.get('version-id-marker', [None])[0]

            bucket = self.backend.get_bucket(s3_request.bucket_name)
            versions = self.backend.get_bucket_versions(
                s3_request.bucket_name,
                delimiter=delimiter,
                encoding_type=encoding_type,
                key_marker=key_marker,
                max_keys=max_keys,
                version_id_marker=version_id_marker
            )
            template = self.response_template(S3_BUCKET_GET_VERSIONS)
            return 200, s3_request.headers, template.render(
                key_list=versions,
                bucket=bucket,
                prefix='',
                max_keys='',
                delimiter='',
                is_truncated='false',
            )

        bucket = self.backend.get_bucket(s3_request.bucket_name)
        prefix = s3_request.query_dict.get('prefix', [None])[0]
        delimiter = s3_request.query_dict.get('delimiter', [None])[0]
        result_keys, result_folders = self.backend.prefix_query(bucket, prefix, delimiter)
        template = self.response_template(S3_BUCKET_GET_RESPONSE)
        return 200, s3_request.headers, template.render(
            bucket=bucket,
            prefix=prefix,
            delimiter=delimiter,
            result_keys=result_keys,
            result_folders=result_folders
        )

    def _bucket_response_put(self, s3_request):
        if 'versioning' in s3_request.query_dict:
            ver = re.search('<Status>([A-Za-z]+)</Status>', s3_request.body)
            if ver:
                self.backend.set_bucket_versioning(s3_request.bucket_name, ver.group(1))
                template = self.response_template(S3_BUCKET_VERSIONING)
                return template.render(bucket_versioning_status=ver.group(1))
            else:
                return 404, s3_request.headers, ""
        elif 'lifecycle' in s3_request.query_dict:
            rules = xmltodict.parse(s3_request.body)['LifecycleConfiguration']['Rule']
            if not isinstance(rules, list):
                # If there is only one rule, xmldict returns just the item
                rules = [rules]
            self.backend.set_bucket_lifecycle(s3_request.bucket_name, rules)
            return ""
        elif 'policy' in s3_request.query_dict:
            self.backend.set_bucket_policy(s3_request.bucket_name, s3_request.body)
            return 'True'
        elif 'acl' in s3_request.query_dict:
            acl = self._acl_from_headers(s3_request.headers)
            # TODO: Support the XML-based ACL format
            self.backend.set_bucket_acl(s3_request.bucket_name, acl)
            return ""
        elif 'website' in s3_request.query_dict:
            self.backend.set_bucket_website_configuration(s3_request.bucket_name, s3_request.body)
            return ""
        else:
            try:
                new_bucket = self.backend.create_bucket(s3_request.bucket_name, s3_request.region)
            except BucketAlreadyExists:
                if s3_request.region == DEFAULT_REGION_NAME:
                    # us-east-1 has different behavior
                    new_bucket = self.backend.get_bucket(s3_request.bucket_name)
                else:
                    raise
            template = self.response_template(S3_BUCKET_CREATE_RESPONSE)
            return 200, s3_request.headers, template.render(bucket=new_bucket)

    def _bucket_response_delete(self, s3_request):
        if 'policy' in s3_request.query_dict:
            self.backend.delete_bucket_policy(s3_request.bucket_name, s3_request.body)
            return 204, s3_request.headers, ""
        elif 'lifecycle' in s3_request.query_dict:
            bucket = self.backend.get_bucket(s3_request.bucket_name)
            bucket.delete_lifecycle()
            return 204, s3_request.headers, ""

        removed_bucket = self.backend.delete_bucket(s3_request.bucket_name)

        if removed_bucket:
            # Bucket exists
            template = self.response_template(S3_DELETE_BUCKET_SUCCESS)
            return 204, s3_request.headers, template.render(bucket=removed_bucket)
        else:
            # Tried to delete a bucket that still has keys
            template = self.response_template(S3_DELETE_BUCKET_WITH_ITEMS_ERROR)
            return 409, s3_request.headers, template.render(bucket=removed_bucket)

    def _bucket_response_post(self, s3_request):
        if self.is_delete_keys(s3_request.path, s3_request.bucket_name):
            return self._bucket_response_delete_keys(s3_request)

        # POST to bucket-url should create file from form
        if s3_request.has_form:
            # Not HTTPretty
            form = s3_request.form
        else:
            # HTTPretty, build new form object
            form = {}
            for kv in s3_request.body.decode('utf-8').split('&'):
                k, v = kv.split('=')
                form[k] = v

        key = form['key']
        if 'file' in form:
            f = form['file']
        else:
            f = s3_request.files['file'].stream.read()

        new_key = self.backend.set_key(s3_request.bucket_name, key, f)

        # Metadata
        metadata = metadata_from_headers(form)
        new_key.set_metadata(metadata)

        return 200, s3_request.headers, ""

    def _bucket_response_delete_keys(self, s3_request):
        template = self.response_template(S3_DELETE_KEYS_RESPONSE)

        keys = minidom.parseString(s3_request.body.decode('utf-8')).getElementsByTagName('Key')
        deleted_names = []
        error_names = []

        for k in keys:
            try:
                key_name = k.firstChild.nodeValue
                self.backend.delete_key(s3_request.bucket_name, key_name)
                deleted_names.append(key_name)
            except KeyError:
                error_names.append(key_name)

        return 200, s3_request.headers, template.render(deleted=deleted_names, delete_errors=error_names)

    def _handle_range_header(self, s3_request, headers, response_content):
        length = len(response_content)
        last = length - 1
        _, rspec = s3_request.headers.get('range').split('=')
        if ',' in rspec:
            raise NotImplementedError(
                "Multiple range specifiers not supported")
        toint = lambda i: int(i) if i else None
        begin, end = map(toint, rspec.split('-'))
        if begin is not None:  # byte range
            end = last if end is None else min(end, last)
        elif end is not None:  # suffix byte range
            begin = length - min(end, length)
            end = last
        else:
            return 400, headers, ""
        if begin < 0 or end > last or begin > min(end, last):
            return 416, headers, ""
        headers['content-range'] = "bytes {0}-{1}/{2}".format(
            begin, end, length)
        return 206, headers, response_content[begin:end + 1]

    def key_response(self, s3_request):
        headers = s3_request.headers
        try:
            response = self._key_response(s3_request)
        except S3ClientError as s3error:
            response = s3error.code, s3_request.headers, s3error.description

        if isinstance(response, six.string_types):
            status_code = 200
            response_content = response
        else:
            status_code, headers, response_content = response

        if status_code == 200 and 'range' in s3_request.headers:
            return self._handle_range_header(s3_request, headers, response_content)
        return status_code, headers, response_content

    def _key_response(self, s3_request):
        bucket_name = s3_request.bucket_name
        query = s3_request.query_dict
        key_name = s3_request.key_name
        method = s3_request.method

        if method == 'GET':
            return self._key_response_get(s3_request)
        elif method == 'PUT':
            return self._key_response_put(s3_request)
        elif method == 'HEAD':
            return self._key_response_head(s3_request)
        elif method == 'DELETE':
            return self._key_response_delete(s3_request)
        elif method == 'POST':
            return self._key_response_post(s3_request)
        else:
            raise NotImplementedError("Method {0} has not been impelemented in the S3 backend yet".format(method))

    def _key_response_get(self, s3_request):
        if s3_request.query_dict.get('uploadId'):
            upload_id = s3_request.query_dict['uploadId'][0]
            parts = self.backend.list_multipart(s3_request.bucket_name, upload_id)
            template = self.response_template(S3_MULTIPART_LIST_RESPONSE)
            return 200, s3_request.headers, template.render(
                bucket_name=s3_request.bucket_name,
                key_name=s3_request.key_name,
                upload_id=upload_id,
                count=len(parts),
                parts=parts
            )
        version_id = s3_request.query_dict.get('versionId', [None])[0]
        key = self.backend.get_key(
            s3_request.bucket_name, s3_request.key_name, version_id=version_id)
        if 'acl' in s3_request.query_dict:
            template = self.response_template(S3_OBJECT_ACL_RESPONSE)
            return 200, s3_request.headers, template.render(obj=key)

        if key:
            s3_request.headers.update(key.metadata)
            return 200, s3_request.headers, key.value
        else:
            return 404, s3_request.headers, ""

    def _key_response_put(self, s3_request):
        if s3_request.query_dict.get('uploadId') and query.get('partNumber'):
            upload_id = s3_request.query_dict['uploadId'][0]
            part_number = int(s3_request.query_dict['partNumber'][0])
            if 'x-amz-copy-source' in s3_request.headers:
                src = s3_request.headers.get("x-amz-copy-source")
                src_bucket, src_key = src.split("/", 1)
                key = self.backend.copy_part(
                    s3_request.bucket_name, upload_id, part_number, src_bucket,
                    src_key)
                template = self.response_template(S3_MULTIPART_UPLOAD_RESPONSE)
                response = template.render(part=key)
            else:
                key = self.backend.set_part(
                    s3_request.bucket_name, upload_id, part_number, body)
                response = ""
            s3_request.headers.update(key.response_dict)
            return 200, s3_request.headers, response

        storage_class = s3_request.headers.get('x-amz-storage-class', 'STANDARD')
        acl = self._acl_from_headers(s3_request.headers)

        if 'acl' in s3_request.query_dict:
            key = self.backend.get_key(s3_request.bucket_name, s3_request.key_name)
            # TODO: Support the XML-based ACL format
            key.set_acl(acl)
            return 200, s3_request.headers, ""

        if 'x-amz-copy-source' in s3_request.headers:
            # Copy key
            src_bucket, src_key = s3_request.headers.get("x-amz-copy-source").split("/", 1)
            self.backend.copy_key(src_bucket, src_key, s3_request.bucket_name, s3_request.key_name,
                                  storage=storage_class, acl=acl)
            mdirective = s3_request.request.headers.get('x-amz-metadata-directive')
            if mdirective is not None and mdirective == 'REPLACE':
                new_key = self.backend.get_key(s3_request.bucket_name, s3_request.key_name)
                metadata = metadata_from_headers(s3_request.headers)
                new_key.set_metadata(metadata, replace=True)
            template = self.response_template(S3_OBJECT_COPY_RESPONSE)
            return template.render(key=src_key)
        streaming_request = hasattr(s3_request.request, 'streaming') and s3_request.request.streaming
        closing_connection = s3_request.headers.get('connection') == 'close'
        if closing_connection and streaming_request:
            # Closing the connection of a streaming request. No more data
            new_key = self.backend.get_key(s3_request.bucket_name, s3_request.key_name)
        elif streaming_request:
            # Streaming request, more data
            new_key = self.backend.append_to_key(s3_request.bucket_name, s3_request.key_name, s3_request.body)
        else:
            # Initial data
            new_key = self.backend.set_key(s3_request.bucket_name, s3_request.key_name, s3_request.body,
                                           storage=storage_class)
            s3_request.request.streaming = True
            metadata = metadata_from_headers(s3_request.headers)
            new_key.set_metadata(metadata)
            new_key.set_acl(acl)

        template = self.response_template(S3_OBJECT_RESPONSE)
        s3_request.headers.update(new_key.response_dict)
        return 200, s3_request.headers, template.render(key=new_key)

    def _key_response_head(self, s3_request):
        key = self.backend.get_key(s3_request.bucket_name, s3_request.key_name)
        if key:
            s3_request.headers.update(key.metadata)
            s3_request.headers.update(key.response_dict)
            return 200, s3_request.headers, key.value
        else:
            return 404, s3_request.headers, ""

    def _acl_from_headers(self, headers):
        canned_acl = headers.get('x-amz-acl', '')
        if canned_acl:
            return get_canned_acl(canned_acl)

        grants = []
        for header, value in headers.items():
            if not header.startswith('x-amz-grant-'):
                continue

            permission = {
                'read': 'READ',
                'write': 'WRITE',
                'read-acp': 'READ_ACP',
                'write-acp': 'WRITE_ACP',
                'full-control': 'FULL_CONTROL',
            }[header[len('x-amz-grant-'):]]

            grantees = []
            for key_and_value in value.split(","):
                key, value = re.match('([^=]+)="([^"]+)"', key_and_value.strip()).groups()
                if key.lower() == 'id':
                    grantees.append(FakeGrantee(id=value))
                else:
                    grantees.append(FakeGrantee(uri=value))
            grants.append(FakeGrant(grantees, [permission]))

        if grants:
            return FakeAcl(grants)
        else:
            return None

    def _key_response_delete(self, s3_request):
        if s3_request.query_dict.get('uploadId'):
            upload_id = s3_request.query_dict['uploadId'][0]
            self.backend.cancel_multipart(s3_request.bucket_name, upload_id)
            return 204, s3_request.headers, ""
        try:
            removed_key = self.backend.delete_key(s3_request.bucket_name, s3_request.key_name)
        except KeyError:
            return 404, s3_request.headers, ""
        template = self.response_template(S3_DELETE_OBJECT_SUCCESS)
        return 204, s3_request.headers, template.render(bucket=removed_key)

    def _complete_multipart_body(self, body):
        ps = minidom.parseString(body).getElementsByTagName('Part')
        prev = 0
        for p in ps:
            pn = int(p.getElementsByTagName('PartNumber')[0].firstChild.wholeText)
            if pn <= prev:
                raise InvalidPartOrder()
            yield (pn, p.getElementsByTagName('ETag')[0].firstChild.wholeText)

    def _key_response_post(self, s3_request):
        if s3_request.body == b'' and 'uploads' in s3_request.query_dict:
            metadata = metadata_from_headers(s3_request.headers)
            multipart = self.backend.initiate_multipart(s3_request.bucket_name, s3_request.key_name, metadata)

            template = self.response_template(S3_MULTIPART_INITIATE_RESPONSE)
            response = template.render(
                bucket_name=s3_request.bucket_name,
                key_name=s3_request.key_name,
                upload_id=multipart.id,
            )
            return 200, s3_request.headers, response

        if s3_request.query_dict.get('uploadId'):
            body = self._complete_multipart_body(s3_request.body)
            upload_id = s3_request.query_dict['uploadId'][0]
            key = self.backend.complete_multipart(s3_request.bucket_name, upload_id, body)
            template = self.response_template(S3_MULTIPART_COMPLETE_RESPONSE)
            return template.render(
                bucket_name=s3_request.bucket_name,
                key_name=key.name,
                etag=key.etag,
            )
        elif 'restore' in s3_request.query_dict:
            es = minidom.parseString(s3_request.body).getElementsByTagName('Days')
            days = es[0].childNodes[0].wholeText
            key = self.backend.get_key(s3_request.bucket_name, s3_request.key_name)
            r = 202
            if key.expiry_date is not None:
                r = 200
            key.restore(int(days))
            return r, s3_request.headers, ""
        else:
            raise NotImplementedError("Method POST had only been implemented for multipart uploads and restore operations, so far")

S3ResponseInstance = ResponseObject(s3_backend)

S3_ALL_BUCKETS = """<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01">
  <Owner>
    <ID>bcaf1ffd86f41161ca5fb16fd081034f</ID>
    <DisplayName>webfile</DisplayName>
  </Owner>
  <Buckets>
    {% for bucket in buckets %}
      <Bucket>
        <Name>{{ bucket.name }}</Name>
        <CreationDate>2006-02-03T16:45:09.000Z</CreationDate>
      </Bucket>
    {% endfor %}
 </Buckets>
</ListAllMyBucketsResult>"""

S3_BUCKET_GET_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>{{ bucket.name }}</Name>
  <Prefix>{{ prefix }}</Prefix>
  <MaxKeys>1000</MaxKeys>
  <Delimiter>{{ delimiter }}</Delimiter>
  <IsTruncated>false</IsTruncated>
  {% for key in result_keys %}
    <Contents>
      <Key>{{ key.name }}</Key>
      <LastModified>{{ key.last_modified_ISO8601 }}</LastModified>
      <ETag>{{ key.etag }}</ETag>
      <Size>{{ key.size }}</Size>
      <StorageClass>{{ key.storage_class }}</StorageClass>
      <Owner>
        <ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID>
        <DisplayName>webfile</DisplayName>
      </Owner>
    </Contents>
  {% endfor %}
  {% if delimiter %}
    {% for folder in result_folders %}
      <CommonPrefixes>
        <Prefix>{{ folder }}</Prefix>
      </CommonPrefixes>
    {% endfor %}
  {% endif %}
  </ListBucketResult>"""

S3_BUCKET_CREATE_RESPONSE = """<CreateBucketResponse xmlns="http://s3.amazonaws.com/doc/2006-03-01">
  <CreateBucketResponse>
    <Bucket>{{ bucket.name }}</Bucket>
  </CreateBucketResponse>
</CreateBucketResponse>"""

S3_DELETE_BUCKET_SUCCESS = """<DeleteBucketResponse xmlns="http://s3.amazonaws.com/doc/2006-03-01">
  <DeleteBucketResponse>
    <Code>204</Code>
    <Description>No Content</Description>
  </DeleteBucketResponse>
</DeleteBucketResponse>"""

S3_DELETE_BUCKET_WITH_ITEMS_ERROR = """<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>BucketNotEmpty</Code>
<Message>The bucket you tried to delete is not empty</Message>
<BucketName>{{ bucket.name }}</BucketName>
<RequestId>asdfasdfsdafds</RequestId>
<HostId>sdfgdsfgdsfgdfsdsfgdfs</HostId>
</Error>"""

S3_BUCKET_LOCATION = """<?xml version="1.0" encoding="UTF-8"?>
<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">{{ location }}</LocationConstraint>"""

S3_BUCKET_LIFECYCLE_CONFIGURATION = """<?xml version="1.0" encoding="UTF-8"?>
<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    {% for rule in rules %}
    <Rule>
        <ID>{{ rule.id }}</ID>
        <Prefix>{{ rule.prefix if rule.prefix != None }}</Prefix>
        <Status>{{ rule.status }}</Status>
        {% if rule.storage_class %}
        <Transition>
            {% if rule.transition_days %}
               <Days>{{ rule.transition_days }}</Days>
            {% endif %}
            {% if rule.transition_date %}
               <Date>{{ rule.transition_date }}</Date>
            {% endif %}
           <StorageClass>{{ rule.storage_class }}</StorageClass>
        </Transition>
        {% endif %}
        {% if rule.expiration_days or rule.expiration_date %}
        <Expiration>
            {% if rule.expiration_days %}
               <Days>{{ rule.expiration_days }}</Days>
            {% endif %}
            {% if rule.expiration_date %}
               <Date>{{ rule.expiration_date }}</Date>
            {% endif %}
        </Expiration>
        {% endif %}
    </Rule>
    {% endfor %}
</LifecycleConfiguration>
"""

S3_BUCKET_VERSIONING = """<?xml version="1.0" encoding="UTF-8"?>
<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Status>{{ bucket_versioning_status }}</Status>
</VersioningConfiguration>
"""

S3_BUCKET_GET_VERSIONING = """<?xml version="1.0" encoding="UTF-8"?>
{% if status is none %}
    <VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>
{% else %}
    <VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Status>{{ status }}</Status>
    </VersioningConfiguration>
{% endif %}
"""

S3_BUCKET_GET_VERSIONS = """<?xml version="1.0" encoding="UTF-8"?>
<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01">
    <Name>{{ bucket.name }}</Name>
    <Prefix>{{ prefix }}</Prefix>
    <KeyMarker>{{ key_marker }}</KeyMarker>
    <MaxKeys>{{ max_keys }}</MaxKeys>
    <IsTruncated>{{ is_truncated }}</IsTruncated>
    {% for key in key_list %}
    <Version>
        <Key>{{ key.name }}</Key>
        <VersionId>{{ key._version_id }}</VersionId>
        <IsLatest>false</IsLatest>
        <LastModified>{{ key.last_modified_ISO8601 }}</LastModified>
        <ETag>{{ key.etag }}</ETag>
        <Size>{{ key.size }}</Size>
        <StorageClass>{{ key.storage_class }}</StorageClass>
        <Owner>
            <ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID>
            <DisplayName>webfile</DisplayName>
        </Owner>
    </Version>
    {% endfor %}
</ListVersionsResult>
"""

S3_DELETE_KEYS_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01">
{% for k in deleted %}
<Deleted>
<Key>{{k}}</Key>
</Deleted>
{% endfor %}
{% for k in delete_errors %}
<Error>
<Key>{{k}}</Key>
</Error>
{% endfor %}
</DeleteResult>"""

S3_DELETE_OBJECT_SUCCESS = """<DeleteObjectResponse xmlns="http://s3.amazonaws.com/doc/2006-03-01">
  <DeleteObjectResponse>
    <Code>200</Code>
    <Description>OK</Description>
  </DeleteObjectResponse>
</DeleteObjectResponse>"""

S3_OBJECT_RESPONSE = """<PutObjectResponse xmlns="http://s3.amazonaws.com/doc/2006-03-01">
      <PutObjectResponse>
        <ETag>{{ key.etag }}</ETag>
        <LastModified>{{ key.last_modified_ISO8601 }}</LastModified>
      </PutObjectResponse>
    </PutObjectResponse>"""

S3_OBJECT_ACL_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
    <AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
      <Owner>
        <ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID>
        <DisplayName>webfile</DisplayName>
      </Owner>
      <AccessControlList>
        {% for grant in obj.acl.grants %}
        <Grant>
          {% for grantee in grant.grantees %}
          <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                   xsi:type="{{ grantee.type }}">
            {% if grantee.uri %}
            <URI>{{ grantee.uri }}</URI>
            {% endif %}
            {% if grantee.id %}
            <ID>{{ grantee.id }}</ID>
            {% endif %}
            {% if grantee.display_name %}
            <DisplayName>{{ grantee.display_name }}</DisplayName>
            {% endif %}
          </Grantee>
          {% endfor %}
          {% for permission in grant.permissions %}
          <Permission>{{ permission }}</Permission>
          {% endfor %}
        </Grant>
        {% endfor %}
      </AccessControlList>
    </AccessControlPolicy>"""

S3_OBJECT_COPY_RESPONSE = """<CopyObjectResponse xmlns="http://doc.s3.amazonaws.com/2006-03-01">
  <CopyObjectResponse>
    <ETag>{{ key.etag }}</ETag>
    <LastModified>{{ key.last_modified_ISO8601 }}</LastModified>
  </CopyObjectResponse>
</CopyObjectResponse>"""

S3_MULTIPART_INITIATE_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>{{ bucket_name }}</Bucket>
  <Key>{{ key_name }}</Key>
  <UploadId>{{ upload_id }}</UploadId>
</InitiateMultipartUploadResult>"""

S3_MULTIPART_UPLOAD_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<CopyPartResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <LastModified>{{ part.last_modified_ISO8601 }}</LastModified>
  <ETag>{{ part.etag }}</ETag>
</CopyPartResult>"""

S3_MULTIPART_LIST_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<ListPartsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>{{ bucket_name }}</Bucket>
  <Key>{{ key_name }}</Key>
  <UploadId>{{ upload_id }}</UploadId>
  <StorageClass>STANDARD</StorageClass>
  <Initiator>
    <ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID>
    <DisplayName>webfile</DisplayName>
  </Initiator>
  <Owner>
    <ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID>
    <DisplayName>webfile</DisplayName>
  </Owner>
  <StorageClass>STANDARD</StorageClass>
  <PartNumberMarker>1</PartNumberMarker>
  <NextPartNumberMarker>{{ count }} </NextPartNumberMarker>
  <MaxParts>{{ count }}</MaxParts>
  <IsTruncated>false</IsTruncated>
  {% for part in parts %}
  <Part>
    <PartNumber>{{ part.name }}</PartNumber>
    <LastModified>{{ part.last_modified_ISO8601 }}</LastModified>
    <ETag>{{ part.etag }}</ETag>
    <Size>{{ part.size }}</Size>
  </Part>
  {% endfor %}
</ListPartsResult>"""

S3_MULTIPART_COMPLETE_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Location>http://{{ bucket_name }}.s3.amazonaws.com/{{ key_name }}</Location>
  <Bucket>{{ bucket_name }}</Bucket>
  <Key>{{ key_name }}</Key>
  <ETag>{{ etag }}</ETag>
</CompleteMultipartUploadResult>
"""

S3_ALL_MULTIPARTS = """<?xml version="1.0" encoding="UTF-8"?>
<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>{{ bucket_name }}</Bucket>
  <KeyMarker></KeyMarker>
  <UploadIdMarker></UploadIdMarker>
  <MaxUploads>1000</MaxUploads>
  <IsTruncated>False</IsTruncated>
  {% for upload in uploads %}
  <Upload>
    <Key>{{ upload.key_name }}</Key>
    <UploadId>{{ upload.id }}</UploadId>
    <Initiator>
      <ID>arn:aws:iam::111122223333:user/user1-11111a31-17b5-4fb7-9df5-b111111f13de</ID>
      <DisplayName>user1-11111a31-17b5-4fb7-9df5-b111111f13de</DisplayName>
    </Initiator>
    <Owner>
      <ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID>
      <DisplayName>webfile</DisplayName>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
    <Initiated>2010-11-10T20:48:33.000Z</Initiated>
  </Upload>
  {% endfor %}
</ListMultipartUploadsResult>
"""

S3_NO_POLICY = """<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>NoSuchBucketPolicy</Code>
  <Message>The bucket policy does not exist</Message>
  <BucketName>{{ bucket_name }}</BucketName>
  <RequestId>0D68A23BB2E2215B</RequestId>
  <HostId>9Gjjt1m+cjU4OPvX9O9/8RuvnG41MRb/18Oux2o5H5MY7ISNTlXN+Dz9IG62/ILVxhAGI0qyPfg=</HostId>
</Error>
"""
