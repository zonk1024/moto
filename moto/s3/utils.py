from __future__ import unicode_literals

from boto.s3.key import Key
import re
import six
from six.moves.urllib.parse import unquote
import sys


def metadata_from_headers(headers):
    metadata = {}
    meta_regex = re.compile('^x-amz-meta-([a-zA-Z0-9\-_]+)$', flags=re.IGNORECASE)
    for header, value in headers.items():
        if isinstance(header, six.string_types):
            result = meta_regex.match(header)
            meta_key = None
            if result:
                # Check for extra metadata
                meta_key = result.group(0).lower()
            elif header.lower() in Key.base_user_settable_fields:
                # Check for special metadata that doesn't start with x-amz-meta
                meta_key = header
            if meta_key:
                metadata[meta_key] = headers[header]
    return metadata


def clean_key_name(key_name):
    return unquote(key_name)


class _VersionedKeyStore(dict):

    """ A simplified/modified version of Django's `MultiValueDict` taken from:
    https://github.com/django/django/blob/70576740b0bb5289873f5a9a9a4e1a26b2c330e5/django/utils/datastructures.py#L282
    """

    def __sgetitem__(self, key):
        return super(_VersionedKeyStore, self).__getitem__(key)

    def __getitem__(self, key):
        return self.__sgetitem__(key)[-1]

    def __setitem__(self, key, value):
        try:
            current = self.__sgetitem__(key)
            current.append(value)
        except (KeyError, IndexError):
            current = [value]

        super(_VersionedKeyStore, self).__setitem__(key, current)

    def get(self, key, default=None):
        try:
            return self[key]
        except (KeyError, IndexError):
            pass
        return default

    def getlist(self, key, default=None):
        try:
            return self.__sgetitem__(key)
        except (KeyError, IndexError):
            pass
        return default

    def setlist(self, key, list_):
        if isinstance(list_, tuple):
            list_ = list(list_)
        elif not isinstance(list_, list):
            list_ = [list_]

        super(_VersionedKeyStore, self).__setitem__(key, list_)

    def _iteritems(self):
        for key in self:
            yield key, self[key]

    def _itervalues(self):
        for key in self:
            yield self[key]

    def _iterlists(self):
        for key in self:
            yield key, self.getlist(key)

    items = iteritems = _iteritems
    lists = iterlists = _iterlists
    values = itervalues = _itervalues

    if sys.version_info[0] < 3:
        def items(self):
            return list(self.iteritems())

        def values(self):
            return list(self.itervalues())

        def lists(self):
            return list(self.iterlists())
