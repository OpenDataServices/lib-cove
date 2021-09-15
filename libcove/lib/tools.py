from decimal import Decimal
from functools import lru_cache, wraps

import requests

from .exceptions import UnrecognisedFileType


@lru_cache(maxsize=64)
def cached_get_request(url):
    return requests.get(url)


def get_request(url, config=None, force_cache=False):
    if force_cache or (
        config
        and "cache_all_requests" in config.config
        and config.config["cache_all_requests"]
    ):
        return cached_get_request(url)
    else:
        return requests.get(url)


def ignore_errors(f):
    @wraps(f)
    def ignore(json_data, *args, ignore_errors=False, return_on_error={}, **kwargs):
        if ignore_errors:
            try:
                return f(json_data, *args, **kwargs)
            except (KeyError, TypeError, IndexError, AttributeError, ValueError):
                return return_on_error
        else:
            return f(json_data, *args, **kwargs)

    return ignore


# From http://bugs.python.org/issue16535
class NumberStr(float):
    def __init__(self, o):
        # We don't call the parent here, since we're deliberately altering it's functionality
        # pylint: disable=W0231
        self.o = o

    def __repr__(self):
        return str(self.o)

    # This is needed for this trick to work in python 3.4
    def __float__(self):
        return self


def decimal_default(o):
    if isinstance(o, Decimal):
        if int(o) == o:
            return int(o)
        else:
            return NumberStr(o)
    raise TypeError(f"{repr(o)} is not JSON serializable")


def to_list(item):
    if isinstance(item, list):
        return item
    return [item]


def get_no_exception(item, key, fallback):
    try:
        return item.get(key, fallback)
    except AttributeError:
        return fallback


def update_docs(document_parent, counter):
    count = 0
    documents = document_parent.get("documents", [])
    for document in documents:
        count += 1
        doc_type = document.get("documentType")
        if doc_type:
            counter.update([doc_type])
    return count


def get_file_type(file_name):
    """Takes an filename (type string), and returns a string saying what type it is."""
    # Older versions of this could take DJango objects to.
    # Tho we don't really want to support that, put in a check for that.
    if not isinstance(file_name, str) and hasattr(file_name, "path"):
        file_name = file_name.path
    # First, just check the extension on the file name
    if file_name.lower().endswith(".json"):
        return "json"
    if file_name.lower().endswith(".xlsx"):
        return "xlsx"
    if file_name.lower().endswith(".ods"):
        return "ods"
    if file_name.lower().endswith(".csv"):
        return "csv"
    # Try and load the first bit of the file to see if it's JSON?
    try:
        with open(file_name, "rb") as fp:
            first_byte = fp.read(1)
            if first_byte in [b"{", b"["]:
                return "json"
    except FileNotFoundError:
        pass
    # All right, we give up.
    raise UnrecognisedFileType
