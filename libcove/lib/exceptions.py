import functools
import logging

logger = logging.getLogger(__name__)


class UnrecognisedFileType(Exception):
    pass


class CoveInputDataError(Exception):
    """
    An error that we think is due to the data input by the user, rather than a
    bug in the application.
    """

    def __init__(self, wrapped_err=None, context=None):
        if wrapped_err:
            self.wrapped_err = wrapped_err
        elif context:
            self.context = context


def cove_spreadsheet_conversion_error(func):
    @functools.wraps(func)
    def wrapper(request, *args, **kwargs):
        try:
            return func(request, *args, **kwargs)
        except Exception as err:
            logger.exception(err, extra={"request": request})
            raise CoveInputDataError(wrapped_err=err)

    return wrapper
