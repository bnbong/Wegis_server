# --------------------------------------------------------------------------
# Enums module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from enum import Enum


class ResponseMessage(str, Enum):
    """Response message Enum

    - SUCCESS : Successfully received the response
    - ERROR : Error occurred (Internal Server Error, Bad Request, etc.)
    """

    SUCCESS = "SUCCESS"
    ERROR = "ERROR"


class ListType(str, Enum):
    """Cached Domain List type Enum

    - WHITELIST : Whitelisted domain list
    - BLACKLIST : Blacklisted domain list
    """

    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"


class Verdict(str):
    """Verdict Enum

    - WHITELIST : Whitelisted domain
    - BLACKLIST : Blacklisted domain
    - UNKNOWN : Unknown domain
    """

    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"
    UNKNOWN = "unknown"
