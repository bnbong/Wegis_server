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
