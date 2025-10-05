# --------------------------------------------------------------------------
# Logging module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import logging
import os


class Logger(logging.Logger):
    def __init__(self, name: str, level: int = logging.DEBUG, file_path: str = "./log"):
        self.logger_name = name
        self.__logger = logging.getLogger(self.logger_name)
        self.__logger.setLevel(level)
        self.__file_path = file_path
        self.__formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

        # Stream handler
        self.__stream_handler = logging.StreamHandler()
        self.__stream_handler.setLevel(self.__logger.level)
        self.__stream_handler.setFormatter(self.__formatter)
        self.__logger.addHandler(self.__stream_handler)

        # File handler
        if not os.path.exists(self.__file_path):
            os.makedirs(self.__file_path)

        self.__file_handler = logging.FileHandler(
            os.path.join(self.__file_path, f"{self.logger_name}.log"), encoding="utf-8"
        )
        self.__file_handler.setLevel(self.__logger.level)
        self.__file_handler.setFormatter(self.__formatter)
        self.__logger.addHandler(self.__file_handler)

    def __getattr__(self, name: str):
        return getattr(self.__logger, name)
