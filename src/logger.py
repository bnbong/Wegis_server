# --------------------------------------------------------------------------
# Logging module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import logging
import os


def setup_logger(
    name: str = "main", file_path: str = "./log", level: int = logging.DEBUG
) -> logging.Logger:
    """Configure and return a logger with stream and file handlers."""
    os.makedirs(file_path, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(level)

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    file_handler = logging.FileHandler(
        os.path.join(file_path, f"{name}.log"), encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger
