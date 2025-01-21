import logging
from logging.handlers import RotatingFileHandler
import colorlog

def setup_logger(log_file_path="scan_log.txt"):
    logger = logging.getLogger("ClamAVLogger")
    logger.setLevel(logging.DEBUG)

    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    color_formatter = colorlog.ColoredFormatter(
        "%(log_color)s%(asctime)s - %(levelname)s - %(message)s",
        datefmt='%Y-%m-%d %H:%M:%S',
        log_colors={
            'DEBUG': 'white',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'bold_red',
        }
    )

    # File handler: ghi log vào file với tính năng xoay vòng file
    file_handler = RotatingFileHandler(log_file_path, maxBytes=5*1024*1024, backupCount=2)
    file_handler.setFormatter(file_formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(color_formatter)

    if not logger.hasHandlers():
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger