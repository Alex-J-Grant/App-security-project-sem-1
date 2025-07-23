import logging
import os
from logging.handlers import RotatingFileHandler

def setup_logger(name, logfile, level = logging.INFO):
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler = RotatingFileHandler(logfile, maxBytes=1024*1024, backupCount=5)
    handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    return logger


if not os.path.exists("logs"):
    os.makedirs("logs")

main_logger = setup_logger("main_logger", "logs/app.log")



