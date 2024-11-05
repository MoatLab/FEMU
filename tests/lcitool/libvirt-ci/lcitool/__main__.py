import sys
import logging

from lcitool.application import Application
from lcitool.commandline import CommandLine
from lcitool.logger import LevelFormatter


class LcitoolLogger(logging.Logger):
    def debug(self, *args, **kwargs):
        super().debug(*args, **kwargs, exc_info=True)


def main():
    log_level_formats = {
        logging.DEBUG: "[%(levelname)s] %(module)s:%(funcName)s:%(lineno)d: %(message)s",
        logging.INFO: "[%(levelname)s]: %(message)s",
        logging.ERROR: "[%(levelname)s]: %(message)s",
    }

    logging.setLoggerClass(LcitoolLogger)

    custom_formatter = LevelFormatter(log_level_formats)
    custom_handler = logging.StreamHandler(stream=sys.stderr)
    custom_handler.setFormatter(custom_formatter)

    log = logging.getLogger()
    log.addHandler(custom_handler)

    args = CommandLine().parse()

    if args.debug:
        log.setLevel(logging.DEBUG)

    try:
        Application().run(args)
    except Exception:
        log.exception("An unexpected error occurred")
        sys.exit(1)


if __name__ == "__main__":
    sys.exit(main())
