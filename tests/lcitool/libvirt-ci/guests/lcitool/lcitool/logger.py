from logging import Formatter


class LevelFormatter(Formatter):
    """
    This class handles different logging formats for different logging levels.

    Unlike the default Formatter class which can only handle a single message
    format for all logging levels, this class works around the limitation by
    employing a dedicated Formatter instance for each logging level.

    This class can be instantiated with the same arguments that you'd normally
    use with the parent Formatter class and will simply pass them through to
    the parent class.
    """

    def __init__(self, fmt_levels, *args, **kwargs):
        """
        Return an instance which handles multiple logging formats.

        :param fmt_levels: dictionary of logging.LEVEL -> logging msg format
        :return: logging.Formatter subclass instance
        """

        self._fmts = {lvl: Formatter(fmt) for lvl, fmt in fmt_levels.items()}

        super().__init__(*args, **kwargs)

    def format(self, record):
        """
        Format a log record to the defined logging output.

        Even though this is a public method, DO NOT use it directly, just like
        you wouldn't use it with a default Formatter instance.
        """

        formatter = self._fmts.get(record.levelno)

        if formatter is not None:
            return formatter.format(record)

        return super().format(record)
