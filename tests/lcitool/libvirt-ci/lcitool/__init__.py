class LcitoolError(Exception):
    """
    Global exception type for the whole project.

    While it is perfectly fine catching this type of exception since it covers
    all module-level exception types it is discouraged to raise an exception
    of this type directly anywhere in the code.
    """

    def __init__(self, message, module_prefix="lcitool"):
        self.module_prefix = module_prefix
        self.message = message
