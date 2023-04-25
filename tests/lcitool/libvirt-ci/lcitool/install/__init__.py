from .install import VirtInstall, InstallerError

# this line only makes sense with 'from xyz import *'; it also silences flake8
__all__ = ["VirtInstall", "InstallerError"]
