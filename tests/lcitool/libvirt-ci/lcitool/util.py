# util.py - module hosting utility functions for lcitool
#
# Copyright (C) 2017-2020 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import copy
import errno
import fnmatch
import logging
import os
import sys
import platform
import tempfile
import textwrap
import yaml

from pathlib import Path

_tempdir = None

log = logging.getLogger(__name__)


class SSHKey:
    """
    :ivar path: Absolute path to the SSH key as Path object
    """

    def __init__(self, keypath):
        self._contents = None

        # resolve user home directory + canonicalize path
        self.path = Path(keypath).expanduser().resolve()
        if not self.path.exists():
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT),
                                    str(self.path))

    def __str__(self):
        if self._contents is None:
            with open(self.path, "r") as f:
                self._contents = f.read().strip()

        return self._contents


class SSHPublicKey(SSHKey):
    pass


class SSHPrivateKey(SSHKey):
    def __str__(self):
        # Only the SSH backend should ever need to know the contents of the
        # private key

        return ""


class SSHKeyPair:
    def __init__(self, keypath):
        pathobj = Path(keypath)
        self.public_key = SSHPublicKey(pathobj.with_suffix(".pub"))
        self.private_key = SSHPrivateKey(pathobj.with_suffix(""))


def expand_pattern(pattern, iterable, name):
    """
    Expands a simple user-provided pattern and return the corresponding
    items from the starting iterable.

    Assuming the iterable is

      [ "foo", "bar", "baz" ]

    then patterns will expand as

      "foo,bar" => [ "foo", "bar" ]
      "b*"      => [ "bar", "baz" ]
      "baz,f*"  => [ "baz", "foo" ]
      "*"       => [ "foo", "bar", "baz" ]
      "all"     => [ "foo", "bar", "baz" ]

    Passing in a pattern that can't be expanded successfully will result in
    an exception being raised.

    Note that ordering is preserved among sub-patterns (those separated by
    commas) but no guarantee in terms of ordering is made when it comes to
    wildcard expansion.

    :param pattern: pattern to be expanded
    :param iterable: iterable over all possible items
    :param name: name of the iterable (used for error reporting)
    :returns: list containing the items in iterable that match pattern
    """

    log.debug(f"Expanding {name} pattern '{pattern}' on '{iterable}'")

    if pattern is None:
        raise ValueError(f"Missing {name} list")

    if pattern == "all":
        pattern = "*"

    # This works correctly for single items as well as more complex
    # cases such as explicit lists, glob patterns and any combination
    # of the above
    matches = []
    for partial_pattern in pattern.split(","):
        if "/" in partial_pattern:
            matches.append(partial_pattern)
            continue

        partial_matches = []
        for item in iterable:
            if fnmatch.fnmatch(item, partial_pattern):
                partial_matches.append(item)

        if not partial_matches:
            raise ValueError(f"Invalid {name} list '{pattern}'")

        for match in partial_matches:
            if match not in matches:
                matches.append(match)

    return matches


def get_host_arch():
    # Same canonicalization as libvirt virArchFromHost
    arch = platform.machine()
    if arch in ["i386", "i486", "i586"]:
        arch = "i686"
    if arch == "amd64":
        arch = "x86_64"
    if arch == "arm64":
        arch = "aarch64"
    if arch not in valid_arches():
        raise ValueError(f"Unsupported architecture {arch}")
    return arch


def valid_arches():
    return [
        "aarch64",
        "armv6l",
        "armv7l",
        "i686",
        "mingw32",
        "mingw64",
        "mips",
        "mipsel",
        "mips64el",
        "ppc64le",
        "riscv64",
        "s390x",
        "x86_64",
    ]


def native_arch_to_abi(native_arch):
    archmap = {
        "aarch64": "aarch64-linux-gnu",
        "armv6l": "arm-linux-gnueabi",
        "armv7l": "arm-linux-gnueabihf",
        "i686": "i686-linux-gnu",
        "mingw32": "i686-w64-mingw32",
        "mingw64": "x86_64-w64-mingw32",
        "mips": "mips-linux-gnu",
        "mipsel": "mipsel-linux-gnu",
        "mips64el": "mips64el-linux-gnuabi64",
        "ppc64le": "powerpc64le-linux-gnu",
        "riscv64": "riscv64-linux-gnu",
        "s390x": "s390x-linux-gnu",
        "x86_64": "x86_64-linux-gnu",
    }
    if native_arch not in archmap:
        raise ValueError(f"Unsupported architecture {native_arch}")
    return archmap[native_arch]


def native_arch_to_deb_arch(native_arch):
    archmap = {
        "aarch64": "arm64",
        "armv6l": "armel",
        "armv7l": "armhf",
        "i686": "i386",
        "mips": "mips",
        "mipsel": "mipsel",
        "mips64el": "mips64el",
        "ppc64le": "ppc64el",
        "riscv64": "riscv64",
        "s390x": "s390x",
        "x86_64": "amd64",
    }
    if native_arch not in archmap:
        raise ValueError(f"Unsupported architecture {native_arch}")
    return archmap[native_arch]


def native_arch_to_rust_target(native_arch):
    archmap = {
        "aarch64": "aarch64-unknown-linux-gnu",
        "armv6l": "armv5te-unknown-linux-gnueabi",
        "armv7l": "armv7-unknown-linux-gnueabihf",
        "i686": "i686-unknown-linux-gnu",
        "mingw32": "i686-pc-windows-gnu",
        "mingw64": "x86_64-pc-windows-gnu",
        "mips": "mips-unknown-linux-gnu",
        "mipsel": "mipsel-unknown-linux-gnu",
        "mips64el": "mips64el-unknown-linux-gnuabi64",
        "ppc64le": "powerpc64le-unknown-linux-gnu",
        "riscv64": "riscv64gc-unknown-linux-gnu",
        "s390x": "s390x-unknown-linux-gnu",
        "x86_64": "x86_64-unknown-linux-gnu",
    }
    if native_arch not in archmap:
        raise ValueError(f"Unsupported rust target {native_arch}")
    return archmap[native_arch]


def generate_file_header(cliargv):
    url = "https://gitlab.com/libvirt/libvirt-ci"

    cliargvlist = " ".join(cliargv)
    return textwrap.dedent(
        f"""\
        # THIS FILE WAS AUTO-GENERATED
        #
        #  $ lcitool {cliargvlist}
        #
        # {url}

        """
    )


def atomic_write(filepath, content):
    tmpfilepath = None
    tmpdir = filepath.parent
    try:
        with tempfile.NamedTemporaryFile("w", dir=tmpdir, delete=False) as fd:
            tmpfilepath = Path(fd.name)
            fd.write(content)

        tmpfilepath.replace(filepath)
    except Exception:
        if tmpfilepath is not None:
            tmpfilepath.unlink()
        raise


def get_temp_dir():
    global _tempdir

    if not _tempdir:
        _tempdir = tempfile.TemporaryDirectory(prefix="lcitool")
    return Path(_tempdir.name)


def get_cache_dir():
    try:
        cache_dir = Path(os.environ["XDG_CACHE_HOME"])
    except KeyError:
        cache_dir = Path.home().joinpath(".cache")

    return Path(cache_dir, "lcitool")


def get_config_dir():
    try:
        config_dir = Path(os.environ["XDG_CONFIG_HOME"])
    except KeyError:
        config_dir = Path.home().joinpath(".config")

    return Path(config_dir, "lcitool")


def get_datadir_inventory(data_dir):
    if data_dir.path is None or not Path(data_dir.path, "ansible").exists():
        return None

    # check whether user provided an inventory file via datadir
    inventory_path = Path(data_dir.path, "ansible/inventory")
    if inventory_path.exists():
        return inventory_path


def package_resource(package, relpath):
    """
    Backcompatibility helper to retrieve a package resource using importlib

    :param package: object conforming to importlib.resources.Package requirement
    :param relpath: relative path to the actual resource (or directory) as
                    str or Path object
    :returns: a Path object to the resource
    """

    from importlib import import_module, resources

    if hasattr(resources, "files"):
        return Path(resources.files(package), relpath)
    else:
        # This is a horrible hack, it won't work for resources that don't exist
        # on the file system (which should not be a problem for our use case),
        # but it's needed because importlib.resources.path only accepts
        # filenames for a 'Resource' [1]. What it means is that one cannot pass
        # a path construct in 'relpath', because 'Resource' cannot contain
        # path delimiters and also cannot be a directory, so we cannot use the
        # method to construct base resource paths.
        # [1] https://docs.python.org/3/library/importlib.resources.html?highlight=importlib%20resources#importlib.resources.path
        # Instead, we'll extract the package path from ModuleSpec (loading the
        # package first if needed) and then concatenate it with the 'relpath'
        #
        # TODO: Drop this helper once we move onto 3.9+
        if package not in sys.modules:
            import_module(package)

        package_path = Path(sys.modules[package].__file__).parent
        return Path(package_path, relpath)


def merge_dict(source, dest):
    for key in source.keys():
        if key not in dest:
            dest[key] = copy.deepcopy(source[key])
            continue

        if isinstance(source[key], list) or isinstance(dest[key], list):
            raise ValueError("cannot merge lists")
        if isinstance(source[key], dict) != isinstance(dest[key], dict):
            raise ValueError("cannot merge dictionaries with non-dictionaries")
        if isinstance(source[key], dict):
            merge_dict(source[key], dest[key])


class DataDir:
    """A class that looks for files both under the lcitool sources and in
       an externally specified data directory.  Used to implement the
       -d option."""

    @property
    def path(self):
        if self._path is None:
            if self._extra_data_dir is not None:
                self._path = Path(self._extra_data_dir).resolve()

        return self._path

    def _default():
        extra = Path("ci", "lcitool")
        if extra.exists():
            return extra.as_posix()

        return None

    def __init__(self, extra_data_dir=_default()):
        self._extra_data_dir = extra_data_dir
        self._path = None

    def __repr__(self):
        return f'DataDir({str(self._extra_data_dir)})'

    def __bool__(self):
        return bool(self._extra_data_dir)

    def _search(self, resource_path, *names, internal=False):
        if self and not internal:
            # The first part of the path is used to keep data files out of
            # the source directory, for example "facts" or "etc".  Remove it
            # when using an external data directory.
            if "/" in resource_path:
                user_path = resource_path[resource_path.index("/") + 1:]
            else:
                user_path = ""
            p = Path(self._extra_data_dir, user_path, *names)
            if p.exists():
                yield p

        p = Path(package_resource(__package__, resource_path), *names)
        if p.exists():
            yield p

    def list_files(self, resource_path, suffix=None, internal=False):
        for p in self._search(resource_path, internal=internal):
            for file in p.iterdir():
                if file.is_file() and (suffix is None or file.suffix == suffix):
                    yield file

    def merge_facts(self, resource_path, name):
        result = {}
        for file in self._search(resource_path, name + ".yml"):
            log.debug(f"Loading facts from '{file}'")
            with open(file, "r") as infile:
                merge_dict(yaml.safe_load(infile), result)
        return result


def validate_cross_platform(cross_arch, osname):
    if osname not in ["Debian", "Fedora"]:
        raise ValueError(f"Cannot cross compile on {osname}")
    if (osname == "Debian" and cross_arch.startswith("mingw")):
        raise ValueError(f"Cannot cross compile for {cross_arch} on {osname}")
    if (osname == "Fedora" and not cross_arch.startswith("mingw")):
        raise ValueError(f"Cannot cross compile for {cross_arch} on {osname}")
