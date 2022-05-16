# util.py - module hosting utility functions for lcitool
#
# Copyright (C) 2017-2020 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import fnmatch
import logging
import os
import platform
import tempfile
import textwrap

from pathlib import Path

_tempdir = None

log = logging.getLogger(__name__)


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
        raise Exception(f"Missing {name} list")

    if pattern == "all":
        pattern = "*"

    # This works correctly for single items as well as more complex
    # cases such as explicit lists, glob patterns and any combination
    # of the above
    matches = []
    for partial_pattern in pattern.split(","):

        partial_matches = []
        for item in iterable:
            if fnmatch.fnmatch(item, partial_pattern):
                partial_matches.append(item)

        if not partial_matches:
            raise Exception(f"Invalid {name} list '{pattern}'")

        for match in partial_matches:
            if match not in matches:
                matches.append(match)

    return matches


def get_native_arch():
    # Same canonicalization as libvirt virArchFromHost
    arch = platform.machine()
    if arch in ["i386", "i486", "i586"]:
        arch = "i686"
    if arch == "amd64":
        arch = "x86_64"
    return arch


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
        raise Exception(f"Unsupported architecture {native_arch}")
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
        raise Exception(f"Unsupported architecture {native_arch}")
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
        cache_dir = Path(os.environ["HOME"], ".cache")

    return Path(cache_dir, "lcitool")


def get_config_dir():
    try:
        config_dir = Path(os.environ["XDG_CONFIG_HOME"])
    except KeyError:
        config_dir = Path(os.environ["HOME"], ".config")

    return Path(config_dir, "lcitool")


extra_data_dir = None


def get_extra_data_dir():
    global extra_data_dir
    return extra_data_dir


def set_extra_data_dir(path):
    global extra_data_dir
    extra_data_dir = path


def validate_cross_platform(cross_arch, osname):
    native_arch = get_native_arch()
    if osname not in ["Debian", "Fedora"]:
        raise ValueError(f"Cannot cross compile on {osname}")
    if (osname == "Debian" and cross_arch.startswith("mingw")):
        raise ValueError(f"Cannot cross compile for {cross_arch} on {osname}")
    if (osname == "Fedora" and not cross_arch.startswith("mingw")):
        raise ValueError(f"Cannot cross compile for {cross_arch} on {osname}")
    if cross_arch == native_arch:
        raise ValueError(
            f"Cross arch {cross_arch} should differ from native "
            f"{native_arch}"
        )
