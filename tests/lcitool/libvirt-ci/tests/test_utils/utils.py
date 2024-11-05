# utils: a set of test suite utility functions
#
# Copyright (C) 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import difflib
import pytest
import yaml

from pathlib import Path


def base_data_dir():
    return Path(__file__).parent.parent.joinpath("data")


def test_data_dir(test_name, relative_dir=None):
    if relative_dir is None:
        relative_dir = ""
    test_stem = Path(test_name).stem[len("test_"):]
    return Path(base_data_dir(), relative_dir, test_stem)


def test_data_outdir(test_name, relative_dir=None):
    return Path(test_data_dir(test_name, relative_dir), "out")


def test_data_indir(test_name, relative_dir=None):
    return Path(test_data_dir(test_name, relative_dir), "in")


def format_err_msg(indices, err_msg):
    if indices:
        return ", ".join(indices) + ": " + err_msg
    else:
        return err_msg


class Diff:
    def __init__(self, diffobj):
        self._obj = diffobj
        self.diff = "".join(diffobj)

    def __repr__(self):
        return f"obj: {repr(self._diffobj)}, str: {self.diff}"

    def __str__(self):
        return self.diff

    def empty(self):
        return not bool(str(self))


class DiffOperand:
    def __init__(self, obj):
        self._obj = obj
        self._data = self._stringify(obj)

    def __repr__(self):
        return f"obj: {repr(self._obj)}, str: {self._data})"

    def __str__(self):
        return self._data

    @staticmethod
    def _stringify(obj):
        if isinstance(obj, str):
            return obj

        if isinstance(obj, Path):
            with open(obj, 'r') as f:
                return f.read()

        return yaml.safe_dump(obj)

    def diff(self, other):
        if not isinstance(other, self.__class__):
            other = self._stringify(other)

        return Diff(difflib.unified_diff(str(self).splitlines(keepends=True),
                                         str(other).splitlines(keepends=True),
                                         fromfile="actual",
                                         tofile="expected",))


def _assert_equal(actual, expected, test_tmp_dir):
    # create a diff operand for 'actual' now so that we can have a string to
    # work with if we need to regenerate the output
    actual = DiffOperand(actual)

    if pytest.custom_args["regenerate_output"] and \
       isinstance(expected, Path):

        # Make sure the target directory exists, since creating the
        # output file would fail otherwise
        expected.parent.mkdir(parents=True, exist_ok=True)
        with open(expected, "w") as fd:
            fd.write(str(actual))

    # create a diff operand for 'expected' late so that we can consume the
    # updated output based on '--regenerate-output'
    expected = DiffOperand(expected)
    diff = actual.diff(expected)
    if diff.empty():
        return

    # pytest doesn't provide any flexibility over how and when tmp directories
    # are created, so we'll take care of it ourselves, but it needs to tell us
    # where the directory should be created and what its name should be
    test_tmp_dir.mkdir(parents=True, exist_ok=True)
    actual_p = Path(test_tmp_dir, "actual")
    expected_p = Path(test_tmp_dir, "expected")
    with open(actual_p, "w") as actual_f, open(expected_p, "w") as expected_f:
        actual_f.write(str(actual))
        expected_f.write(str(expected))

    raise AssertionError(
        f"Actual and expected outputs differ"
        f"\n{diff}\n\n"
        f"Full output dumps available at '{test_tmp_dir}'"
    )


# Force loading the facts, for example to avoid conflicts with monkeypatching
def force_load(packages=None, projects=None, targets=None):
    if packages:
        packages._load_mappings()
    if projects:
        projects._load_public()
        projects._load_internal()
    if targets:
        targets._load_target_facts()
