# utils: a set of test suite utility functions
#
# Copyright (C) 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
import yaml

from pathlib import Path


def base_data_dir():
    return Path(__file__).parent.parent.joinpath("data")


def test_data_dir(test_name):
    return Path(base_data_dir(), Path(test_name).stem[len("test_"):])


def test_data_outdir(test_name):
    return Path(test_data_dir(test_name), "out")


def test_data_indir(test_name):
    return Path(test_data_dir(test_name), "in")


def format_err_msg(indices, err_msg):
    if indices:
        return ", ".join(indices) + ": " + err_msg
    else:
        return err_msg


def assert_equal_list(actual, expected, indices, kind):
    len_err = None
    if len(actual) != len(expected):
        # stash the error for later: printing the first different element
        # has higher priority, but actual and expected will not be
        # available later to print the error
        len_err = format_err_msg(indices, f"expected {len(expected)} {kind}s, got {len(actual)}, ")
        if len(actual) < len(expected):
            len_err += f"first missing element: {repr(expected[len(actual)])}"
            expected = expected[:len(actual)]
        else:
            len_err += f"first extra element: {repr(actual[len(expected)])}"
            actual = actual[:len(expected)]

    indices.append(None)
    try:
        n = 0
        for i, j in zip(iter(actual), iter(expected)):
            indices[-1] = f"at {kind} {n}"
            assert_equal(i, j, indices)
            n += 1
    finally:
        indices.pop()
    if len_err:
        raise AssertionError(len_err)


def assert_equal(actual, expected, indices):
    if not isinstance(actual, type(expected)):
        raise AssertionError(format_err_msg(indices, f"expected {type(expected)}, got {type(actual)}"))

    if isinstance(expected, list):
        assert_equal_list(actual, expected, indices, "item")

    elif isinstance(expected, str) and "\n" in expected:
        actual_lines = actual.split("\n")
        expected_lines = expected.split("\n")
        assert_equal_list(actual_lines, expected_lines, indices, "line")

    elif isinstance(expected, dict):
        actual_keys = sorted(actual.keys())
        expected_keys = sorted(expected.keys())
        assert_equal_list(actual_keys, expected_keys, indices, "key")

        indices.append(None)
        try:
            for i in actual_keys:
                indices[-1] = f"at key {i}"
                assert_equal(actual[i], expected[i], indices)
        finally:
            indices.pop()

    elif actual != expected:
        raise AssertionError(format_err_msg(indices, f"expected {repr(expected)}, got {repr(actual)}"))


def assert_yaml_matches_file(actual, expected_path, allow_regenerate=True):
    if pytest.custom_args["regenerate_output"] and allow_regenerate:
        # Make sure the target directory exists, since creating the
        # output file would fail otherwise
        expected_path.parent.mkdir(parents=True, exist_ok=True)
        with open(expected_path, "w") as fd:
            yaml.safe_dump(actual, stream=fd)

    with open(expected_path) as fd:
        expected = yaml.safe_load(fd)

    assert_equal(actual, expected, [f"comparing against {expected_path}"])


def assert_matches_file(actual, expected_path, allow_regenerate=True):
    if pytest.custom_args["regenerate_output"] and allow_regenerate:
        # Make sure the target directory exists, since creating the
        # output file would fail otherwise
        expected_path.parent.mkdir(parents=True, exist_ok=True)
        with open(expected_path, "w") as fd:
            fd.write(actual)

    with open(expected_path) as fd:
        expected = fd.read()

    assert_equal(actual, expected, [f"comparing against {expected_path}"])


# Force loading the facts, for example to avoid conflicts with monkeypatching
def force_load(packages=None, projects=None, targets=None):
    if packages:
        packages._load_mappings()
    if projects:
        projects._load_public()
        projects._load_internal()
    if targets:
        targets._load_target_facts()
