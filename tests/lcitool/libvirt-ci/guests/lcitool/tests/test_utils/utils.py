# utils: a set of test suite utility functions
#
# Copyright (C) 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
import yaml

import test_packages

from pathlib import Path


def base_data_dir():
    return Path(test_packages.__file__).parent.joinpath("data")


def test_data_dir(test_name):
    return Path(base_data_dir(), Path(test_name).stem[len("test_"):])


def test_data_outdir(test_name):
    return Path(test_data_dir(test_name), "out")


def test_data_indir(test_name):
    return Path(test_data_dir(test_name), "in")


def assert_yaml_matches_file(actual, expected_path, allow_regenerate=True):
    if pytest.custom_args["regenerate_output"] and allow_regenerate:
        # Make sure the target directory exists, since creating the
        # output file would fail otherwise
        expected_path.parent.mkdir(parents=True, exist_ok=True)
        with open(expected_path, "w") as fd:
            yaml.safe_dump(actual, stream=fd)

    with open(expected_path) as fd:
        expected = yaml.safe_load(fd)

    assert actual.keys() == expected.keys()
    for key in actual.keys():
        assert actual[key] == expected[key]


def assert_matches_file(actual, expected_path, allow_regenerate=True):
    if pytest.custom_args["regenerate_output"] and allow_regenerate:
        # Make sure the target directory exists, since creating the
        # output file would fail otherwise
        expected_path.parent.mkdir(parents=True, exist_ok=True)
        with open(expected_path, "w") as fd:
            fd.write(actual)

    with open(expected_path) as fd:
        expected = fd.read()

    assert actual == expected
