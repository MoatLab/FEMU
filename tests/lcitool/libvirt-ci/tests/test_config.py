# test_config: test defaults and validation of the config file
#
# Copyright (C) 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

import test_utils.utils as test_utils

from pathlib import Path
from lcitool.config import Config, ValidationError


@pytest.mark.parametrize(
    "config_filename",
    [
        "empty.yml",
        "full.yml",
        "minimal.yml",
        "minimal_no_root_password.yml",
        "no_config",
        "unknown_section.yml",
        "unknown_key.yml",
    ],
)
def test_config(assert_equal, config_filename):
    expected_path = Path(test_utils.test_data_outdir(__file__), config_filename)

    actual = Config(path=expected_path).values
    assert_equal(actual, expected_path)


@pytest.mark.parametrize(
    "config_filename",
    [
        "missing_gitlab_section_with_gitlab_flavor.yml",
        "root_password_none.yml",
    ],
)
def test_config_invalid(config_filename):
    with pytest.raises(ValidationError):
        path = Path(test_utils.test_data_indir(__file__), config_filename)
        Config(path=path).values
