# test_config: test defaults and validation of the config file
#
# Copyright (C) 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

import test_utils.utils as test_utils

from pathlib import Path
from lcitool.config import ValidationError


@pytest.mark.parametrize(
    "config_filename",
    [
        "full.yml",
        "minimal.yml",
        "unknown_section.yml",
        "unknown_key.yml",
    ],
)
def test_config(config, config_filename):
    expected_path = Path(test_utils.test_data_outdir(__file__), config_filename)

    actual = config.values
    test_utils.assert_yaml_matches_file(actual, expected_path)


@pytest.mark.parametrize(
    "config_filename",
    [
        "empty.yml",
        "missing_mandatory_section.yml",
        "missing_mandatory_key.yml",
        "missing_gitlab_section_with_gitlab_flavor.yml",
    ],
)
def test_config_invalid(config, config_filename):
    with pytest.raises(ValidationError):
        config.values
