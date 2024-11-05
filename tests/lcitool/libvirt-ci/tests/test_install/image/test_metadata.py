# test_image_metadata: test loading and validation of the image metadata
#
# Copyright (C) 2023 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
import yaml

import lcitool.install.image as image
import test_utils.utils as test_utils

from pathlib import Path


@pytest.fixture
def invalid_metadata():
    filepath = Path(test_utils.test_data_indir(__file__, "install/image"),
                    "invalid_schema.metadata")

    with open(filepath) as fd:
        metadata = yaml.safe_load(fd)
    return metadata


@pytest.fixture
def valid_metadata():
    filepath = Path(test_utils.test_data_indir(__file__, "install/image"),
                    "valid.metadata")

    with open(filepath) as fd:
        metadata = yaml.safe_load(fd)
    return metadata


def test_metadata_load(assert_equal, valid_metadata):
    filepath = Path(test_utils.test_data_indir(__file__, "install/image"),
                    "valid.metadata")

    # Metadata is a UserDict subclass, hence we need '.data' for the comparison
    actual = image.Metadata().load(filepath).data
    assert_equal(actual, valid_metadata)


@pytest.mark.parametrize(
    "file,exception",
    [
        pytest.param("invalid_yaml.metadata", image.MetadataLoadError,
                     id="invalid_yaml"),
        pytest.param("invalid_schema.metadata", image.MetadataValidationError,
                     id="invalid_schema"),
    ]
)
def test_metadata_load_invalid(file, exception):
    filepath = Path(test_utils.test_data_indir(__file__, "install/image"),
                    file)
    with pytest.raises(exception):
        image.Metadata().load(filepath)


def test_metadata_dump(assert_equal, tmp_path, valid_metadata):
    actual_path = Path(tmp_path, "valid.metadata")
    expected_path = Path(test_utils.test_data_outdir(__file__, "install/image"),
                         "valid.metadata")

    image.Metadata(**valid_metadata).dump(actual_path)
    assert_equal(actual_path, expected_path)


def test_metadata_dump_invalid(tmp_path, invalid_metadata):
    actual_path = Path(tmp_path, "invalid.metadata")
    with pytest.raises(image.MetadataValidationError):
        image.Metadata(**invalid_metadata).dump(actual_path)
