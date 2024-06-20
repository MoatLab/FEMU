# test_images: test handling of vendor cloud-init images
#
# Copyright (C) 2023 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
import yaml

import lcitool.install.image as image
import test_utils.utils as test_utils

from pathlib import Path

IMAGE = None


class MockOSinfoImageObject:
    def __init__(self, obj):
        self.__dict__.update(obj)

    def has_cloud_init(self):
        return self.cloud_init


class MockOSinfoObject:
    """
    This mock allows us to provide the same image information to the image.py
    module caller without needing the underlying libosinfo machinery.
    """

    def __init__(self):
        self.name = "Debian 11"
        self.images = [MockOSinfoImageObject(IMAGE)]


class MockOSinfoDB:
    """
    This mocked class allows us to override the wrapper interface we have over
    libosinfo.
    """

    def get_os_by_id(self, libosinfo_id):
        return MockOSinfoObject()

    def get_os_by_short_id(self, short_id):
        return MockOSinfoObject()


@pytest.fixture(scope="module", autouse=True)
def patch_osinfodb(monkeypatch_module_scope):
    monkeypatch_module_scope.setattr("lcitool.install.osinfo.OSinfoDB",
                                     MockOSinfoDB)


@pytest.fixture(scope="module", autouse=True)
def patch_cache_dir(tmp_path_factory, monkeypatch_module_scope):
    def mock_cache_dir(self):
        return Path(test_utils.test_data_indir(__file__, "install/image"),
                    "cache")

    monkeypatch_module_scope.setattr("lcitool.install.image.Images._get_cache_dir",
                                     mock_cache_dir)


@pytest.fixture
def osinfo_image(scope="module"):
    filepath = Path(test_utils.test_data_indir(__file__, "install/image"),
                    "debian-11.metadata")

    with open(filepath) as fd:
        return yaml.safe_load(fd).copy()


@pytest.mark.parametrize(
    "target",
    [
        pytest.param("debian-11", id="non_cached_image"),
        pytest.param("fedora-rawhide", id="cached_image"),
    ]
)
def test_get_image(assert_equal, target, osinfo_image, targets):
    """
    Test that we can successfully query an Image object given a target and
    that the image has loaded/initialized the correct metadata for the image.
    """

    global IMAGE
    IMAGE = osinfo_image
    IMAGE.update({"variants": ["generic", "nocloud"], "cloud_init": True})

    img = image.Images().get(target, targets.target_facts[target])

    # We need to inject the 'image' key to Metadata explicitly here, because
    # that's normally done during the Image().dump() method when we know the
    # actual filename of the image, which we're not running as part of this
    # test
    img.metadata["image"] = f"{target}.qcow2"

    expected_path = Path(test_utils.test_data_indir(__file__,
                                                    "install/image"),
                         f"{target}.metadata")

    # Metadata is a UserDict subclass, hence we need '.data' for the comparison
    actual = img.metadata.data
    assert_equal(actual, expected_path)


@pytest.mark.parametrize(
    "img_params",
    [
        pytest.param(
            {
                "variants": ["aws", "openstack"],
                "cloud_init": True,
            }, id="invalid_image_variants"),
        pytest.param(
            {
                "variants": ["generic", "nocloud"],
                "cloud_init": False,
            }, id="no_cloud_image"),
    ]
)
def test_get_image_NoImageError(monkeypatch, img_params, osinfo_image, targets):
    """
    Test that we get an exception if libosinfo only provides image variants we
    don't support.
    """
    global IMAGE
    target = "debian-11"

    IMAGE = osinfo_image
    IMAGE.update(img_params)

    with pytest.raises(image.NoImageError):
        image.Images().get(target, targets.target_facts[target])
