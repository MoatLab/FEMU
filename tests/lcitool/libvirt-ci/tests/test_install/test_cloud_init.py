# test_cloud_init: test cloud-init related operations
#
# Copyright (C) 2023 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

import lcitool.install.cloud_init as cloud_init
import test_utils.utils as test_utils

from pathlib import Path


USER_DATA = {
    "ssh_authorized_keys": ["ssh-rsa DEADBEEF"],
    "foo": "bar",
}


@pytest.mark.parametrize(
    "source,outfile",
    [
        pytest.param(None, "cloud_config_from_base_template.conf",
                     id="from_base_template"),
        pytest.param(Path(test_utils.test_data_indir(__file__, "install"),
                          "cloud_config_user_template.conf"),
                     "cloud_config_from_user_template.conf",
                     id="from_user_template"),
    ]
)
def test_cloud_config_init(source, outfile):
    cloud_init.CloudConfig(file=source, **USER_DATA)


def test_cloud_config_init_error():
    template = Path(test_utils.test_data_indir(__file__, "install"),
                    "cloud_config_invalid_template.conf")

    with pytest.raises(cloud_init.CloudConfigError):
        cloud_init.CloudConfig(file=template, **USER_DATA)


@pytest.mark.parametrize(
    "filename",
    [
        pytest.param(None, id="to_string"),
        pytest.param("cloud-init.conf", id="to_file"),
    ]
)
def test_cloud_config_dump(assert_equal, tmp_path, filename):
    def _dump_helper(cc, outfile):
        if outfile is None:
            return cc.dump()
        else:
            cc.dump(file=outfile)
            return outfile

    template = Path(test_utils.test_data_indir(__file__, "install"),
                    "cloud_config_user_template.conf")

    outfile = filename
    if outfile is not None:
        outfile = tmp_path.joinpath(filename)

    expected = Path(test_utils.test_data_outdir(__file__, "install"),
                    "cloud_config_from_user_template.conf")
    cc = cloud_init.CloudConfig(file=template, **USER_DATA)

    assert_equal(_dump_helper(cc, outfile), expected)
