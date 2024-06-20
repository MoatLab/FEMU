# test_commands: sanity check command operation
#
# Copyright (C) 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
import subprocess
import sys
from pathlib import Path


cli_args = [
    ["--help"],
    ["targets"],
    ["projects"],
    ["variables", "almalinux-8", "osinfo-db-tools"],
    ["dockerfile", "almalinux-8", "osinfo-db-tools"],
    ["manifest", "-n", Path(__file__).parent.parent.joinpath("examples", "manifest.yml")],
    ["container", "engines"]
]


@pytest.mark.parametrize("test_cli_args", cli_args)
def test_commands(test_cli_args):
    if sys.prefix == sys.base_prefix:
        # we're running the tests directly from git using the lcitool wrapper
        lcitool_path = Path(__file__).parent.parent.joinpath("bin", "lcitool")
    else:
        # we're running the tests in a virtual env
        lcitool_path = Path(sys.prefix, "bin/lcitool")

    subprocess.check_call([lcitool_path] + test_cli_args,
                          stdout=subprocess.DEVNULL)
