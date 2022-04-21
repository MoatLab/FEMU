# test_commands: sanity check command operation
#
# Copyright (C) 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import pytest
import subprocess
from pathlib import Path


cli_args = [
    ["targets"],
    ["projects"],
    ["variables", "almalinux-8", "osinfo-db-tools"],
    ["dockerfile", "almalinux-8", "osinfo-db-tools"],
    ["manifest", "-n", Path(__file__).parent.parent.joinpath("examples", "manifest.yml")],
]


@pytest.mark.parametrize("test_cli_args", cli_args)
def test_commands(test_cli_args):
    pybase = Path(__file__).parent.parent
    lcitool = pybase.joinpath("bin", "lcitool")
    subenv = os.environ
    subenv["PYTHONPATH"] = str(pybase)
    subprocess.check_call([lcitool] + test_cli_args, stdout=subprocess.DEVNULL)
