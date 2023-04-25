# test_commands: sanity check command operation
#
# Copyright (C) 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os
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
    pybase = Path(__file__).parent.parent
    lcitool = pybase.joinpath("bin", "lcitool")
    subenv = os.environ
    subenv["PYTHONPATH"] = str(pybase)
    subprocess.check_call([lcitool] + test_cli_args, stdout=subprocess.DEVNULL)


@pytest.mark.skipif(sys.prefix == sys.base_prefix,
                    reason="lcitool package not installed")
@pytest.mark.parametrize("test_cli_args", cli_args)
def test_commands_installed(test_cli_args):
    lcitool_venv_path = Path(sys.prefix, "bin/lcitool")
    subprocess.check_call([lcitool_venv_path] + test_cli_args,
                          stdout=subprocess.DEVNULL)
