# test_projects: test the project package definitions
#
# Copyright (C) 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

from lcitool.projects import Projects
from lcitool.inventory import Inventory


ALL_PROJECTS = sorted(Projects().names)


@pytest.mark.parametrize(
    "name",
    ALL_PROJECTS
)
def test_project_packages(name):
    project = Projects().projects[name]
    target = Inventory().targets[0]
    facts = Inventory().target_facts[target]
    project.get_packages(facts)
