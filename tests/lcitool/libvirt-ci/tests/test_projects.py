# test_projects: test the project package definitions
#
# Copyright (C) 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

from lcitool.targets import BuildTarget

from conftest import ALL_PROJECTS


@pytest.fixture(params=ALL_PROJECTS)
def project(request, projects):
    try:
        return projects.public[request.param]
    except KeyError:
        return projects.internal[request.param]


def test_project_packages(targets, packages, project):
    target = BuildTarget(targets, packages, targets.targets[0])
    project.get_packages(target)


def test_project_package_sorting(project):
    pkgs = project._load_generic_packages()

    otherpkgs = sorted(pkgs)

    assert otherpkgs == pkgs
