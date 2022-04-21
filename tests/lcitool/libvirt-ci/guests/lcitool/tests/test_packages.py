# test_packages: test the package mapping resolving code
#
# Copyright (C) 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

import test_utils.utils as test_utils

from pathlib import Path
from lcitool.inventory import Inventory
from lcitool.projects import Project, Projects, ProjectError
from lcitool.package import NativePackage, CrossPackage, PyPIPackage, CPANPackage


ALL_TARGETS = sorted(Inventory().targets)


def get_non_cross_targets():
    ret = []
    for target in ALL_TARGETS:
        if target.startswith("debian-") or target.startswith("fedora-"):
            continue

        ret.append(target)
    return ret


def packages_as_dict(raw_pkgs):
    ret = {}
    for cls in [NativePackage, CrossPackage, PyPIPackage, CPANPackage]:
        pkg_type = cls.__name__.replace("Package", "").lower()

        pkg_names = set([p.name for p in raw_pkgs.values() if isinstance(p, cls)])
        if pkg_names:
            ret[pkg_type] = sorted(pkg_names)
    return ret


@pytest.fixture
def test_project():
    return Project("packages",
                   Path(test_utils.test_data_indir(__file__), "packages.yml"))


def test_verify_all_mappings_and_packages():
    expected_path = Path(test_utils.test_data_indir(__file__), "packages.yml")
    actual = {"packages": sorted(Projects().mappings["mappings"].keys())}

    test_utils.assert_yaml_matches_file(actual, expected_path)


native_params = [
    pytest.param(target, None, id=target) for target in ALL_TARGETS
]

cross_params = [
    pytest.param("debian-10", "s390x", id="debian-10-cross-s390x"),
    pytest.param("fedora-rawhide", "mingw64", id="fedora-rawhide-cross-mingw64")
]


@pytest.mark.parametrize("target,arch", native_params + cross_params)
def test_package_resolution(test_project, target, arch):
    if arch is None:
        outfile = f"{target}.yml"
    else:
        outfile = f"{target}-cross-{arch}.yml"
    expected_path = Path(test_utils.test_data_outdir(__file__), outfile)
    pkgs = test_project.get_packages(Inventory().target_facts[target],
                                     cross_arch=arch)
    actual = packages_as_dict(pkgs)

    test_utils.assert_yaml_matches_file(actual, expected_path)


@pytest.mark.parametrize(
    "target",
    [pytest.param(target, id=target) for target in get_non_cross_targets()],
)
def test_unsupported_cross_platform(test_project, target):
    with pytest.raises(ProjectError):
        test_project.get_packages(Inventory().target_facts[target],
                                  cross_arch="s390x")


@pytest.mark.parametrize(
    "target,arch",
    [
        pytest.param("debian-sid", "mingw64", id="debian-sid-cross-mingw64"),
        pytest.param("fedora-rawhide", "s390x", id="fedora-rawhide-cross-s390x"),
    ],
)
def test_cross_platform_arch_mismatch(test_project, target, arch):
    with pytest.raises(ProjectError):
        test_project.get_packages(Inventory().target_facts[target],
                                  cross_arch=arch)
