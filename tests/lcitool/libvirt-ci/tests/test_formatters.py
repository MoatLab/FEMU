# test_formatters: test the formatters
#
# Copyright (C) 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

import test_utils.utils as test_utils
from pathlib import Path

from lcitool.targets import BuildTarget
from lcitool.formatters import DockerfileFormatter
from lcitool.formatters import ShellVariablesFormatter, JSONVariablesFormatter, YamlVariablesFormatter
from lcitool.formatters import ShellBuildEnvFormatter


scenarios = [
    # A minimalist application, testing package managers
    pytest.param("libvirt-go-xml-module", "debian-12", "x86_64", None, id="libvirt-go-xml-module-debian-12"),
    pytest.param("libvirt-go-xml-module", "almalinux-9", "x86_64", None, id="libvirt-go-xml-module-almalinux-9"),
    pytest.param("libvirt-go-xml-module", "opensuse-leap-15", "x86_64", None, id="libvirt-go-xml-module-opensuse-leap-15"),
    pytest.param("libvirt-go-xml-module", "alpine-edge", "x86_64", None, id="libvirt-go-xml-module-alpine-edge"),
    pytest.param("libvirt-go-xml-module", "opensuse-tumbleweed", "x86_64", None, id="libvirt-go-xml-module-opensuse-tumbleweed"),

    # An application using cache symlinks
    pytest.param("libvirt-go-module", "debian-12", "x86_64", None, id="libvirt-go-debian-12"),
    pytest.param("libvirt-go-module", "debian-12", "x86_64", "s390x", id="libvirt-go-debian-12-cross-s390x"),
    pytest.param("libvirt-go-module", "fedora-rawhide", "x86_64", "mingw64", id="libvirt-go-fedora-rawhide-cross-mingw64"),
    pytest.param("libvirt", "debian-sid", "s390x", None, id="libvirt-debian-sid-s390x"),
]

layer_scenarios = [
    # Overriding default base image
    pytest.param("libvirt-go-module", "debian-12", "x86_64", "s390x", "debian-12-common", "all", id="libvirt-go-debian-12-common-cross-s390x"),

    # Customizing the layers
    pytest.param("libvirt-go-module", "fedora-rawhide", "x86_64", "mingw64", None, "all", id="libvirt-go-fedora-rawhide-cross-mingw64-combined"),
    pytest.param("libvirt-go-module", "fedora-rawhide", "x86_64", "mingw64", None, "native", id="libvirt-go-fedora-rawhide-cross-mingw64-native"),
    pytest.param("libvirt-go-module", "fedora-rawhide", "x86_64", "mingw64", None, "foreign", id="libvirt-go-fedora-rawhide-cross-mingw64-foreign"),
    pytest.param("libvirt-go-module", "fedora-rawhide", "x86_64", "mingw64", "fedora-rawhide-common", "foreign", id="libvirt-go-fedora-rawhide-common-cross-mingw64-foreign"),
    pytest.param("libvirt", "debian-sid", "s390x", "aarch64", None, "all", id="libvirt-debian-sid-s390x-cross-aarch64-combined"),
]


@pytest.mark.parametrize("project,target,native_arch,cross_arch", scenarios)
def test_dockerfiles(assert_equal, packages, projects, targets, project, target, native_arch, cross_arch, request):
    gen = DockerfileFormatter(projects)
    target_obj = BuildTarget(targets, packages, target, native_arch, cross_arch)
    actual = gen.format(target_obj, [project])
    expected_path = Path(test_utils.test_data_outdir(__file__), request.node.callspec.id + ".Dockerfile")
    assert_equal(actual, expected_path)


@pytest.mark.parametrize("project,target,native_arch,cross_arch,base,layers", layer_scenarios)
def test_dockerfile_layers(assert_equal, packages, projects, targets, project, target, native_arch, cross_arch, base, layers, request):
    gen = DockerfileFormatter(projects, base, layers)
    target_obj = BuildTarget(targets, packages, target, native_arch, cross_arch)
    actual = gen.format(target_obj, [project])
    expected_path = Path(test_utils.test_data_outdir(__file__), request.node.callspec.id + ".Dockerfile")
    assert_equal(actual, expected_path)


@pytest.mark.parametrize("project,target,native_arch,cross_arch", scenarios)
def test_variables_shell(assert_equal, packages, projects, targets, project, target, native_arch, cross_arch, request):
    gen = ShellVariablesFormatter(projects)
    target_obj = BuildTarget(targets, packages, target, native_arch, cross_arch)
    actual = gen.format(target_obj, [project])
    expected_path = Path(test_utils.test_data_outdir(__file__), request.node.callspec.id + ".vars")
    assert_equal(actual, expected_path)


@pytest.mark.parametrize("project,target,native_arch,cross_arch", scenarios)
def test_variables_json(assert_equal, packages, projects, targets, project, target, native_arch, cross_arch, request):
    gen = JSONVariablesFormatter(projects)
    target_obj = BuildTarget(targets, packages, target, native_arch, cross_arch)
    actual = gen.format(target_obj, [project])
    expected_path = Path(test_utils.test_data_outdir(__file__), request.node.callspec.id + ".json")
    assert_equal(actual, expected_path)


@pytest.mark.parametrize("project,target,native_arch,cross_arch", scenarios)
def test_variables_yaml(assert_equal, packages, projects, targets, project, target, native_arch, cross_arch, request):
    gen = YamlVariablesFormatter(projects)
    target_obj = BuildTarget(targets, packages, target, native_arch, cross_arch)
    actual = gen.format(target_obj, [project])
    expected_path = Path(test_utils.test_data_outdir(__file__), request.node.callspec.id + ".yaml")
    assert_equal(actual, expected_path)


@pytest.mark.parametrize("project,target,native_arch,cross_arch", scenarios)
def test_prepbuildenv(assert_equal, packages, projects, targets, project, target, native_arch, cross_arch, request):
    gen = ShellBuildEnvFormatter(projects)
    target_obj = BuildTarget(targets, packages, target, native_arch, cross_arch)
    actual = gen.format(target_obj, [project])
    expected_path = Path(test_utils.test_data_outdir(__file__), request.node.callspec.id + ".sh")
    assert_equal(actual, expected_path)
