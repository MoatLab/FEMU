# test_formatters: test the formatters
#
# Copyright (C) 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

import test_utils.utils as test_utils
from pathlib import Path

from lcitool import util
from lcitool.projects import Projects
from lcitool.formatters import ShellVariablesFormatter, JSONVariablesFormatter, DockerfileFormatter


scenarios = [
    # A minimalist application, testing package managers
    pytest.param("test-minimal", "debian-10", None, id="minimal-debian-10"),
    pytest.param("test-minimal", "almalinux-8", None, id="minimal-almalinux-8"),
    pytest.param("test-minimal", "opensuse-leap-152", None, id="minimal-opensuse-leap-152"),
    pytest.param("test-minimal", "alpine-314", None, id="minimal-alpine-314"),
    pytest.param("test-minimal", "opensuse-tumbleweed", None, id="minimal-opensuse-tumbleweed"),

    # A minimalist application, testing two different cross-compile scenarios
    pytest.param("test-minimal", "debian-10", "s390x", id="minimal-debian-10-cross-s390x"),
    pytest.param("test-minimal", "fedora-rawhide", "mingw64", id="minimal-fedora-rawhide-cross-mingw64"),

    # An application using cache symlinks
    pytest.param("test-ccache", "debian-10", None, id="ccache-debian-10"),
    pytest.param("test-ccache", "debian-10", "s390x", id="ccache-debian-10-cross-s390x"),
]

layer_scenarios = [
    # Overriding default base image
    pytest.param("test-minimal", "debian-10", "s390x", "debian-10-common", "all", id="minimal-debian-10-common-cross-s390x"),

    # Customizing the layers
    pytest.param("test-minimal", "fedora-rawhide", "mingw64", None, "all", id="minimal-fedora-rawhide-cross-mingw64-combined"),
    pytest.param("test-minimal", "fedora-rawhide", "mingw64", None, "native", id="minimal-fedora-rawhide-cross-mingw64-native"),
    pytest.param("test-minimal", "fedora-rawhide", "mingw64", None, "foreign", id="minimal-fedora-rawhide-cross-mingw64-foreign"),
    pytest.param("test-minimal", "fedora-rawhide", "mingw64", "fedora-rawhide-common", "foreign", id="minimal-fedora-rawhide-common-cross-mingw64-foreign"),
]


@pytest.fixture
def custom_projects():
    oldprojects = Projects()._projects
    olddir = util.get_extra_data_dir()
    util.set_extra_data_dir(test_utils.test_data_dir(__file__))
    Projects()._projects = None
    yield
    Projects()._projects = oldprojects
    util.set_extra_data_dir(olddir)


@pytest.mark.parametrize("project,target,arch", scenarios)
def test_dockerfiles(custom_projects, project, target, arch, request):
    gen = DockerfileFormatter()
    actual = gen.format(target, [project], arch)
    expected_path = Path(test_utils.test_data_outdir(__file__), request.node.callspec.id + ".Dockerfile")
    test_utils.assert_matches_file(actual, expected_path)


@pytest.mark.parametrize("project,target,arch,base,layers", layer_scenarios)
def test_dockerfile_layers(custom_projects, project, target, arch, base, layers, request):
    gen = DockerfileFormatter(base, layers)
    actual = gen.format(target, [project], arch)
    expected_path = Path(test_utils.test_data_outdir(__file__), request.node.callspec.id + ".Dockerfile")
    test_utils.assert_matches_file(actual, expected_path)


@pytest.mark.parametrize("project,target,arch", scenarios)
def test_variables_shell(custom_projects, project, target, arch, request):
    gen = ShellVariablesFormatter()
    actual = gen.format(target, [project], arch)
    expected_path = Path(test_utils.test_data_outdir(__file__), request.node.callspec.id + ".vars")
    test_utils.assert_matches_file(actual, expected_path)


@pytest.mark.parametrize("project,target,arch", scenarios)
def test_variables_json(custom_projects, project, target, arch, request):
    gen = JSONVariablesFormatter()
    actual = gen.format(target, [project], arch)
    expected_path = Path(test_utils.test_data_outdir(__file__), request.node.callspec.id + ".json")
    test_utils.assert_matches_file(actual, expected_path)
