# test_manifest: test the manifest
#
# Copyright (C) 2022 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from fnmatch import fnmatch
import pytest

import test_utils.utils as test_utils
from pathlib import Path

from lcitool import util
from lcitool.projects import Projects
from lcitool.manifest import Manifest


@pytest.fixture
def custom_projects():
    oldprojects = Projects()._projects
    olddir = util.get_extra_data_dir()
    util.set_extra_data_dir(test_utils.test_data_dir(__file__))
    Projects()._projects = None
    yield
    Projects()._projects = oldprojects
    util.set_extra_data_dir(olddir)


def test_generate(monkeypatch, custom_projects):
    manifest_path = Path(test_utils.test_data_indir(__file__), "manifest.yml")

    # Squish the header that contains argv with paths we don't
    # want in the output
    def fake_header(cliargv):
        return ""

    writes = {}
    mkdirs = {}
    unlinks = {}

    def fake_write(path, content):
        writes[path.as_posix()] = content

    def fake_mkdir(self, **kwargs):
        mkdirs[self.as_posix()] = True

    def fake_unlink(self, **kwargs):
        unlinks[self.as_posix()] = True

    def fake_exists(self):
        return self.as_posix() in [
            "ci/containers",
            "ci/cirrus",
        ]

    def fake_glob(self, pattern):
        files = [
            # to be deleted
            "ci/cirrus/freebsd-9.vars",
            # to be re-written
            "ci/cirrus/freebsd-current.vars",
            # to be deleted
            "ci/containers/almalinux-8.Dockerfile",
            # to be re-written
            "ci/containers/fedora-rawhide.Dockerfile",
        ]

        want = filter(lambda f: fnmatch(f, pattern), files)
        return [Path(f) for f in want]

    monkeypatch.setattr(util, 'generate_file_header', fake_header)

    with monkeypatch.context() as m:
        # Stop the manifest generation interacting with the
        # host OS state, capturing its operations
        m.setattr(util, 'atomic_write', fake_write)
        m.setattr(Path, 'mkdir', fake_mkdir)
        m.setattr(Path, 'exists', fake_exists)
        m.setattr(Path, 'unlink', fake_unlink)
        m.setattr(Path, 'glob', fake_glob)

        with open(manifest_path, "r") as fp:
            manifest = Manifest(fp, quiet=True)

        manifest.generate()

    # Helpers to validate that expected operations took place

    def assert_mkdir(key):
        assert key in mkdirs
        del mkdirs[key]

    def assert_unlink(key):
        assert key in unlinks
        del unlinks[key]

    def assert_write(filename):
        expected_path = Path(test_utils.test_data_outdir(__file__), filename)

        test_utils.assert_matches_file(writes[filename], expected_path,
                                       allow_regenerate=False)
        del writes[filename]

    def assert_operations():
        # Verify which directories we expect to be created
        assert_mkdir("ci")
        assert_mkdir("ci/containers")
        assert_mkdir("ci/cirrus")

        # Verify which files we expect to be deleted
        assert_unlink("ci/cirrus/freebsd-9.vars")
        assert_unlink("ci/containers/almalinux-8.Dockerfile")

        # Verify content of files we expect to be created
        assert_write("ci/gitlab.yml")
        assert_write("ci/cirrus/freebsd-current.vars")
        assert_write("ci/cirrus/macos-11.vars")
        assert_write("ci/containers/centos-stream-9.Dockerfile")
        assert_write("ci/containers/fedora-rawhide.Dockerfile")
        assert_write("ci/containers/fedora-rawhide-cross-mingw32.Dockerfile")
        assert_write("ci/containers/debian-sid-cross-ppc64le.Dockerfile")
        assert_write("ci/containers/debian-sid-cross-i686.Dockerfile")

        # Verify nothing else unexpected was created/deleted/written
        assert(len(mkdirs) == 0)
        assert(len(unlinks) == 0)
        assert(len(writes) == 0)

    try:
        assert_operations()
    finally:
        if pytest.custom_args["regenerate_output"]:
            with open(manifest_path, "r") as fp:
                manifest = Manifest(fp, quiet=True,
                                    basedir=Path(test_utils.test_data_outdir(__file__)))

            manifest.generate()
