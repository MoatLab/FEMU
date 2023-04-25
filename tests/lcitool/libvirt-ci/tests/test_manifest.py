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
from lcitool.manifest import Manifest


def test_generate(targets, packages, projects, monkeypatch):
    manifest_path = Path(test_utils.test_data_indir(__file__), "manifest.yml")

    # Squish the header that contains argv with paths we don't
    # want in the output
    def fake_header(cliargv):
        return ""

    writes = {}
    mkdirs = set()
    unlinks = set()

    def fake_write(path, content):
        writes[path.as_posix()] = content

    def fake_mkdir(self, **kwargs):
        mkdirs.add(self)

    def fake_unlink(self, **kwargs):
        unlinks.add(self)

    def fake_exists(self):
        return self in set((
            Path("ci", "containers"),
            Path("ci", "cirrus"),
        ))

    def fake_glob(self, pattern):
        files = set((
            # to be deleted
            Path("ci", "cirrus", "freebsd-9.vars"),
            # to be re-written
            Path("ci", "cirrus", "freebsd-current.vars"),
            # to be deleted
            Path("ci", "containers", "almalinux-8.Dockerfile"),
            # to be re-written
            Path("ci", "containers", "fedora-rawhide.Dockerfile"),
        ))

        return filter(lambda f: fnmatch(f.as_posix(), pattern), files)

    # Force loading the facts before monkeypatching is enabled
    test_utils.force_load(packages=packages, projects=projects, targets=targets)

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
            manifest = Manifest(targets, packages, projects, fp, quiet=True)

        manifest.generate()

    # Helpers to validate that expected operations took place

    def assert_mkdir(key):
        assert key in mkdirs
        mkdirs.remove(key)

    def assert_unlink(key):
        assert key in unlinks
        unlinks.remove(key)

    def assert_write(filename):
        actual_path = Path(filename)
        expected_path = Path(test_utils.test_data_outdir(__file__), filename)

        test_utils.assert_matches_file(writes[actual_path.as_posix()],
                                       expected_path,
                                       allow_regenerate=False)
        del writes[actual_path.as_posix()]

    def assert_operations():
        # Verify which directories we expect to be created
        assert_mkdir(Path("ci", "gitlab"))
        assert_mkdir(Path("ci", "containers"))
        assert_mkdir(Path("ci", "cirrus"))
        assert_mkdir(Path("ci", "buildenv"))

        # Verify which files we expect to be deleted
        assert_unlink(Path("ci", "cirrus", "freebsd-9.vars"))
        assert_unlink(Path("ci", "containers", "almalinux-8.Dockerfile"))

        # Verify content of files we expect to be created
        assert_write(Path("ci", "gitlab.yml"))
        assert_write(Path("ci", "gitlab", "container-templates.yml"))
        assert_write(Path("ci", "gitlab", "containers.yml"))
        assert_write(Path("ci", "gitlab", "build-templates.yml"))
        assert_write(Path("ci", "gitlab", "builds.yml"))
        assert_write(Path("ci", "gitlab", "sanity-checks.yml"))
        assert_write(Path("ci", "cirrus", "freebsd-current.vars"))
        assert_write(Path("ci", "cirrus", "macos-12.vars"))
        assert_write(Path("ci", "cirrus", "macos-13.vars"))
        assert_write(Path("ci", "containers", "centos-stream-9.Dockerfile"))
        assert_write(Path("ci", "containers", "fedora-rawhide.Dockerfile"))
        assert_write(Path("ci", "containers", "fedora-rawhide-cross-mingw32.Dockerfile"))
        assert_write(Path("ci", "containers", "debian-10.Dockerfile"))
        assert_write(Path("ci", "containers", "debian-sid-cross-ppc64le.Dockerfile"))
        assert_write(Path("ci", "containers", "debian-sid-cross-i686.Dockerfile"))
        assert_write(Path("ci", "buildenv", "centos-stream-9.sh"))
        assert_write(Path("ci", "buildenv", "fedora-rawhide.sh"))
        assert_write(Path("ci", "buildenv", "fedora-rawhide-cross-mingw32.sh"))
        assert_write(Path("ci", "buildenv", "debian-10.sh"))
        assert_write(Path("ci", "buildenv", "debian-sid-cross-ppc64le.sh"))
        assert_write(Path("ci", "buildenv", "debian-sid-cross-i686.sh"))

        # Verify nothing else unexpected was created/deleted/written
        assert len(mkdirs) == 0
        assert len(unlinks) == 0
        assert len(writes) == 0

    try:
        assert_operations()
    finally:
        if pytest.custom_args["regenerate_output"]:
            with open(manifest_path, "r") as fp:
                manifest = Manifest(targets, packages, projects, fp, quiet=True,
                                    basedir=Path(test_utils.test_data_outdir(__file__)))

            manifest.generate()
