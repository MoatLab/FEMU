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


def test_generate(assert_equal, targets, packages, projects, monkeypatch):
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

    def assert_write(filename, assert_func):
        actual_path = Path(filename)
        expected_path = Path(test_utils.test_data_outdir(__file__), filename)

        assert_func(writes[actual_path.as_posix()], expected_path)
        del writes[actual_path.as_posix()]

    def assert_operations(**kwargs):
        # Verify which directories we expect to be created
        assert_mkdir(Path("ci", "gitlab"))
        assert_mkdir(Path("ci", "containers"))
        assert_mkdir(Path("ci", "cirrus"))
        assert_mkdir(Path("ci", "buildenv"))

        # Verify which files we expect to be deleted
        assert_unlink(Path("ci", "cirrus", "freebsd-9.vars"))
        assert_unlink(Path("ci", "containers", "almalinux-8.Dockerfile"))

        # Verify content of files we expect to be created
        assert_writes = [
            Path("ci", "gitlab.yml"),
            Path("ci", "gitlab", "container-templates.yml"),
            Path("ci", "gitlab", "containers.yml"),
            Path("ci", "gitlab", "build-templates.yml"),
            Path("ci", "gitlab", "builds.yml"),
            Path("ci", "gitlab", "sanity-checks.yml"),
            Path("ci", "cirrus", "freebsd-current.vars"),
            Path("ci", "cirrus", "macos-12.vars"),
            Path("ci", "cirrus", "macos-13.vars"),
            Path("ci", "containers", "centos-stream-9.Dockerfile"),
            Path("ci", "containers", "fedora-rawhide.Dockerfile"),
            Path("ci", "containers", "fedora-rawhide-cross-mingw32.Dockerfile"),
            Path("ci", "containers", "debian-12.Dockerfile"),
            Path("ci", "containers", "debian-sid-cross-ppc64le.Dockerfile"),
            Path("ci", "containers", "debian-sid-cross-i686.Dockerfile"),
            Path("ci", "buildenv", "centos-stream-9.sh"),
            Path("ci", "buildenv", "fedora-rawhide.sh"),
            Path("ci", "buildenv", "fedora-rawhide-cross-mingw32.sh"),
            Path("ci", "buildenv", "debian-12.sh"),
            Path("ci", "buildenv", "debian-sid-cross-ppc64le.sh"),
            Path("ci", "buildenv", "debian-sid-cross-i686.sh"),
        ]
        for path in assert_writes:
            assert_write(path, kwargs["assert_func"])

        # Verify nothing else unexpected was created/deleted/written
        assert len(mkdirs) == 0
        assert len(unlinks) == 0
        assert len(writes) == 0

    try:
        assert_operations(assert_func=assert_equal)
    finally:
        if pytest.custom_args["regenerate_output"]:
            with open(manifest_path, "r") as fp:
                manifest = Manifest(targets, packages, projects, fp, quiet=True,
                                    basedir=Path(test_utils.test_data_outdir(__file__)))

            manifest.generate()
