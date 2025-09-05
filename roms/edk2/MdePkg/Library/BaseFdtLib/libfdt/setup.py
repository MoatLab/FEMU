#!/usr/bin/env python3
# SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause)

"""
Copied from dtc/setup.py file for SWIG libfdt
Copyright (C) 2017 Google, Inc.
Written by Simon Glass <sjg@chromium.org>
"""

from setuptools import setup, Extension
from setuptools.command.build_py import build_py as _build_py

with open("README", "r") as fh:
    long_description = fh.read()

libfdt_module = Extension(
    '_libfdt',
    sources=[
        'libfdt/libfdt.i',
        'libfdt/fdt.c',
        'libfdt/fdt_ro.c',
        'libfdt/fdt_rw.c',
        'libfdt/fdt_sw.c',
        'libfdt/fdt_wip.c',
        'libfdt/fdt_addresses.c',
        'libfdt/fdt_check.c',
        'libfdt/fdt_empty_tree.c',
        'libfdt/fdt_overlay.c',
        'libfdt/fdt_strerror.c',
    ],
    define_macros=[('PY_SSIZE_T_CLEAN', None)],
    include_dirs=['libfdt'],
    swig_opts=['-Ilibfdt'],
)


class build_py(_build_py):
    def run(self):
        self.run_command("build_ext")
        return super().run()


setup(
    name='pylibfdt',
    cmdclass = {'build_py' : build_py},
    use_scm_version=True,
    setup_requires = ['setuptools_scm'],
    author='Simon Glass <sjg@chromium.org>',
    description='Python binding for libfdt',
    ext_modules=[libfdt_module],
    py_modules=['libfdt'],
    package_dir={'': 'libfdt'},

    long_description=long_description,
    long_description_content_type="text/plain",
)
