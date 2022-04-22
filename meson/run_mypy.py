#!/usr/bin/env python3

from pathlib import Path
import argparse
import os
import subprocess
import sys
import typing as T

from mesonbuild.mesonlib import version_compare

modules = [
    # fully typed submodules
    # 'mesonbuild/ast',
    'mesonbuild/cmake',
    'mesonbuild/compilers',
    'mesonbuild/dependencies',
    'mesonbuild/interpreterbase',
    'mesonbuild/linkers',
    'mesonbuild/scripts',
    'mesonbuild/wrap',

    # specific files
    'mesonbuild/arglist.py',
    # 'mesonbuild/coredata.py',
    'mesonbuild/envconfig.py',
    'mesonbuild/interpreter/interpreterobjects.py',
    'mesonbuild/mcompile.py',
    'mesonbuild/mdevenv.py',
    'mesonbuild/mesonlib/platform.py',
    'mesonbuild/mesonlib/universal.py',
    'mesonbuild/minit.py',
    'mesonbuild/minstall.py',
    'mesonbuild/mintro.py',
    'mesonbuild/mlog.py',
    'mesonbuild/modules/fs.py',
    'mesonbuild/modules/unstable_rust.py',
    'mesonbuild/modules/qt.py',
    'mesonbuild/mparser.py',
    'mesonbuild/msetup.py',
    'mesonbuild/mtest.py',
    'mesonbuild/optinterpreter.py',
    'mesonbuild/programs.py',

    'run_custom_lint.py',
    'run_mypy.py',
    'run_project_tests.py',
    'run_single_test.py',
    'tools'
]

if os.name == 'posix':
    modules.append('mesonbuild/mesonlib/posix.py')
elif os.name == 'nt':
    modules.append('mesonbuild/mesonlib/win32.py')

def check_mypy() -> None:
    try:
        import mypy
    except ImportError:
        print('Failed import mypy')
        sys.exit(1)
    from mypy.version import __version__ as mypy_version
    if not version_compare(mypy_version, '>=0.812'):
        print('mypy >=0.812 is required, older versions report spurious errors')
        sys.exit(1)

def main() -> int:
    check_mypy()

    root = Path(__file__).absolute().parent
    args = []  # type: T.List[str]

    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('-p', '--pretty', action='store_true', help='pretty print mypy errors')
    parser.add_argument('-C', '--clear', action='store_true', help='clear the terminal before running mypy')

    opts = parser.parse_args()
    if opts.pretty:
        args.append('--pretty')

    if opts.clear:
        print('\x1bc', end='', flush=True)

    print('Running mypy (this can take some time) ...')
    p = subprocess.run(
        [sys.executable, '-m', 'mypy'] + args + modules,
        cwd=root,
    )
    return p.returncode

if __name__ == '__main__':
    sys.exit(main())
