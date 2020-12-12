#!/usr/bin/env python3


# Copyright 2018 The Meson development team

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

'''
Regenerate markdown docs by using `meson.py` from the root dir
'''

import argparse
import jinja2
import os
import re
import subprocess
import sys
import textwrap
import typing as T
from pathlib import Path

PathLike = T.Union[Path,str]

def _get_meson_output(root_dir: Path, args: T.List):
    env = os.environ.copy()
    env['COLUMNS'] = '80'
    return subprocess.run([str(sys.executable), str(root_dir/'meson.py')] + args, check=True, capture_output=True, text=True, env=env).stdout.strip()

def get_commands_data(root_dir: Path):
    usage_start_pattern = re.compile(r'^usage: ', re.MULTILINE)
    positional_start_pattern = re.compile(r'^positional arguments:[\t ]*[\r\n]+', re.MULTILINE)
    options_start_pattern = re.compile(r'^optional arguments:[\t ]*[\r\n]+', re.MULTILINE)
    commands_start_pattern = re.compile(r'^[A-Za-z ]*[Cc]ommands:[\t ]*[\r\n]+', re.MULTILINE)

    def get_next_start(iterators, end):
        return next((i.start() for i in iterators if i), end)

    def normalize_text(text):
        # clean up formatting
        out = text
        out = re.sub(r'\r\n', r'\r', out, flags=re.MULTILINE) # replace newlines with a linux EOL
        out = re.sub(r'^ +$', '', out, flags=re.MULTILINE) # remove trailing whitespace
        out = re.sub(r'(?:^\n+|\n+$)', '', out) # remove trailing empty lines
        return out

    def parse_cmd(cmd):
        cmd_len = len(cmd)
        usage = usage_start_pattern.search(cmd)
        positionals = positional_start_pattern.search(cmd)
        options = options_start_pattern.search(cmd)
        commands = commands_start_pattern.search(cmd)

        arguments_start = get_next_start([positionals, options, commands], None)
        assert arguments_start

        # replace `usage:` with `$` and dedent
        dedent_size = (usage.end() - usage.start()) - len('$ ')
        usage_text = textwrap.dedent(f'{dedent_size * " "}$ {normalize_text(cmd[usage.end():arguments_start])}')

        return {
            'usage': usage_text,
            'arguments': normalize_text(cmd[arguments_start:cmd_len]),
        }

    def clean_dir_arguments(text):
        # Remove platform specific defaults
        args = [
            'prefix',
            'bindir',
            'datadir',
            'includedir',
            'infodir',
            'libdir',
            'libexecdir',
            'localedir',
            'localstatedir',
            'mandir',
            'sbindir',
            'sharedstatedir',
            'sysconfdir'
        ]
        out = text
        for a in args:
            out = re.sub(r'(--' + a + r' .+?)\s+\(default:.+?\)(\.)?', r'\1\2', out, flags=re.MULTILINE|re.DOTALL)
        return out

    output = _get_meson_output(root_dir, ['--help'])
    commands = set(c.strip() for c in re.findall(r'usage:(?:.+)?{((?:[a-z]+,*)+?)}', output, re.MULTILINE|re.DOTALL)[0].split(','))
    commands.remove('help')

    cmd_data = dict()

    for cmd in commands:
        cmd_output = _get_meson_output(root_dir, [cmd, '--help'])
        cmd_data[cmd] = parse_cmd(cmd_output)
        if cmd in ['setup', 'configure']:
            cmd_data[cmd]['arguments'] = clean_dir_arguments(cmd_data[cmd]['arguments'])

    return cmd_data

def regenerate_commands(root_dir: Path, output_dir: Path) -> None:
    with open(root_dir/'docs'/'markdown_dynamic'/'Commands.md') as f:
        template = f.read()

    cmd_data = get_commands_data(root_dir)

    t = jinja2.Template(template, undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
    content = t.render(cmd_help=cmd_data)

    output_file = output_dir/'Commands.md'
    with open(output_file, 'w') as f:
        f.write(content)

    print(f'`{output_file}` was regenerated')

def regenerate_docs(output_dir: PathLike,
                    dummy_output_file: T.Optional[PathLike]) -> None:
    if not output_dir:
        raise ValueError(f'Output directory value is not set')
        
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    root_dir = Path(__file__).resolve().parent.parent

    regenerate_commands(root_dir, output_dir)

    if dummy_output_file:
        with open(output_dir/dummy_output_file, 'w') as f:
            f.write('dummy file for custom_target output')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate meson docs')
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--dummy-output-file', type=str)
    
    args = parser.parse_args()

    regenerate_docs(output_dir=args.output_dir,
                    dummy_output_file=args.dummy_output_file)
