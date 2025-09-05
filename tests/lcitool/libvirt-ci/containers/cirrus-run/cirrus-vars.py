#!/usr/bin/env python3

import os
import re
import sys

var = re.compile(r'@([a-zA-Z0-9_]+)@')


# Return empty string if var is not set, since not all
# OS targets require all vars to be set.
def get_env(matchobj):
    return os.environ.get(matchobj.group(1), '')


for line in sys.stdin:
    print(var.sub(get_env, line), end='')

sys.exit(0)
