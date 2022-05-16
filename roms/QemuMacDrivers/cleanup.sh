#!/bin/sh
#
# Cleanup cruft left by MacOS

find . -name "@eaDir" -print0 | xargs -0 rm -rf
find . -type d -print0 | xargs -0 chmod o-w
find . -type f -print0 | xargs -0 chmod a-x
chmod +x cleanup.sh
