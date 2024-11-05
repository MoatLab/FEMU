# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# NOTE: shared lib versioning has *NOTHING* to do with software package version
#
# If source code has changed, revision++
# if any interfaces have been added, removed, or changed, current++, revision=0
# if any interfaces have been added, age++
# if any interfaces have been removed or changed, age=0
#
# i.e. AGE refers to backwards compatibility.
# e.g. If we start with 5.3.0 and we're releasing new version:
#      - bug fix no api change: 5.4.0
#      - new API call, backwards compatible otherwise: 6.0.1
#      - API removed, or changed (i.e. not backwards compat): 6.0.0

LIBFLASH_VERSION_CURRENT=5
LIBFLASH_VERSION_REVISION=3
LIBFLASH_VERSION_AGE=0

SHARED_NAME=libflash.so.${LIBFLASH_VERSION_CURRENT}.${LIBFLASH_VERSION_REVISION}.${LIBFLASH_VERSION_AGE}
