#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

echo "#if defined(__powerpc__)
echo -n ARCH_POWERPC
#elif defined(__arm__)
echo -n ARCH_ARM
#elif defined(__aarch64__)
echo -n ARCH_AARCH64
#else
echo -n ARCH_UNKNOWN
#endif" | $1cpp | /bin/sh

