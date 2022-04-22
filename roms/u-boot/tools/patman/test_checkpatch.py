# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0+
#
# Tests for U-Boot-specific checkpatch.pl features
#
# Copyright (c) 2011 The Chromium OS Authors.
#

import os
import tempfile
import unittest

from patman import checkpatch
from patman import gitutil
from patman import patchstream
from patman import series
from patman import commit


class Line:
    def __init__(self, fname, text):
        self.fname = fname
        self.text = text


class PatchMaker:
    def __init__(self):
        self.lines = []

    def add_line(self, fname, text):
        self.lines.append(Line(fname, text))

    def get_patch_text(self):
        base = '''From 125b77450f4c66b8fd9654319520bbe795c9ef31 Mon Sep 17 00:00:00 2001
From: Simon Glass <sjg@chromium.org>
Date: Sun, 14 Jun 2020 09:45:14 -0600
Subject: [PATCH] Test commit

This is a test commit.

Signed-off-by: Simon Glass <sjg@chromium.org>
---

'''
        lines = base.splitlines()

        # Create the diffstat
        change = 0
        insert = 0
        for line in self.lines:
            lines.append(' %s      | 1 +' % line.fname)
            change += 1
            insert += 1
        lines.append(' %d files changed, %d insertions(+)' % (change, insert))
        lines.append('')

        # Create the patch info for each file
        for line in self.lines:
            lines.append('diff --git a/%s b/%s' % (line.fname, line.fname))
            lines.append('index 7837d459f18..5ba7840f68e 100644')
            lines.append('--- a/%s' % line.fname)
            lines.append('+++ b/%s' % line.fname)
            lines += ('''@@ -121,6 +121,7 @@ enum uclass_id {
 	UCLASS_W1,		/* Dallas 1-Wire bus */
 	UCLASS_W1_EEPROM,	/* one-wire EEPROMs */
 	UCLASS_WDT,		/* Watchdog Timer driver */
+%s

 	UCLASS_COUNT,
 	UCLASS_INVALID = -1,
''' % line.text).splitlines()
        lines.append('---')
        lines.append('2.17.1')

        return '\n'.join(lines)

    def get_patch(self):
        inhandle, inname = tempfile.mkstemp()
        infd = os.fdopen(inhandle, 'w')
        infd.write(self.get_patch_text())
        infd.close()
        return inname

    def run_checkpatch(self):
        return checkpatch.CheckPatch(self.get_patch(), show_types=True)


class TestPatch(unittest.TestCase):
    """Test the u_boot_line() function in checkpatch.pl"""

    def testBasic(self):
        """Test basic filter operation"""
        data='''

From 656c9a8c31fa65859d924cd21da920d6ba537fad Mon Sep 17 00:00:00 2001
From: Simon Glass <sjg@chromium.org>
Date: Thu, 28 Apr 2011 09:58:51 -0700
Subject: [PATCH (resend) 3/7] Tegra2: Add more clock support

This adds functions to enable/disable clocks and reset to on-chip peripherals.

cmd/pci.c:152:11: warning: format ‘%llx’ expects argument of type
   ‘long long unsigned int’, but argument 3 has type
   ‘u64 {aka long unsigned int}’ [-Wformat=]

BUG=chromium-os:13875
TEST=build U-Boot for Seaboard, boot

Change-Id: I80fe1d0c0b7dd10aa58ce5bb1d9290b6664d5413

Review URL: http://codereview.chromium.org/6900006

Signed-off-by: Simon Glass <sjg@chromium.org>
---
 arch/arm/cpu/armv7/tegra2/Makefile         |    2 +-
 arch/arm/cpu/armv7/tegra2/ap20.c           |   57 ++----
 arch/arm/cpu/armv7/tegra2/clock.c          |  163 +++++++++++++++++
'''
        expected='''Message-Id: <19991231235959.0.I80fe1d0c0b7dd10aa58ce5bb1d9290b6664d5413@changeid>


From 656c9a8c31fa65859d924cd21da920d6ba537fad Mon Sep 17 00:00:00 2001
From: Simon Glass <sjg@chromium.org>
Date: Thu, 28 Apr 2011 09:58:51 -0700
Subject: [PATCH (resend) 3/7] Tegra2: Add more clock support

This adds functions to enable/disable clocks and reset to on-chip peripherals.

cmd/pci.c:152:11: warning: format ‘%llx’ expects argument of type
   ‘long long unsigned int’, but argument 3 has type
   ‘u64 {aka long unsigned int}’ [-Wformat=]

Signed-off-by: Simon Glass <sjg@chromium.org>
---

 arch/arm/cpu/armv7/tegra2/Makefile         |    2 +-
 arch/arm/cpu/armv7/tegra2/ap20.c           |   57 ++----
 arch/arm/cpu/armv7/tegra2/clock.c          |  163 +++++++++++++++++
'''
        out = ''
        inhandle, inname = tempfile.mkstemp()
        infd = os.fdopen(inhandle, 'w', encoding='utf-8')
        infd.write(data)
        infd.close()

        exphandle, expname = tempfile.mkstemp()
        expfd = os.fdopen(exphandle, 'w', encoding='utf-8')
        expfd.write(expected)
        expfd.close()

        # Normally by the time we call fix_patch we've already collected
        # metadata.  Here, we haven't, but at least fake up something.
        # Set the "count" to -1 which tells fix_patch to use a bogus/fixed
        # time for generating the Message-Id.
        com = commit.Commit('')
        com.change_id = 'I80fe1d0c0b7dd10aa58ce5bb1d9290b6664d5413'
        com.count = -1

        patchstream.fix_patch(None, inname, series.Series(), com)

        rc = os.system('diff -u %s %s' % (inname, expname))
        self.assertEqual(rc, 0)

        os.remove(inname)
        os.remove(expname)

    def GetData(self, data_type):
        data='''From 4924887af52713cabea78420eff03badea8f0035 Mon Sep 17 00:00:00 2001
From: Simon Glass <sjg@chromium.org>
Date: Thu, 7 Apr 2011 10:14:41 -0700
Subject: [PATCH 1/4] Add microsecond boot time measurement

This defines the basics of a new boot time measurement feature. This allows
logging of very accurate time measurements as the boot proceeds, by using
an available microsecond counter.

%s
---
 README              |   11 ++++++++
 MAINTAINERS         |    3 ++
 common/bootstage.c  |   50 ++++++++++++++++++++++++++++++++++++
 include/bootstage.h |   71 +++++++++++++++++++++++++++++++++++++++++++++++++++
 include/common.h    |    8 ++++++
 5 files changed, 141 insertions(+), 0 deletions(-)
 create mode 100644 common/bootstage.c
 create mode 100644 include/bootstage.h

diff --git a/README b/README
index 6f3748d..f9e4e65 100644
--- a/README
+++ b/README
@@ -2026,6 +2026,17 @@ The following options need to be configured:
 		example, some LED's) on your board. At the moment,
 		the following checkpoints are implemented:

+- Time boot progress
+		CONFIG_BOOTSTAGE
+
+		Define this option to enable microsecond boot stage timing
+		on supported platforms. For this to work your platform
+		needs to define a function timer_get_us() which returns the
+		number of microseconds since reset. This would normally
+		be done in your SOC or board timer.c file.
+
+		You can add calls to bootstage_mark() to set time markers.
+
 - Standalone program support:
 		CONFIG_STANDALONE_LOAD_ADDR

diff --git a/MAINTAINERS b/MAINTAINERS
index b167b028ec..beb7dc634f 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -474,3 +474,8 @@ S:	Maintained
 T:	git git://git.denx.de/u-boot.git
 F:	*
 F:	*/
+
+BOOTSTAGE
+M:	Simon Glass <sjg@chromium.org>
+L:	u-boot@lists.denx.de
+F:	common/bootstage.c
diff --git a/common/bootstage.c b/common/bootstage.c
new file mode 100644
index 0000000..2234c87
--- /dev/null
+++ b/common/bootstage.c
@@ -0,0 +1,37 @@
+%s
+/*
+ * Copyright (c) 2011, Google Inc. All rights reserved.
+ *
+ */
+
+/*
+ * This module records the progress of boot and arbitrary commands, and
+ * permits accurate timestamping of each. The records can optionally be
+ * passed to kernel in the ATAGs
+ */
+
+#include <common.h>
+
+struct bootstage_record {
+	u32 time_us;
+	const char *name;
+};
+
+static struct bootstage_record record[BOOTSTAGE_COUNT];
+
+u32 bootstage_mark(enum bootstage_id id, const char *name)
+{
+	struct bootstage_record *rec = &record[id];
+
+	/* Only record the first event for each */
+%sif (!rec->name) {
+		rec->time_us = (u32)timer_get_us();
+		rec->name = name;
+	}
+	if (!rec->name &&
+	%ssomething_else) {
+		rec->time_us = (u32)timer_get_us();
+		rec->name = name;
+	}
+%sreturn rec->time_us;
+}
--
1.7.3.1
'''
        signoff = 'Signed-off-by: Simon Glass <sjg@chromium.org>\n'
        license = '// SPDX-License-Identifier: GPL-2.0+'
        tab = '	'
        indent = '    '
        if data_type == 'good':
            pass
        elif data_type == 'no-signoff':
            signoff = ''
        elif data_type == 'no-license':
            license = ''
        elif data_type == 'spaces':
            tab = '   '
        elif data_type == 'indent':
            indent = tab
        else:
            print('not implemented')
        return data % (signoff, license, tab, indent, tab)

    def SetupData(self, data_type):
        inhandle, inname = tempfile.mkstemp()
        infd = os.fdopen(inhandle, 'w')
        data = self.GetData(data_type)
        infd.write(data)
        infd.close()
        return inname

    def testGood(self):
        """Test checkpatch operation"""
        inf = self.SetupData('good')
        result = checkpatch.CheckPatch(inf)
        self.assertEqual(result.ok, True)
        self.assertEqual(result.problems, [])
        self.assertEqual(result.errors, 0)
        self.assertEqual(result.warnings, 0)
        self.assertEqual(result.checks, 0)
        self.assertEqual(result.lines, 62)
        os.remove(inf)

    def testNoSignoff(self):
        inf = self.SetupData('no-signoff')
        result = checkpatch.CheckPatch(inf)
        self.assertEqual(result.ok, False)
        self.assertEqual(len(result.problems), 1)
        self.assertEqual(result.errors, 1)
        self.assertEqual(result.warnings, 0)
        self.assertEqual(result.checks, 0)
        self.assertEqual(result.lines, 62)
        os.remove(inf)

    def testNoLicense(self):
        inf = self.SetupData('no-license')
        result = checkpatch.CheckPatch(inf)
        self.assertEqual(result.ok, False)
        self.assertEqual(len(result.problems), 1)
        self.assertEqual(result.errors, 0)
        self.assertEqual(result.warnings, 1)
        self.assertEqual(result.checks, 0)
        self.assertEqual(result.lines, 62)
        os.remove(inf)

    def testSpaces(self):
        inf = self.SetupData('spaces')
        result = checkpatch.CheckPatch(inf)
        self.assertEqual(result.ok, False)
        self.assertEqual(len(result.problems), 3)
        self.assertEqual(result.errors, 0)
        self.assertEqual(result.warnings, 3)
        self.assertEqual(result.checks, 0)
        self.assertEqual(result.lines, 62)
        os.remove(inf)

    def testIndent(self):
        inf = self.SetupData('indent')
        result = checkpatch.CheckPatch(inf)
        self.assertEqual(result.ok, False)
        self.assertEqual(len(result.problems), 1)
        self.assertEqual(result.errors, 0)
        self.assertEqual(result.warnings, 0)
        self.assertEqual(result.checks, 1)
        self.assertEqual(result.lines, 62)
        os.remove(inf)

    def checkSingleMessage(self, pm, msg, pmtype = 'warning'):
        """Helper function to run checkpatch and check the result

        Args:
            pm: PatchMaker object to use
            msg: Expected message (e.g. 'LIVETREE')
            pmtype: Type of problem ('error', 'warning')
        """
        result = pm.run_checkpatch()
        if pmtype == 'warning':
            self.assertEqual(result.warnings, 1)
        elif pmtype == 'error':
            self.assertEqual(result.errors, 1)
        if len(result.problems) != 1:
            print(result.problems)
        self.assertEqual(len(result.problems), 1)
        self.assertIn(msg, result.problems[0]['cptype'])

    def testUclass(self):
        """Test for possible new uclass"""
        pm = PatchMaker()
        pm.add_line('include/dm/uclass-id.h', 'UCLASS_WIBBLE,')
        self.checkSingleMessage(pm, 'NEW_UCLASS')

    def testLivetree(self):
        """Test for using the livetree API"""
        pm = PatchMaker()
        pm.add_line('common/main.c', 'fdtdec_do_something()')
        self.checkSingleMessage(pm, 'LIVETREE')

    def testNewCommand(self):
        """Test for adding a new command"""
        pm = PatchMaker()
        pm.add_line('common/main.c', 'do_wibble(struct cmd_tbl *cmd_tbl)')
        self.checkSingleMessage(pm, 'CMD_TEST')

    def testPreferIf(self):
        """Test for using #ifdef"""
        pm = PatchMaker()
        pm.add_line('common/main.c', '#ifdef CONFIG_YELLOW')
        pm.add_line('common/init.h', '#ifdef CONFIG_YELLOW')
        pm.add_line('fred.dtsi', '#ifdef CONFIG_YELLOW')
        self.checkSingleMessage(pm, "PREFER_IF")

    def testCommandUseDefconfig(self):
        """Test for enabling/disabling commands using preprocesor"""
        pm = PatchMaker()
        pm.add_line('common/main.c', '#undef CONFIG_CMD_WHICH')
        self.checkSingleMessage(pm, 'DEFINE_CONFIG_CMD', 'error')

    def testBarredIncludeInHdr(self):
        """Test for using a barred include in a header file"""
        pm = PatchMaker()
        #pm.add_line('include/myfile.h', '#include <common.h>')
        pm.add_line('include/myfile.h', '#include <dm.h>')
        self.checkSingleMessage(pm, 'BARRED_INCLUDE_IN_HDR', 'error')

    def testConfigIsEnabledConfig(self):
        """Test for accidental CONFIG_IS_ENABLED(CONFIG_*) calls"""
        pm = PatchMaker()
        pm.add_line('common/main.c', 'if (CONFIG_IS_ENABLED(CONFIG_CLK))')
        self.checkSingleMessage(pm, 'CONFIG_IS_ENABLED_CONFIG', 'error')

    def check_struct(self, auto, suffix, warning):
        """Check one of the warnings for struct naming

        Args:
            auto: Auto variable name, e.g. 'per_child_auto'
            suffix: Suffix to expect on member, e.g. '_priv'
            warning: Warning name, e.g. 'PRIV_AUTO'
        """
        pm = PatchMaker()
        pm.add_line('common/main.c', '.%s = sizeof(struct(fred)),' % auto)
        pm.add_line('common/main.c', '.%s = sizeof(struct(mary%s)),' %
                    (auto, suffix))
        self.checkSingleMessage(
            pm, warning, "struct 'fred' should have a %s suffix" % suffix)

    def testDmDriverAuto(self):
        """Check for the correct suffix on 'struct driver' auto members"""
        self.check_struct('priv_auto', '_priv', 'PRIV_AUTO')
        self.check_struct('plat_auto', '_plat', 'PLAT_AUTO')
        self.check_struct('per_child_auto', '_priv', 'CHILD_PRIV_AUTO')
        self.check_struct('per_child_plat_auto', '_plat', 'CHILD_PLAT_AUTO')

    def testDmUclassAuto(self):
        """Check for the correct suffix on 'struct uclass' auto members"""
        # Some of these are omitted since they match those from struct driver
        self.check_struct('per_device_auto', '_priv', 'DEVICE_PRIV_AUTO')
        self.check_struct('per_device_plat_auto', '_plat', 'DEVICE_PLAT_AUTO')

    def check_strl(self, func):
        """Check one of the checks for strn(cpy|cat)"""
        pm = PatchMaker()
        pm.add_line('common/main.c', "strn%s(foo, bar, sizeof(foo));" % func)
        self.checkSingleMessage(pm, "STRL",
            "strl%s is preferred over strn%s because it always produces a nul-terminated string\n"
            % (func, func))

    def testStrl(self):
        """Check for uses of strn(cat|cpy)"""
        self.check_strl("cat");
        self.check_strl("cpy");

if __name__ == "__main__":
    unittest.main()
    gitutil.RunTests()
