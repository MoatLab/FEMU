# SPDX-License-Identifier: GPL-2.0+
# Copyright (c) 2016 Google, Inc
# Written by Simon Glass <sjg@chromium.org>
#
# To run a single test, change to this directory, and:
#
#    python -m unittest func_test.TestFunctional.testHelp

import collections
import gzip
import hashlib
from optparse import OptionParser
import os
import re
import shutil
import struct
import sys
import tempfile
import unittest

from binman import cbfs_util
from binman import cmdline
from binman import control
from binman import elf
from binman import elf_test
from binman import fmap_util
from binman import state
from dtoc import fdt
from dtoc import fdt_util
from binman.etype import fdtmap
from binman.etype import image_header
from binman.image import Image
from patman import command
from patman import test_util
from patman import tools
from patman import tout

# Contents of test files, corresponding to different entry types
U_BOOT_DATA           = b'1234'
U_BOOT_IMG_DATA       = b'img'
U_BOOT_SPL_DATA       = b'56780123456789abcdefghi'
U_BOOT_TPL_DATA       = b'tpl9876543210fedcbazyw'
BLOB_DATA             = b'89'
ME_DATA               = b'0abcd'
VGA_DATA              = b'vga'
U_BOOT_DTB_DATA       = b'udtb'
U_BOOT_SPL_DTB_DATA   = b'spldtb'
U_BOOT_TPL_DTB_DATA   = b'tpldtb'
X86_START16_DATA      = b'start16'
X86_START16_SPL_DATA  = b'start16spl'
X86_START16_TPL_DATA  = b'start16tpl'
X86_RESET16_DATA      = b'reset16'
X86_RESET16_SPL_DATA  = b'reset16spl'
X86_RESET16_TPL_DATA  = b'reset16tpl'
PPC_MPC85XX_BR_DATA   = b'ppcmpc85xxbr'
U_BOOT_NODTB_DATA     = b'nodtb with microcode pointer somewhere in here'
U_BOOT_SPL_NODTB_DATA = b'splnodtb with microcode pointer somewhere in here'
U_BOOT_TPL_NODTB_DATA = b'tplnodtb with microcode pointer somewhere in here'
FSP_DATA              = b'fsp'
CMC_DATA              = b'cmc'
VBT_DATA              = b'vbt'
MRC_DATA              = b'mrc'
TEXT_DATA             = 'text'
TEXT_DATA2            = 'text2'
TEXT_DATA3            = 'text3'
CROS_EC_RW_DATA       = b'ecrw'
GBB_DATA              = b'gbbd'
BMPBLK_DATA           = b'bmp'
VBLOCK_DATA           = b'vblk'
FILES_DATA            = (b"sorry I'm late\nOh, don't bother apologising, I'm " +
                         b"sorry you're alive\n")
COMPRESS_DATA         = b'compress xxxxxxxxxxxxxxxxxxxxxx data'
COMPRESS_DATA_BIG     = COMPRESS_DATA * 2
REFCODE_DATA          = b'refcode'
FSP_M_DATA            = b'fsp_m'
FSP_S_DATA            = b'fsp_s'
FSP_T_DATA            = b'fsp_t'
ATF_BL31_DATA         = b'bl31'
OPENSBI_DATA          = b'opensbi'
SCP_DATA              = b'scp'
TEST_FDT1_DATA        = b'fdt1'
TEST_FDT2_DATA        = b'test-fdt2'
ENV_DATA              = b'var1=1\nvar2="2"'

# Subdirectory of the input dir to use to put test FDTs
TEST_FDT_SUBDIR       = 'fdts'

# The expected size for the device tree in some tests
EXTRACT_DTB_SIZE = 0x3c9

# Properties expected to be in the device tree when update_dtb is used
BASE_DTB_PROPS = ['offset', 'size', 'image-pos']

# Extra properties expected to be in the device tree when allow-repack is used
REPACK_DTB_PROPS = ['orig-offset', 'orig-size']


class TestFunctional(unittest.TestCase):
    """Functional tests for binman

    Most of these use a sample .dts file to build an image and then check
    that it looks correct. The sample files are in the test/ subdirectory
    and are numbered.

    For each entry type a very small test file is created using fixed
    string contents. This makes it easy to test that things look right, and
    debug problems.

    In some cases a 'real' file must be used - these are also supplied in
    the test/ diurectory.
    """
    @classmethod
    def setUpClass(cls):
        global entry
        from binman import entry

        # Handle the case where argv[0] is 'python'
        cls._binman_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
        cls._binman_pathname = os.path.join(cls._binman_dir, 'binman')

        # Create a temporary directory for input files
        cls._indir = tempfile.mkdtemp(prefix='binmant.')

        # Create some test files
        TestFunctional._MakeInputFile('u-boot.bin', U_BOOT_DATA)
        TestFunctional._MakeInputFile('u-boot.img', U_BOOT_IMG_DATA)
        TestFunctional._MakeInputFile('spl/u-boot-spl.bin', U_BOOT_SPL_DATA)
        TestFunctional._MakeInputFile('tpl/u-boot-tpl.bin', U_BOOT_TPL_DATA)
        TestFunctional._MakeInputFile('blobfile', BLOB_DATA)
        TestFunctional._MakeInputFile('me.bin', ME_DATA)
        TestFunctional._MakeInputFile('vga.bin', VGA_DATA)
        cls._ResetDtbs()

        TestFunctional._MakeInputFile('u-boot-br.bin', PPC_MPC85XX_BR_DATA)

        TestFunctional._MakeInputFile('u-boot-x86-start16.bin', X86_START16_DATA)
        TestFunctional._MakeInputFile('spl/u-boot-x86-start16-spl.bin',
                                      X86_START16_SPL_DATA)
        TestFunctional._MakeInputFile('tpl/u-boot-x86-start16-tpl.bin',
                                      X86_START16_TPL_DATA)

        TestFunctional._MakeInputFile('u-boot-x86-reset16.bin',
                                      X86_RESET16_DATA)
        TestFunctional._MakeInputFile('spl/u-boot-x86-reset16-spl.bin',
                                      X86_RESET16_SPL_DATA)
        TestFunctional._MakeInputFile('tpl/u-boot-x86-reset16-tpl.bin',
                                      X86_RESET16_TPL_DATA)

        TestFunctional._MakeInputFile('u-boot-nodtb.bin', U_BOOT_NODTB_DATA)
        TestFunctional._MakeInputFile('spl/u-boot-spl-nodtb.bin',
                                      U_BOOT_SPL_NODTB_DATA)
        TestFunctional._MakeInputFile('tpl/u-boot-tpl-nodtb.bin',
                                      U_BOOT_TPL_NODTB_DATA)
        TestFunctional._MakeInputFile('fsp.bin', FSP_DATA)
        TestFunctional._MakeInputFile('cmc.bin', CMC_DATA)
        TestFunctional._MakeInputFile('vbt.bin', VBT_DATA)
        TestFunctional._MakeInputFile('mrc.bin', MRC_DATA)
        TestFunctional._MakeInputFile('ecrw.bin', CROS_EC_RW_DATA)
        TestFunctional._MakeInputDir('devkeys')
        TestFunctional._MakeInputFile('bmpblk.bin', BMPBLK_DATA)
        TestFunctional._MakeInputFile('refcode.bin', REFCODE_DATA)
        TestFunctional._MakeInputFile('fsp_m.bin', FSP_M_DATA)
        TestFunctional._MakeInputFile('fsp_s.bin', FSP_S_DATA)
        TestFunctional._MakeInputFile('fsp_t.bin', FSP_T_DATA)

        cls._elf_testdir = os.path.join(cls._indir, 'elftest')
        elf_test.BuildElfTestFiles(cls._elf_testdir)

        # ELF file with a '_dt_ucode_base_size' symbol
        TestFunctional._MakeInputFile('u-boot',
            tools.ReadFile(cls.ElfTestFile('u_boot_ucode_ptr')))

        # Intel flash descriptor file
        cls._SetupDescriptor()

        shutil.copytree(cls.TestFile('files'),
                        os.path.join(cls._indir, 'files'))

        TestFunctional._MakeInputFile('compress', COMPRESS_DATA)
        TestFunctional._MakeInputFile('compress_big', COMPRESS_DATA_BIG)
        TestFunctional._MakeInputFile('bl31.bin', ATF_BL31_DATA)
        TestFunctional._MakeInputFile('fw_dynamic.bin', OPENSBI_DATA)
        TestFunctional._MakeInputFile('scp.bin', SCP_DATA)

        # Add a few .dtb files for testing
        TestFunctional._MakeInputFile('%s/test-fdt1.dtb' % TEST_FDT_SUBDIR,
                                      TEST_FDT1_DATA)
        TestFunctional._MakeInputFile('%s/test-fdt2.dtb' % TEST_FDT_SUBDIR,
                                      TEST_FDT2_DATA)

        TestFunctional._MakeInputFile('env.txt', ENV_DATA)

        # Travis-CI may have an old lz4
        cls.have_lz4 = True
        try:
            tools.Run('lz4', '--no-frame-crc', '-c',
                      os.path.join(cls._indir, 'u-boot.bin'), binary=True)
        except:
            cls.have_lz4 = False

    @classmethod
    def tearDownClass(cls):
        """Remove the temporary input directory and its contents"""
        if cls.preserve_indir:
            print('Preserving input dir: %s' % cls._indir)
        else:
            if cls._indir:
                shutil.rmtree(cls._indir)
        cls._indir = None

    @classmethod
    def setup_test_args(cls, preserve_indir=False, preserve_outdirs=False,
                        toolpath=None, verbosity=None):
        """Accept arguments controlling test execution

        Args:
            preserve_indir: Preserve the shared input directory used by all
                tests in this class.
            preserve_outdir: Preserve the output directories used by tests. Each
                test has its own, so this is normally only useful when running a
                single test.
            toolpath: ist of paths to use for tools
        """
        cls.preserve_indir = preserve_indir
        cls.preserve_outdirs = preserve_outdirs
        cls.toolpath = toolpath
        cls.verbosity = verbosity

    def _CheckLz4(self):
        if not self.have_lz4:
            self.skipTest('lz4 --no-frame-crc not available')

    def _CleanupOutputDir(self):
        """Remove the temporary output directory"""
        if self.preserve_outdirs:
            print('Preserving output dir: %s' % tools.outdir)
        else:
            tools._FinaliseForTest()

    def setUp(self):
        # Enable this to turn on debugging output
        # tout.Init(tout.DEBUG)
        command.test_result = None

    def tearDown(self):
        """Remove the temporary output directory"""
        self._CleanupOutputDir()

    def _SetupImageInTmpdir(self):
        """Set up the output image in a new temporary directory

        This is used when an image has been generated in the output directory,
        but we want to run binman again. This will create a new output
        directory and fail to delete the original one.

        This creates a new temporary directory, copies the image to it (with a
        new name) and removes the old output directory.

        Returns:
            Tuple:
                Temporary directory to use
                New image filename
        """
        image_fname = tools.GetOutputFilename('image.bin')
        tmpdir = tempfile.mkdtemp(prefix='binman.')
        updated_fname = os.path.join(tmpdir, 'image-updated.bin')
        tools.WriteFile(updated_fname, tools.ReadFile(image_fname))
        self._CleanupOutputDir()
        return tmpdir, updated_fname

    @classmethod
    def _ResetDtbs(cls):
        TestFunctional._MakeInputFile('u-boot.dtb', U_BOOT_DTB_DATA)
        TestFunctional._MakeInputFile('spl/u-boot-spl.dtb', U_BOOT_SPL_DTB_DATA)
        TestFunctional._MakeInputFile('tpl/u-boot-tpl.dtb', U_BOOT_TPL_DTB_DATA)

    def _RunBinman(self, *args, **kwargs):
        """Run binman using the command line

        Args:
            Arguments to pass, as a list of strings
            kwargs: Arguments to pass to Command.RunPipe()
        """
        result = command.RunPipe([[self._binman_pathname] + list(args)],
                capture=True, capture_stderr=True, raise_on_error=False)
        if result.return_code and kwargs.get('raise_on_error', True):
            raise Exception("Error running '%s': %s" % (' '.join(args),
                            result.stdout + result.stderr))
        return result

    def _DoBinman(self, *argv):
        """Run binman using directly (in the same process)

        Args:
            Arguments to pass, as a list of strings
        Returns:
            Return value (0 for success)
        """
        argv = list(argv)
        args = cmdline.ParseArgs(argv)
        args.pager = 'binman-invalid-pager'
        args.build_dir = self._indir

        # For testing, you can force an increase in verbosity here
        # args.verbosity = tout.DEBUG
        return control.Binman(args)

    def _DoTestFile(self, fname, debug=False, map=False, update_dtb=False,
                    entry_args=None, images=None, use_real_dtb=False,
                    use_expanded=False, verbosity=None, allow_missing=False,
                    extra_indirs=None):
        """Run binman with a given test file

        Args:
            fname: Device-tree source filename to use (e.g. 005_simple.dts)
            debug: True to enable debugging output
            map: True to output map files for the images
            update_dtb: Update the offset and size of each entry in the device
                tree before packing it into the image
            entry_args: Dict of entry args to supply to binman
                key: arg name
                value: value of that arg
            images: List of image names to build
            use_real_dtb: True to use the test file as the contents of
                the u-boot-dtb entry. Normally this is not needed and the
                test contents (the U_BOOT_DTB_DATA string) can be used.
                But in some test we need the real contents.
            use_expanded: True to use expanded entries where available, e.g.
                'u-boot-expanded' instead of 'u-boot'
            verbosity: Verbosity level to use (0-3, None=don't set it)
            allow_missing: Set the '--allow-missing' flag so that missing
                external binaries just produce a warning instead of an error
            extra_indirs: Extra input directories to add using -I
        """
        args = []
        if debug:
            args.append('-D')
        if verbosity is not None:
            args.append('-v%d' % verbosity)
        elif self.verbosity:
            args.append('-v%d' % self.verbosity)
        if self.toolpath:
            for path in self.toolpath:
                args += ['--toolpath', path]
        args += ['build', '-p', '-I', self._indir, '-d', self.TestFile(fname)]
        if map:
            args.append('-m')
        if update_dtb:
            args.append('-u')
        if not use_real_dtb:
            args.append('--fake-dtb')
        if not use_expanded:
            args.append('--no-expanded')
        if entry_args:
            for arg, value in entry_args.items():
                args.append('-a%s=%s' % (arg, value))
        if allow_missing:
            args.append('-M')
        if images:
            for image in images:
                args += ['-i', image]
        if extra_indirs:
            for indir in extra_indirs:
                args += ['-I', indir]
        return self._DoBinman(*args)

    def _SetupDtb(self, fname, outfile='u-boot.dtb'):
        """Set up a new test device-tree file

        The given file is compiled and set up as the device tree to be used
        for ths test.

        Args:
            fname: Filename of .dts file to read
            outfile: Output filename for compiled device-tree binary

        Returns:
            Contents of device-tree binary
        """
        tmpdir = tempfile.mkdtemp(prefix='binmant.')
        dtb = fdt_util.EnsureCompiled(self.TestFile(fname), tmpdir)
        with open(dtb, 'rb') as fd:
            data = fd.read()
            TestFunctional._MakeInputFile(outfile, data)
        shutil.rmtree(tmpdir)
        return data

    def _GetDtbContentsForSplTpl(self, dtb_data, name):
        """Create a version of the main DTB for SPL or SPL

        For testing we don't actually have different versions of the DTB. With
        U-Boot we normally run fdtgrep to remove unwanted nodes, but for tests
        we don't normally have any unwanted nodes.

        We still want the DTBs for SPL and TPL to be different though, since
        otherwise it is confusing to know which one we are looking at. So add
        an 'spl' or 'tpl' property to the top-level node.

        Args:
            dtb_data: dtb data to modify (this should be a value devicetree)
            name: Name of a new property to add

        Returns:
            New dtb data with the property added
        """
        dtb = fdt.Fdt.FromData(dtb_data)
        dtb.Scan()
        dtb.GetNode('/binman').AddZeroProp(name)
        dtb.Sync(auto_resize=True)
        dtb.Pack()
        return dtb.GetContents()

    def _DoReadFileDtb(self, fname, use_real_dtb=False, use_expanded=False,
                       map=False, update_dtb=False, entry_args=None,
                       reset_dtbs=True, extra_indirs=None):
        """Run binman and return the resulting image

        This runs binman with a given test file and then reads the resulting
        output file. It is a shortcut function since most tests need to do
        these steps.

        Raises an assertion failure if binman returns a non-zero exit code.

        Args:
            fname: Device-tree source filename to use (e.g. 005_simple.dts)
            use_real_dtb: True to use the test file as the contents of
                the u-boot-dtb entry. Normally this is not needed and the
                test contents (the U_BOOT_DTB_DATA string) can be used.
                But in some test we need the real contents.
            use_expanded: True to use expanded entries where available, e.g.
                'u-boot-expanded' instead of 'u-boot'
            map: True to output map files for the images
            update_dtb: Update the offset and size of each entry in the device
                tree before packing it into the image
            entry_args: Dict of entry args to supply to binman
                key: arg name
                value: value of that arg
            reset_dtbs: With use_real_dtb the test dtb is overwritten by this
                function. If reset_dtbs is True, then the original test dtb
                is written back before this function finishes
            extra_indirs: Extra input directories to add using -I

        Returns:
            Tuple:
                Resulting image contents
                Device tree contents
                Map data showing contents of image (or None if none)
                Output device tree binary filename ('u-boot.dtb' path)
        """
        dtb_data = None
        # Use the compiled test file as the u-boot-dtb input
        if use_real_dtb:
            dtb_data = self._SetupDtb(fname)

            # For testing purposes, make a copy of the DT for SPL and TPL. Add
            # a node indicating which it is, so aid verification.
            for name in ['spl', 'tpl']:
                dtb_fname = '%s/u-boot-%s.dtb' % (name, name)
                outfile = os.path.join(self._indir, dtb_fname)
                TestFunctional._MakeInputFile(dtb_fname,
                        self._GetDtbContentsForSplTpl(dtb_data, name))

        try:
            retcode = self._DoTestFile(fname, map=map, update_dtb=update_dtb,
                    entry_args=entry_args, use_real_dtb=use_real_dtb,
                    use_expanded=use_expanded, extra_indirs=extra_indirs)
            self.assertEqual(0, retcode)
            out_dtb_fname = tools.GetOutputFilename('u-boot.dtb.out')

            # Find the (only) image, read it and return its contents
            image = control.images['image']
            image_fname = tools.GetOutputFilename('image.bin')
            self.assertTrue(os.path.exists(image_fname))
            if map:
                map_fname = tools.GetOutputFilename('image.map')
                with open(map_fname) as fd:
                    map_data = fd.read()
            else:
                map_data = None
            with open(image_fname, 'rb') as fd:
                return fd.read(), dtb_data, map_data, out_dtb_fname
        finally:
            # Put the test file back
            if reset_dtbs and use_real_dtb:
                self._ResetDtbs()

    def _DoReadFileRealDtb(self, fname):
        """Run binman with a real .dtb file and return the resulting data

        Args:
            fname: DT source filename to use (e.g. 082_fdt_update_all.dts)

        Returns:
            Resulting image contents
        """
        return self._DoReadFileDtb(fname, use_real_dtb=True, update_dtb=True)[0]

    def _DoReadFile(self, fname, use_real_dtb=False):
        """Helper function which discards the device-tree binary

        Args:
            fname: Device-tree source filename to use (e.g. 005_simple.dts)
            use_real_dtb: True to use the test file as the contents of
                the u-boot-dtb entry. Normally this is not needed and the
                test contents (the U_BOOT_DTB_DATA string) can be used.
                But in some test we need the real contents.

        Returns:
            Resulting image contents
        """
        return self._DoReadFileDtb(fname, use_real_dtb)[0]

    @classmethod
    def _MakeInputFile(cls, fname, contents):
        """Create a new test input file, creating directories as needed

        Args:
            fname: Filename to create
            contents: File contents to write in to the file
        Returns:
            Full pathname of file created
        """
        pathname = os.path.join(cls._indir, fname)
        dirname = os.path.dirname(pathname)
        if dirname and not os.path.exists(dirname):
            os.makedirs(dirname)
        with open(pathname, 'wb') as fd:
            fd.write(contents)
        return pathname

    @classmethod
    def _MakeInputDir(cls, dirname):
        """Create a new test input directory, creating directories as needed

        Args:
            dirname: Directory name to create

        Returns:
            Full pathname of directory created
        """
        pathname = os.path.join(cls._indir, dirname)
        if not os.path.exists(pathname):
            os.makedirs(pathname)
        return pathname

    @classmethod
    def _SetupSplElf(cls, src_fname='bss_data'):
        """Set up an ELF file with a '_dt_ucode_base_size' symbol

        Args:
            Filename of ELF file to use as SPL
        """
        TestFunctional._MakeInputFile('spl/u-boot-spl',
            tools.ReadFile(cls.ElfTestFile(src_fname)))

    @classmethod
    def _SetupTplElf(cls, src_fname='bss_data'):
        """Set up an ELF file with a '_dt_ucode_base_size' symbol

        Args:
            Filename of ELF file to use as TPL
        """
        TestFunctional._MakeInputFile('tpl/u-boot-tpl',
            tools.ReadFile(cls.ElfTestFile(src_fname)))

    @classmethod
    def _SetupDescriptor(cls):
        with open(cls.TestFile('descriptor.bin'), 'rb') as fd:
            TestFunctional._MakeInputFile('descriptor.bin', fd.read())

    @classmethod
    def TestFile(cls, fname):
        return os.path.join(cls._binman_dir, 'test', fname)

    @classmethod
    def ElfTestFile(cls, fname):
        return os.path.join(cls._elf_testdir, fname)

    def AssertInList(self, grep_list, target):
        """Assert that at least one of a list of things is in a target

        Args:
            grep_list: List of strings to check
            target: Target string
        """
        for grep in grep_list:
            if grep in target:
                return
        self.fail("Error: '%s' not found in '%s'" % (grep_list, target))

    def CheckNoGaps(self, entries):
        """Check that all entries fit together without gaps

        Args:
            entries: List of entries to check
        """
        offset = 0
        for entry in entries.values():
            self.assertEqual(offset, entry.offset)
            offset += entry.size

    def GetFdtLen(self, dtb):
        """Get the totalsize field from a device-tree binary

        Args:
            dtb: Device-tree binary contents

        Returns:
            Total size of device-tree binary, from the header
        """
        return struct.unpack('>L', dtb[4:8])[0]

    def _GetPropTree(self, dtb, prop_names, prefix='/binman/'):
        def AddNode(node, path):
            if node.name != '/':
                path += '/' + node.name
            for prop in node.props.values():
                if prop.name in prop_names:
                    prop_path = path + ':' + prop.name
                    tree[prop_path[len(prefix):]] = fdt_util.fdt32_to_cpu(
                        prop.value)
            for subnode in node.subnodes:
                AddNode(subnode, path)

        tree = {}
        AddNode(dtb.GetRoot(), '')
        return tree

    def testRun(self):
        """Test a basic run with valid args"""
        result = self._RunBinman('-h')

    def testFullHelp(self):
        """Test that the full help is displayed with -H"""
        result = self._RunBinman('-H')
        help_file = os.path.join(self._binman_dir, 'README.rst')
        # Remove possible extraneous strings
        extra = '::::::::::::::\n' + help_file + '\n::::::::::::::\n'
        gothelp = result.stdout.replace(extra, '')
        self.assertEqual(len(gothelp), os.path.getsize(help_file))
        self.assertEqual(0, len(result.stderr))
        self.assertEqual(0, result.return_code)

    def testFullHelpInternal(self):
        """Test that the full help is displayed with -H"""
        try:
            command.test_result = command.CommandResult()
            result = self._DoBinman('-H')
            help_file = os.path.join(self._binman_dir, 'README.rst')
        finally:
            command.test_result = None

    def testHelp(self):
        """Test that the basic help is displayed with -h"""
        result = self._RunBinman('-h')
        self.assertTrue(len(result.stdout) > 200)
        self.assertEqual(0, len(result.stderr))
        self.assertEqual(0, result.return_code)

    def testBoard(self):
        """Test that we can run it with a specific board"""
        self._SetupDtb('005_simple.dts', 'sandbox/u-boot.dtb')
        TestFunctional._MakeInputFile('sandbox/u-boot.bin', U_BOOT_DATA)
        result = self._DoBinman('build', '-n', '-b', 'sandbox')
        self.assertEqual(0, result)

    def testNeedBoard(self):
        """Test that we get an error when no board ius supplied"""
        with self.assertRaises(ValueError) as e:
            result = self._DoBinman('build')
        self.assertIn("Must provide a board to process (use -b <board>)",
                str(e.exception))

    def testMissingDt(self):
        """Test that an invalid device-tree file generates an error"""
        with self.assertRaises(Exception) as e:
            self._RunBinman('build', '-d', 'missing_file')
        # We get one error from libfdt, and a different one from fdtget.
        self.AssertInList(["Couldn't open blob from 'missing_file'",
                           'No such file or directory'], str(e.exception))

    def testBrokenDt(self):
        """Test that an invalid device-tree source file generates an error

        Since this is a source file it should be compiled and the error
        will come from the device-tree compiler (dtc).
        """
        with self.assertRaises(Exception) as e:
            self._RunBinman('build', '-d', self.TestFile('001_invalid.dts'))
        self.assertIn("FATAL ERROR: Unable to parse input tree",
                str(e.exception))

    def testMissingNode(self):
        """Test that a device tree without a 'binman' node generates an error"""
        with self.assertRaises(Exception) as e:
            self._DoBinman('build', '-d', self.TestFile('002_missing_node.dts'))
        self.assertIn("does not have a 'binman' node", str(e.exception))

    def testEmpty(self):
        """Test that an empty binman node works OK (i.e. does nothing)"""
        result = self._RunBinman('build', '-d', self.TestFile('003_empty.dts'))
        self.assertEqual(0, len(result.stderr))
        self.assertEqual(0, result.return_code)

    def testInvalidEntry(self):
        """Test that an invalid entry is flagged"""
        with self.assertRaises(Exception) as e:
            result = self._RunBinman('build', '-d',
                                     self.TestFile('004_invalid_entry.dts'))
        self.assertIn("Unknown entry type 'not-a-valid-type' in node "
                "'/binman/not-a-valid-type'", str(e.exception))

    def testSimple(self):
        """Test a simple binman with a single file"""
        data = self._DoReadFile('005_simple.dts')
        self.assertEqual(U_BOOT_DATA, data)

    def testSimpleDebug(self):
        """Test a simple binman run with debugging enabled"""
        self._DoTestFile('005_simple.dts', debug=True)

    def testDual(self):
        """Test that we can handle creating two images

        This also tests image padding.
        """
        retcode = self._DoTestFile('006_dual_image.dts')
        self.assertEqual(0, retcode)

        image = control.images['image1']
        self.assertEqual(len(U_BOOT_DATA), image.size)
        fname = tools.GetOutputFilename('image1.bin')
        self.assertTrue(os.path.exists(fname))
        with open(fname, 'rb') as fd:
            data = fd.read()
            self.assertEqual(U_BOOT_DATA, data)

        image = control.images['image2']
        self.assertEqual(3 + len(U_BOOT_DATA) + 5, image.size)
        fname = tools.GetOutputFilename('image2.bin')
        self.assertTrue(os.path.exists(fname))
        with open(fname, 'rb') as fd:
            data = fd.read()
            self.assertEqual(U_BOOT_DATA, data[3:7])
            self.assertEqual(tools.GetBytes(0, 3), data[:3])
            self.assertEqual(tools.GetBytes(0, 5), data[7:])

    def testBadAlign(self):
        """Test that an invalid alignment value is detected"""
        with self.assertRaises(ValueError) as e:
            self._DoTestFile('007_bad_align.dts')
        self.assertIn("Node '/binman/u-boot': Alignment 23 must be a power "
                      "of two", str(e.exception))

    def testPackSimple(self):
        """Test that packing works as expected"""
        retcode = self._DoTestFile('008_pack.dts')
        self.assertEqual(0, retcode)
        self.assertIn('image', control.images)
        image = control.images['image']
        entries = image.GetEntries()
        self.assertEqual(5, len(entries))

        # First u-boot
        self.assertIn('u-boot', entries)
        entry = entries['u-boot']
        self.assertEqual(0, entry.offset)
        self.assertEqual(len(U_BOOT_DATA), entry.size)

        # Second u-boot, aligned to 16-byte boundary
        self.assertIn('u-boot-align', entries)
        entry = entries['u-boot-align']
        self.assertEqual(16, entry.offset)
        self.assertEqual(len(U_BOOT_DATA), entry.size)

        # Third u-boot, size 23 bytes
        self.assertIn('u-boot-size', entries)
        entry = entries['u-boot-size']
        self.assertEqual(20, entry.offset)
        self.assertEqual(len(U_BOOT_DATA), entry.contents_size)
        self.assertEqual(23, entry.size)

        # Fourth u-boot, placed immediate after the above
        self.assertIn('u-boot-next', entries)
        entry = entries['u-boot-next']
        self.assertEqual(43, entry.offset)
        self.assertEqual(len(U_BOOT_DATA), entry.size)

        # Fifth u-boot, placed at a fixed offset
        self.assertIn('u-boot-fixed', entries)
        entry = entries['u-boot-fixed']
        self.assertEqual(61, entry.offset)
        self.assertEqual(len(U_BOOT_DATA), entry.size)

        self.assertEqual(65, image.size)

    def testPackExtra(self):
        """Test that extra packing feature works as expected"""
        data, _, _, out_dtb_fname = self._DoReadFileDtb('009_pack_extra.dts',
                                                        update_dtb=True)

        self.assertIn('image', control.images)
        image = control.images['image']
        entries = image.GetEntries()
        self.assertEqual(5, len(entries))

        # First u-boot with padding before and after
        self.assertIn('u-boot', entries)
        entry = entries['u-boot']
        self.assertEqual(0, entry.offset)
        self.assertEqual(3, entry.pad_before)
        self.assertEqual(3 + 5 + len(U_BOOT_DATA), entry.size)
        self.assertEqual(U_BOOT_DATA, entry.data)
        self.assertEqual(tools.GetBytes(0, 3) + U_BOOT_DATA +
                         tools.GetBytes(0, 5), data[:entry.size])
        pos = entry.size

        # Second u-boot has an aligned size, but it has no effect
        self.assertIn('u-boot-align-size-nop', entries)
        entry = entries['u-boot-align-size-nop']
        self.assertEqual(pos, entry.offset)
        self.assertEqual(len(U_BOOT_DATA), entry.size)
        self.assertEqual(U_BOOT_DATA, entry.data)
        self.assertEqual(U_BOOT_DATA, data[pos:pos + entry.size])
        pos += entry.size

        # Third u-boot has an aligned size too
        self.assertIn('u-boot-align-size', entries)
        entry = entries['u-boot-align-size']
        self.assertEqual(pos, entry.offset)
        self.assertEqual(32, entry.size)
        self.assertEqual(U_BOOT_DATA, entry.data)
        self.assertEqual(U_BOOT_DATA + tools.GetBytes(0, 32 - len(U_BOOT_DATA)),
                         data[pos:pos + entry.size])
        pos += entry.size

        # Fourth u-boot has an aligned end
        self.assertIn('u-boot-align-end', entries)
        entry = entries['u-boot-align-end']
        self.assertEqual(48, entry.offset)
        self.assertEqual(16, entry.size)
        self.assertEqual(U_BOOT_DATA, entry.data[:len(U_BOOT_DATA)])
        self.assertEqual(U_BOOT_DATA + tools.GetBytes(0, 16 - len(U_BOOT_DATA)),
                         data[pos:pos + entry.size])
        pos += entry.size

        # Fifth u-boot immediately afterwards
        self.assertIn('u-boot-align-both', entries)
        entry = entries['u-boot-align-both']
        self.assertEqual(64, entry.offset)
        self.assertEqual(64, entry.size)
        self.assertEqual(U_BOOT_DATA, entry.data[:len(U_BOOT_DATA)])
        self.assertEqual(U_BOOT_DATA + tools.GetBytes(0, 64 - len(U_BOOT_DATA)),
                         data[pos:pos + entry.size])

        self.CheckNoGaps(entries)
        self.assertEqual(128, image.size)

        dtb = fdt.Fdt(out_dtb_fname)
        dtb.Scan()
        props = self._GetPropTree(dtb, ['size', 'offset', 'image-pos'])
        expected = {
            'image-pos': 0,
            'offset': 0,
            'size': 128,

            'u-boot:image-pos': 0,
            'u-boot:offset': 0,
            'u-boot:size': 3 + 5 + len(U_BOOT_DATA),

            'u-boot-align-size-nop:image-pos': 12,
            'u-boot-align-size-nop:offset': 12,
            'u-boot-align-size-nop:size': 4,

            'u-boot-align-size:image-pos': 16,
            'u-boot-align-size:offset': 16,
            'u-boot-align-size:size': 32,

            'u-boot-align-end:image-pos': 48,
            'u-boot-align-end:offset': 48,
            'u-boot-align-end:size': 16,

            'u-boot-align-both:image-pos': 64,
            'u-boot-align-both:offset': 64,
            'u-boot-align-both:size': 64,
            }
        self.assertEqual(expected, props)

    def testPackAlignPowerOf2(self):
        """Test that invalid entry alignment is detected"""
        with self.assertRaises(ValueError) as e:
            self._DoTestFile('010_pack_align_power2.dts')
        self.assertIn("Node '/binman/u-boot': Alignment 5 must be a power "
                      "of two", str(e.exception))

    def testPackAlignSizePowerOf2(self):
        """Test that invalid entry size alignment is detected"""
        with self.assertRaises(ValueError) as e:
            self._DoTestFile('011_pack_align_size_power2.dts')
        self.assertIn("Node '/binman/u-boot': Alignment size 55 must be a "
                      "power of two", str(e.exception))

    def testPackInvalidAlign(self):
        """Test detection of an offset that does not match its alignment"""
        with self.assertRaises(ValueError) as e:
            self._DoTestFile('012_pack_inv_align.dts')
        self.assertIn("Node '/binman/u-boot': Offset 0x5 (5) does not match "
                      "align 0x4 (4)", str(e.exception))

    def testPackInvalidSizeAlign(self):
        """Test that invalid entry size alignment is detected"""
        with self.assertRaises(ValueError) as e:
            self._DoTestFile('013_pack_inv_size_align.dts')
        self.assertIn("Node '/binman/u-boot': Size 0x5 (5) does not match "
                      "align-size 0x4 (4)", str(e.exception))

    def testPackOverlap(self):
        """Test that overlapping regions are detected"""
        with self.assertRaises(ValueError) as e:
            self._DoTestFile('014_pack_overlap.dts')
        self.assertIn("Node '/binman/u-boot-align': Offset 0x3 (3) overlaps "
                      "with previous entry '/binman/u-boot' ending at 0x4 (4)",
                      str(e.exception))

    def testPackEntryOverflow(self):
        """Test that entries that overflow their size are detected"""
        with self.assertRaises(ValueError) as e:
            self._DoTestFile('015_pack_overflow.dts')
        self.assertIn("Node '/binman/u-boot': Entry contents size is 0x4 (4) "
                      "but entry size is 0x3 (3)", str(e.exception))

    def testPackImageOverflow(self):
        """Test that entries which overflow the image size are detected"""
        with self.assertRaises(ValueError) as e:
            self._DoTestFile('016_pack_image_overflow.dts')
        self.assertIn("Section '/binman': contents size 0x4 (4) exceeds section "
                      "size 0x3 (3)", str(e.exception))

    def testPackImageSize(self):
        """Test that the image size can be set"""
        retcode = self._DoTestFile('017_pack_image_size.dts')
        self.assertEqual(0, retcode)
        self.assertIn('image', control.images)
        image = control.images['image']
        self.assertEqual(7, image.size)

    def testPackImageSizeAlign(self):
        """Test that image size alignemnt works as expected"""
        retcode = self._DoTestFile('018_pack_image_align.dts')
        self.assertEqual(0, retcode)
        self.assertIn('image', control.images)
        image = control.images['image']
        self.assertEqual(16, image.size)

    def testPackInvalidImageAlign(self):
        """Test that invalid image alignment is detected"""
        with self.assertRaises(ValueError) as e:
            self._DoTestFile('019_pack_inv_image_align.dts')
        self.assertIn("Section '/binman': Size 0x7 (7) does not match "
                      "align-size 0x8 (8)", str(e.exception))

    def testPackAlignPowerOf2(self):
        """Test that invalid image alignment is detected"""
        with self.assertRaises(ValueError) as e:
            self._DoTestFile('020_pack_inv_image_align_power2.dts')
        self.assertIn("Image '/binman': Alignment size 131 must be a power of "
                      "two", str(e.exception))

    def testImagePadByte(self):
        """Test that the image pad byte can be specified"""
        self._SetupSplElf()
        data = self._DoReadFile('021_image_pad.dts')
        self.assertEqual(U_BOOT_SPL_DATA + tools.GetBytes(0xff, 1) +
                         U_BOOT_DATA, data)

    def testImageName(self):
        """Test that image files can be named"""
        retcode = self._DoTestFile('022_image_name.dts')
        self.assertEqual(0, retcode)
        image = control.images['image1']
        fname = tools.GetOutputFilename('test-name')
        self.assertTrue(os.path.exists(fname))

        image = control.images['image2']
        fname = tools.GetOutputFilename('test-name.xx')
        self.assertTrue(os.path.exists(fname))

    def testBlobFilename(self):
        """Test that generic blobs can be provided by filename"""
        data = self._DoReadFile('023_blob.dts')
        self.assertEqual(BLOB_DATA, data)

    def testPackSorted(self):
        """Test that entries can be sorted"""
        self._SetupSplElf()
        data = self._DoReadFile('024_sorted.dts')
        self.assertEqual(tools.GetBytes(0, 1) + U_BOOT_SPL_DATA +
                         tools.GetBytes(0, 2) + U_BOOT_DATA, data)

    def testPackZeroOffset(self):
        """Test that an entry at offset 0 is not given a new offset"""
        with self.assertRaises(ValueError) as e:
            self._DoTestFile('025_pack_zero_size.dts')
        self.assertIn("Node '/binman/u-boot-spl': Offset 0x0 (0) overlaps "
                      "with previous entry '/binman/u-boot' ending at 0x4 (4)",
                      str(e.exception))

    def testPackUbootDtb(self):
        """Test that a device tree can be added to U-Boot"""
        data = self._DoReadFile('026_pack_u_boot_dtb.dts')
        self.assertEqual(U_BOOT_NODTB_DATA + U_BOOT_DTB_DATA, data)

    def testPackX86RomNoSize(self):
        """Test that the end-at-4gb property requires a size property"""
        with self.assertRaises(ValueError) as e:
            self._DoTestFile('027_pack_4gb_no_size.dts')
        self.assertIn("Image '/binman': Section size must be provided when "
                      "using end-at-4gb", str(e.exception))

    def test4gbAndSkipAtStartTogether(self):
        """Test that the end-at-4gb and skip-at-size property can't be used
        together"""
        with self.assertRaises(ValueError) as e:
            self._DoTestFile('098_4gb_and_skip_at_start_together.dts')
        self.assertIn("Image '/binman': Provide either 'end-at-4gb' or "
                      "'skip-at-start'", str(e.exception))

    def testPackX86RomOutside(self):
        """Test that the end-at-4gb property checks for offset boundaries"""
        with self.assertRaises(ValueError) as e:
            self._DoTestFile('028_pack_4gb_outside.dts')
        self.assertIn("Node '/binman/u-boot': Offset 0x0 (0) size 0x4 (4) "
                      "is outside the section '/binman' starting at "
                      '0xffffffe0 (4294967264) of size 0x20 (32)',
                      str(e.exception))

    def testPackX86Rom(self):
        """Test that a basic x86 ROM can be created"""
        self._SetupSplElf()
        data = self._DoReadFile('029_x86_rom.dts')
        self.assertEqual(U_BOOT_DATA + tools.GetBytes(0, 3) + U_BOOT_SPL_DATA +
                         tools.GetBytes(0, 2), data)

    def testPackX86RomMeNoDesc(self):
        """Test that an invalid Intel descriptor entry is detected"""
        try:
            TestFunctional._MakeInputFile('descriptor-empty.bin', b'')
            with self.assertRaises(ValueError) as e:
                self._DoTestFile('163_x86_rom_me_empty.dts')
            self.assertIn("Node '/binman/intel-descriptor': Cannot find Intel Flash Descriptor (FD) signature",
                          str(e.exception))
        finally:
            self._SetupDescriptor()

    def testPackX86RomBadDesc(self):
        """Test that the Intel requires a descriptor entry"""
        with self.assertRaises(ValueError) as e:
            self._DoTestFile('030_x86_rom_me_no_desc.dts')
        self.assertIn("Node '/binman/intel-me': No offset set with "
                      "offset-unset: should another entry provide this correct "
                      "offset?", str(e.exception))

    def testPackX86RomMe(self):
        """Test that an x86 ROM with an ME region can be created"""
        data = self._DoReadFile('031_x86_rom_me.dts')
        expected_desc = tools.ReadFile(self.TestFile('descriptor.bin'))
        if data[:0x1000] != expected_desc:
            self.fail('Expected descriptor binary at start of image')
        self.assertEqual(ME_DATA, data[0x1000:0x1000 + len(ME_DATA)])

    def testPackVga(self):
        """Test that an image with a VGA binary can be created"""
        data = self._DoReadFile('032_intel_vga.dts')
        self.assertEqual(VGA_DATA, data[:len(VGA_DATA)])

    def testPackStart16(self):
        """Test that an image with an x86 start16 region can be created"""
        data = self._DoReadFile('033_x86_start16.dts')
        self.assertEqual(X86_START16_DATA, data[:len(X86_START16_DATA)])

    def testPackPowerpcMpc85xxBootpgResetvec(self):
        """Test that an image with powerpc-mpc85xx-bootpg-resetvec can be
        created"""
        data = self._DoReadFile('150_powerpc_mpc85xx_bootpg_resetvec.dts')
        self.assertEqual(PPC_MPC85XX_BR_DATA, data[:len(PPC_MPC85XX_BR_DATA)])

    def _RunMicrocodeTest(self, dts_fname, nodtb_data, ucode_second=False):
        """Handle running a test for insertion of microcode

        Args:
            dts_fname: Name of test .dts file
            nodtb_data: Data that we expect in the first section
            ucode_second: True if the microsecond entry is second instead of
                third

        Returns:
            Tuple:
                Contents of first region (U-Boot or SPL)
                Offset and size components of microcode pointer, as inserted
                    in the above (two 4-byte words)
        """
        data = self._DoReadFile(dts_fname, True)

        # Now check the device tree has no microcode
        if ucode_second:
            ucode_content = data[len(nodtb_data):]
            ucode_pos = len(nodtb_data)
            dtb_with_ucode = ucode_content[16:]
            fdt_len = self.GetFdtLen(dtb_with_ucode)
        else:
            dtb_with_ucode = data[len(nodtb_data):]
            fdt_len = self.GetFdtLen(dtb_with_ucode)
            ucode_content = dtb_with_ucode[fdt_len:]
            ucode_pos = len(nodtb_data) + fdt_len
        fname = tools.GetOutputFilename('test.dtb')
        with open(fname, 'wb') as fd:
            fd.write(dtb_with_ucode)
        dtb = fdt.FdtScan(fname)
        ucode = dtb.GetNode('/microcode')
        self.assertTrue(ucode)
        for node in ucode.subnodes:
            self.assertFalse(node.props.get('data'))

        # Check that the microcode appears immediately after the Fdt
        # This matches the concatenation of the data properties in
        # the /microcode/update@xxx nodes in 34_x86_ucode.dts.
        ucode_data = struct.pack('>4L', 0x12345678, 0x12345679, 0xabcd0000,
                                 0x78235609)
        self.assertEqual(ucode_data, ucode_content[:len(ucode_data)])

        # Check that the microcode pointer was inserted. It should match the
        # expected offset and size
        pos_and_size = struct.pack('<2L', 0xfffffe00 + ucode_pos,
                                   len(ucode_data))
        u_boot = data[:len(nodtb_data)]
        return u_boot, pos_and_size

    def testPackUbootMicrocode(self):
        """Test that x86 microcode can be handled correctly

        We expect to see the following in the image, in order:
            u-boot-nodtb.bin with a microcode pointer inserted at the correct
                place
            u-boot.dtb with the microcode removed
            the microcode
        """
        first, pos_and_size = self._RunMicrocodeTest('034_x86_ucode.dts',
                                                     U_BOOT_NODTB_DATA)
        self.assertEqual(b'nodtb with microcode' + pos_and_size +
                         b' somewhere in here', first)

    def _RunPackUbootSingleMicrocode(self):
        """Test that x86 microcode can be handled correctly

        We expect to see the following in the image, in order:
            u-boot-nodtb.bin with a microcode pointer inserted at the correct
                place
            u-boot.dtb with the microcode
            an empty microcode region
        """
        # We need the libfdt library to run this test since only that allows
        # finding the offset of a property. This is required by
        # Entry_u_boot_dtb_with_ucode.ObtainContents().
        data = self._DoReadFile('035_x86_single_ucode.dts', True)

        second = data[len(U_BOOT_NODTB_DATA):]

        fdt_len = self.GetFdtLen(second)
        third = second[fdt_len:]
        second = second[:fdt_len]

        ucode_data = struct.pack('>2L', 0x12345678, 0x12345679)
        self.assertIn(ucode_data, second)
        ucode_pos = second.find(ucode_data) + len(U_BOOT_NODTB_DATA)

        # Check that the microcode pointer was inserted. It should match the
        # expected offset and size
        pos_and_size = struct.pack('<2L', 0xfffffe00 + ucode_pos,
                                   len(ucode_data))
        first = data[:len(U_BOOT_NODTB_DATA)]
        self.assertEqual(b'nodtb with microcode' + pos_and_size +
                         b' somewhere in here', first)

    def testPackUbootSingleMicrocode(self):
        """Test that x86 microcode can be handled correctly with fdt_normal.
        """
        self._RunPackUbootSingleMicrocode()

    def testUBootImg(self):
        """Test that u-boot.img can be put in a file"""
        data = self._DoReadFile('036_u_boot_img.dts')
        self.assertEqual(U_BOOT_IMG_DATA, data)

    def testNoMicrocode(self):
        """Test that a missing microcode region is detected"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('037_x86_no_ucode.dts', True)
        self.assertIn("Node '/binman/u-boot-dtb-with-ucode': No /microcode "
                      "node found in ", str(e.exception))

    def testMicrocodeWithoutNode(self):
        """Test that a missing u-boot-dtb-with-ucode node is detected"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('038_x86_ucode_missing_node.dts', True)
        self.assertIn("Node '/binman/u-boot-with-ucode-ptr': Cannot find "
                "microcode region u-boot-dtb-with-ucode", str(e.exception))

    def testMicrocodeWithoutNode2(self):
        """Test that a missing u-boot-ucode node is detected"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('039_x86_ucode_missing_node2.dts', True)
        self.assertIn("Node '/binman/u-boot-with-ucode-ptr': Cannot find "
            "microcode region u-boot-ucode", str(e.exception))

    def testMicrocodeWithoutPtrInElf(self):
        """Test that a U-Boot binary without the microcode symbol is detected"""
        # ELF file without a '_dt_ucode_base_size' symbol
        try:
            TestFunctional._MakeInputFile('u-boot',
                tools.ReadFile(self.ElfTestFile('u_boot_no_ucode_ptr')))

            with self.assertRaises(ValueError) as e:
                self._RunPackUbootSingleMicrocode()
            self.assertIn("Node '/binman/u-boot-with-ucode-ptr': Cannot locate "
                    "_dt_ucode_base_size symbol in u-boot", str(e.exception))

        finally:
            # Put the original file back
            TestFunctional._MakeInputFile('u-boot',
                tools.ReadFile(self.ElfTestFile('u_boot_ucode_ptr')))

    def testMicrocodeNotInImage(self):
        """Test that microcode must be placed within the image"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('040_x86_ucode_not_in_image.dts', True)
        self.assertIn("Node '/binman/u-boot-with-ucode-ptr': Microcode "
                "pointer _dt_ucode_base_size at fffffe14 is outside the "
                "section ranging from 00000000 to 0000002e", str(e.exception))

    def testWithoutMicrocode(self):
        """Test that we can cope with an image without microcode (e.g. qemu)"""
        TestFunctional._MakeInputFile('u-boot',
            tools.ReadFile(self.ElfTestFile('u_boot_no_ucode_ptr')))
        data, dtb, _, _ = self._DoReadFileDtb('044_x86_optional_ucode.dts', True)

        # Now check the device tree has no microcode
        self.assertEqual(U_BOOT_NODTB_DATA, data[:len(U_BOOT_NODTB_DATA)])
        second = data[len(U_BOOT_NODTB_DATA):]

        fdt_len = self.GetFdtLen(second)
        self.assertEqual(dtb, second[:fdt_len])

        used_len = len(U_BOOT_NODTB_DATA) + fdt_len
        third = data[used_len:]
        self.assertEqual(tools.GetBytes(0, 0x200 - used_len), third)

    def testUnknownPosSize(self):
        """Test that microcode must be placed within the image"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('041_unknown_pos_size.dts', True)
        self.assertIn("Section '/binman': Unable to set offset/size for unknown "
                "entry 'invalid-entry'", str(e.exception))

    def testPackFsp(self):
        """Test that an image with a FSP binary can be created"""
        data = self._DoReadFile('042_intel_fsp.dts')
        self.assertEqual(FSP_DATA, data[:len(FSP_DATA)])

    def testPackCmc(self):
        """Test that an image with a CMC binary can be created"""
        data = self._DoReadFile('043_intel_cmc.dts')
        self.assertEqual(CMC_DATA, data[:len(CMC_DATA)])

    def testPackVbt(self):
        """Test that an image with a VBT binary can be created"""
        data = self._DoReadFile('046_intel_vbt.dts')
        self.assertEqual(VBT_DATA, data[:len(VBT_DATA)])

    def testSplBssPad(self):
        """Test that we can pad SPL's BSS with zeros"""
        # ELF file with a '__bss_size' symbol
        self._SetupSplElf()
        data = self._DoReadFile('047_spl_bss_pad.dts')
        self.assertEqual(U_BOOT_SPL_DATA + tools.GetBytes(0, 10) + U_BOOT_DATA,
                         data)

    def testSplBssPadMissing(self):
        """Test that a missing symbol is detected"""
        self._SetupSplElf('u_boot_ucode_ptr')
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('047_spl_bss_pad.dts')
        self.assertIn('Expected __bss_size symbol in spl/u-boot-spl',
                      str(e.exception))

    def testPackStart16Spl(self):
        """Test that an image with an x86 start16 SPL region can be created"""
        data = self._DoReadFile('048_x86_start16_spl.dts')
        self.assertEqual(X86_START16_SPL_DATA, data[:len(X86_START16_SPL_DATA)])

    def _PackUbootSplMicrocode(self, dts, ucode_second=False):
        """Helper function for microcode tests

        We expect to see the following in the image, in order:
            u-boot-spl-nodtb.bin with a microcode pointer inserted at the
                correct place
            u-boot.dtb with the microcode removed
            the microcode

        Args:
            dts: Device tree file to use for test
            ucode_second: True if the microsecond entry is second instead of
                third
        """
        self._SetupSplElf('u_boot_ucode_ptr')
        first, pos_and_size = self._RunMicrocodeTest(dts, U_BOOT_SPL_NODTB_DATA,
                                                     ucode_second=ucode_second)
        self.assertEqual(b'splnodtb with microc' + pos_and_size +
                         b'ter somewhere in here', first)

    def testPackUbootSplMicrocode(self):
        """Test that x86 microcode can be handled correctly in SPL"""
        self._PackUbootSplMicrocode('049_x86_ucode_spl.dts')

    def testPackUbootSplMicrocodeReorder(self):
        """Test that order doesn't matter for microcode entries

        This is the same as testPackUbootSplMicrocode but when we process the
        u-boot-ucode entry we have not yet seen the u-boot-dtb-with-ucode
        entry, so we reply on binman to try later.
        """
        self._PackUbootSplMicrocode('058_x86_ucode_spl_needs_retry.dts',
                                    ucode_second=True)

    def testPackMrc(self):
        """Test that an image with an MRC binary can be created"""
        data = self._DoReadFile('050_intel_mrc.dts')
        self.assertEqual(MRC_DATA, data[:len(MRC_DATA)])

    def testSplDtb(self):
        """Test that an image with spl/u-boot-spl.dtb can be created"""
        data = self._DoReadFile('051_u_boot_spl_dtb.dts')
        self.assertEqual(U_BOOT_SPL_DTB_DATA, data[:len(U_BOOT_SPL_DTB_DATA)])

    def testSplNoDtb(self):
        """Test that an image with spl/u-boot-spl-nodtb.bin can be created"""
        self._SetupSplElf()
        data = self._DoReadFile('052_u_boot_spl_nodtb.dts')
        self.assertEqual(U_BOOT_SPL_NODTB_DATA, data[:len(U_BOOT_SPL_NODTB_DATA)])

    def checkSymbols(self, dts, base_data, u_boot_offset, entry_args=None,
                     use_expanded=False):
        """Check the image contains the expected symbol values

        Args:
            dts: Device tree file to use for test
            base_data: Data before and after 'u-boot' section
            u_boot_offset: Offset of 'u-boot' section in image
            entry_args: Dict of entry args to supply to binman
                key: arg name
                value: value of that arg
            use_expanded: True to use expanded entries where available, e.g.
                'u-boot-expanded' instead of 'u-boot'
        """
        elf_fname = self.ElfTestFile('u_boot_binman_syms')
        syms = elf.GetSymbols(elf_fname, ['binman', 'image'])
        addr = elf.GetSymbolAddress(elf_fname, '__image_copy_start')
        self.assertEqual(syms['_binman_u_boot_spl_any_prop_offset'].address,
                         addr)

        self._SetupSplElf('u_boot_binman_syms')
        data = self._DoReadFileDtb(dts, entry_args=entry_args,
                                   use_expanded=use_expanded)[0]
        # The image should contain the symbols from u_boot_binman_syms.c
        # Note that image_pos is adjusted by the base address of the image,
        # which is 0x10 in our test image
        sym_values = struct.pack('<LQLL', 0x00,
                                 u_boot_offset + len(U_BOOT_DATA),
                                 0x10 + u_boot_offset, 0x04)
        expected = (sym_values + base_data[20:] +
                    tools.GetBytes(0xff, 1) + U_BOOT_DATA + sym_values +
                    base_data[20:])
        self.assertEqual(expected, data)

    def testSymbols(self):
        """Test binman can assign symbols embedded in U-Boot"""
        self.checkSymbols('053_symbols.dts', U_BOOT_SPL_DATA, 0x18)

    def testSymbolsNoDtb(self):
        """Test binman can assign symbols embedded in U-Boot SPL"""
        self.checkSymbols('196_symbols_nodtb.dts',
                          U_BOOT_SPL_NODTB_DATA + U_BOOT_SPL_DTB_DATA,
                          0x38)

    def testPackUnitAddress(self):
        """Test that we support multiple binaries with the same name"""
        data = self._DoReadFile('054_unit_address.dts')
        self.assertEqual(U_BOOT_DATA + U_BOOT_DATA, data)

    def testSections(self):
        """Basic test of sections"""
        data = self._DoReadFile('055_sections.dts')
        expected = (U_BOOT_DATA + tools.GetBytes(ord('!'), 12) +
                    U_BOOT_DATA + tools.GetBytes(ord('a'), 12) +
                    U_BOOT_DATA + tools.GetBytes(ord('&'), 4))
        self.assertEqual(expected, data)

    def testMap(self):
        """Tests outputting a map of the images"""
        _, _, map_data, _ = self._DoReadFileDtb('055_sections.dts', map=True)
        self.assertEqual('''ImagePos    Offset      Size  Name
00000000  00000000  00000028  main-section
00000000   00000000  00000010  section@0
00000000    00000000  00000004  u-boot
00000010   00000010  00000010  section@1
00000010    00000000  00000004  u-boot
00000020   00000020  00000004  section@2
00000020    00000000  00000004  u-boot
''', map_data)

    def testNamePrefix(self):
        """Tests that name prefixes are used"""
        _, _, map_data, _ = self._DoReadFileDtb('056_name_prefix.dts', map=True)
        self.assertEqual('''ImagePos    Offset      Size  Name
00000000  00000000  00000028  main-section
00000000   00000000  00000010  section@0
00000000    00000000  00000004  ro-u-boot
00000010   00000010  00000010  section@1
00000010    00000000  00000004  rw-u-boot
''', map_data)

    def testUnknownContents(self):
        """Test that obtaining the contents works as expected"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('057_unknown_contents.dts', True)
        self.assertIn("Image '/binman': Internal error: Could not complete "
                "processing of contents: remaining ["
                "<binman.etype._testing.Entry__testing ", str(e.exception))

    def testBadChangeSize(self):
        """Test that trying to change the size of an entry fails"""
        try:
            state.SetAllowEntryExpansion(False)
            with self.assertRaises(ValueError) as e:
                self._DoReadFile('059_change_size.dts', True)
            self.assertIn("Node '/binman/_testing': Cannot update entry size from 2 to 3",
                          str(e.exception))
        finally:
            state.SetAllowEntryExpansion(True)

    def testUpdateFdt(self):
        """Test that we can update the device tree with offset/size info"""
        _, _, _, out_dtb_fname = self._DoReadFileDtb('060_fdt_update.dts',
                                                     update_dtb=True)
        dtb = fdt.Fdt(out_dtb_fname)
        dtb.Scan()
        props = self._GetPropTree(dtb, BASE_DTB_PROPS + REPACK_DTB_PROPS)
        self.assertEqual({
            'image-pos': 0,
            'offset': 0,
            '_testing:offset': 32,
            '_testing:size': 2,
            '_testing:image-pos': 32,
            'section@0/u-boot:offset': 0,
            'section@0/u-boot:size': len(U_BOOT_DATA),
            'section@0/u-boot:image-pos': 0,
            'section@0:offset': 0,
            'section@0:size': 16,
            'section@0:image-pos': 0,

            'section@1/u-boot:offset': 0,
            'section@1/u-boot:size': len(U_BOOT_DATA),
            'section@1/u-boot:image-pos': 16,
            'section@1:offset': 16,
            'section@1:size': 16,
            'section@1:image-pos': 16,
            'size': 40
        }, props)

    def testUpdateFdtBad(self):
        """Test that we detect when ProcessFdt never completes"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFileDtb('061_fdt_update_bad.dts', update_dtb=True)
        self.assertIn('Could not complete processing of Fdt: remaining '
                      '[<binman.etype._testing.Entry__testing',
                        str(e.exception))

    def testEntryArgs(self):
        """Test passing arguments to entries from the command line"""
        entry_args = {
            'test-str-arg': 'test1',
            'test-int-arg': '456',
        }
        self._DoReadFileDtb('062_entry_args.dts', entry_args=entry_args)
        self.assertIn('image', control.images)
        entry = control.images['image'].GetEntries()['_testing']
        self.assertEqual('test0', entry.test_str_fdt)
        self.assertEqual('test1', entry.test_str_arg)
        self.assertEqual(123, entry.test_int_fdt)
        self.assertEqual(456, entry.test_int_arg)

    def testEntryArgsMissing(self):
        """Test missing arguments and properties"""
        entry_args = {
            'test-int-arg': '456',
        }
        self._DoReadFileDtb('063_entry_args_missing.dts', entry_args=entry_args)
        entry = control.images['image'].GetEntries()['_testing']
        self.assertEqual('test0', entry.test_str_fdt)
        self.assertEqual(None, entry.test_str_arg)
        self.assertEqual(None, entry.test_int_fdt)
        self.assertEqual(456, entry.test_int_arg)

    def testEntryArgsRequired(self):
        """Test missing arguments and properties"""
        entry_args = {
            'test-int-arg': '456',
        }
        with self.assertRaises(ValueError) as e:
            self._DoReadFileDtb('064_entry_args_required.dts')
        self.assertIn("Node '/binman/_testing': "
            'Missing required properties/entry args: test-str-arg, '
            'test-int-fdt, test-int-arg',
            str(e.exception))

    def testEntryArgsInvalidFormat(self):
        """Test that an invalid entry-argument format is detected"""
        args = ['build', '-d', self.TestFile('064_entry_args_required.dts'),
                '-ano-value']
        with self.assertRaises(ValueError) as e:
            self._DoBinman(*args)
        self.assertIn("Invalid entry arguemnt 'no-value'", str(e.exception))

    def testEntryArgsInvalidInteger(self):
        """Test that an invalid entry-argument integer is detected"""
        entry_args = {
            'test-int-arg': 'abc',
        }
        with self.assertRaises(ValueError) as e:
            self._DoReadFileDtb('062_entry_args.dts', entry_args=entry_args)
        self.assertIn("Node '/binman/_testing': Cannot convert entry arg "
                      "'test-int-arg' (value 'abc') to integer",
            str(e.exception))

    def testEntryArgsInvalidDatatype(self):
        """Test that an invalid entry-argument datatype is detected

        This test could be written in entry_test.py except that it needs
        access to control.entry_args, which seems more than that module should
        be able to see.
        """
        entry_args = {
            'test-bad-datatype-arg': '12',
        }
        with self.assertRaises(ValueError) as e:
            self._DoReadFileDtb('065_entry_args_unknown_datatype.dts',
                                entry_args=entry_args)
        self.assertIn('GetArg() internal error: Unknown data type ',
                      str(e.exception))

    def testText(self):
        """Test for a text entry type"""
        entry_args = {
            'test-id': TEXT_DATA,
            'test-id2': TEXT_DATA2,
            'test-id3': TEXT_DATA3,
        }
        data, _, _, _ = self._DoReadFileDtb('066_text.dts',
                                            entry_args=entry_args)
        expected = (tools.ToBytes(TEXT_DATA) +
                    tools.GetBytes(0, 8 - len(TEXT_DATA)) +
                    tools.ToBytes(TEXT_DATA2) + tools.ToBytes(TEXT_DATA3) +
                    b'some text' + b'more text')
        self.assertEqual(expected, data)

    def testEntryDocs(self):
        """Test for creation of entry documentation"""
        with test_util.capture_sys_output() as (stdout, stderr):
            control.WriteEntryDocs(control.GetEntryModules())
        self.assertTrue(len(stdout.getvalue()) > 0)

    def testEntryDocsMissing(self):
        """Test handling of missing entry documentation"""
        with self.assertRaises(ValueError) as e:
            with test_util.capture_sys_output() as (stdout, stderr):
                control.WriteEntryDocs(control.GetEntryModules(), 'u_boot')
        self.assertIn('Documentation is missing for modules: u_boot',
                      str(e.exception))

    def testFmap(self):
        """Basic test of generation of a flashrom fmap"""
        data = self._DoReadFile('067_fmap.dts')
        fhdr, fentries = fmap_util.DecodeFmap(data[32:])
        expected = (U_BOOT_DATA + tools.GetBytes(ord('!'), 12) +
                    U_BOOT_DATA + tools.GetBytes(ord('a'), 12))
        self.assertEqual(expected, data[:32])
        self.assertEqual(b'__FMAP__', fhdr.signature)
        self.assertEqual(1, fhdr.ver_major)
        self.assertEqual(0, fhdr.ver_minor)
        self.assertEqual(0, fhdr.base)
        expect_size = fmap_util.FMAP_HEADER_LEN + fmap_util.FMAP_AREA_LEN * 5
        self.assertEqual(16 + 16 + expect_size, fhdr.image_size)
        self.assertEqual(b'FMAP', fhdr.name)
        self.assertEqual(5, fhdr.nareas)
        fiter = iter(fentries)

        fentry = next(fiter)
        self.assertEqual(b'SECTION0', fentry.name)
        self.assertEqual(0, fentry.offset)
        self.assertEqual(16, fentry.size)
        self.assertEqual(0, fentry.flags)

        fentry = next(fiter)
        self.assertEqual(b'RO_U_BOOT', fentry.name)
        self.assertEqual(0, fentry.offset)
        self.assertEqual(4, fentry.size)
        self.assertEqual(0, fentry.flags)

        fentry = next(fiter)
        self.assertEqual(b'SECTION1', fentry.name)
        self.assertEqual(16, fentry.offset)
        self.assertEqual(16, fentry.size)
        self.assertEqual(0, fentry.flags)

        fentry = next(fiter)
        self.assertEqual(b'RW_U_BOOT', fentry.name)
        self.assertEqual(16, fentry.offset)
        self.assertEqual(4, fentry.size)
        self.assertEqual(0, fentry.flags)

        fentry = next(fiter)
        self.assertEqual(b'FMAP', fentry.name)
        self.assertEqual(32, fentry.offset)
        self.assertEqual(expect_size, fentry.size)
        self.assertEqual(0, fentry.flags)

    def testBlobNamedByArg(self):
        """Test we can add a blob with the filename coming from an entry arg"""
        entry_args = {
            'cros-ec-rw-path': 'ecrw.bin',
        }
        self._DoReadFileDtb('068_blob_named_by_arg.dts', entry_args=entry_args)

    def testFill(self):
        """Test for an fill entry type"""
        data = self._DoReadFile('069_fill.dts')
        expected = tools.GetBytes(0xff, 8) + tools.GetBytes(0, 8)
        self.assertEqual(expected, data)

    def testFillNoSize(self):
        """Test for an fill entry type with no size"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('070_fill_no_size.dts')
        self.assertIn("'fill' entry must have a size property",
                      str(e.exception))

    def _HandleGbbCommand(self, pipe_list):
        """Fake calls to the futility utility"""
        if pipe_list[0][0] == 'futility':
            fname = pipe_list[0][-1]
            # Append our GBB data to the file, which will happen every time the
            # futility command is called.
            with open(fname, 'ab') as fd:
                fd.write(GBB_DATA)
            return command.CommandResult()

    def testGbb(self):
        """Test for the Chromium OS Google Binary Block"""
        command.test_result = self._HandleGbbCommand
        entry_args = {
            'keydir': 'devkeys',
            'bmpblk': 'bmpblk.bin',
        }
        data, _, _, _ = self._DoReadFileDtb('071_gbb.dts', entry_args=entry_args)

        # Since futility
        expected = (GBB_DATA + GBB_DATA + tools.GetBytes(0, 8) +
                    tools.GetBytes(0, 0x2180 - 16))
        self.assertEqual(expected, data)

    def testGbbTooSmall(self):
        """Test for the Chromium OS Google Binary Block being large enough"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFileDtb('072_gbb_too_small.dts')
        self.assertIn("Node '/binman/gbb': GBB is too small",
                      str(e.exception))

    def testGbbNoSize(self):
        """Test for the Chromium OS Google Binary Block having a size"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFileDtb('073_gbb_no_size.dts')
        self.assertIn("Node '/binman/gbb': GBB must have a fixed size",
                      str(e.exception))

    def _HandleVblockCommand(self, pipe_list):
        """Fake calls to the futility utility

        The expected pipe is:

           [('futility', 'vbutil_firmware', '--vblock',
             'vblock.vblock', '--keyblock', 'devkeys/firmware.keyblock',
             '--signprivate', 'devkeys/firmware_data_key.vbprivk',
             '--version', '1', '--fv', 'input.vblock', '--kernelkey',
             'devkeys/kernel_subkey.vbpubk', '--flags', '1')]

        This writes to the output file (here, 'vblock.vblock'). If
        self._hash_data is False, it writes VBLOCK_DATA, else it writes a hash
        of the input data (here, 'input.vblock').
        """
        if pipe_list[0][0] == 'futility':
            fname = pipe_list[0][3]
            with open(fname, 'wb') as fd:
                if self._hash_data:
                    infile = pipe_list[0][11]
                    m = hashlib.sha256()
                    data = tools.ReadFile(infile)
                    m.update(data)
                    fd.write(m.digest())
                else:
                    fd.write(VBLOCK_DATA)

            return command.CommandResult()

    def testVblock(self):
        """Test for the Chromium OS Verified Boot Block"""
        self._hash_data = False
        command.test_result = self._HandleVblockCommand
        entry_args = {
            'keydir': 'devkeys',
        }
        data, _, _, _ = self._DoReadFileDtb('074_vblock.dts',
                                            entry_args=entry_args)
        expected = U_BOOT_DATA + VBLOCK_DATA + U_BOOT_DTB_DATA
        self.assertEqual(expected, data)

    def testVblockNoContent(self):
        """Test we detect a vblock which has no content to sign"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('075_vblock_no_content.dts')
        self.assertIn("Node '/binman/vblock': Collection must have a 'content' "
                      'property', str(e.exception))

    def testVblockBadPhandle(self):
        """Test that we detect a vblock with an invalid phandle in contents"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('076_vblock_bad_phandle.dts')
        self.assertIn("Node '/binman/vblock': Cannot find node for phandle "
                      '1000', str(e.exception))

    def testVblockBadEntry(self):
        """Test that we detect an entry that points to a non-entry"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('077_vblock_bad_entry.dts')
        self.assertIn("Node '/binman/vblock': Cannot find entry for node "
                      "'other'", str(e.exception))

    def testVblockContent(self):
        """Test that the vblock signs the right data"""
        self._hash_data = True
        command.test_result = self._HandleVblockCommand
        entry_args = {
            'keydir': 'devkeys',
        }
        data = self._DoReadFileDtb(
            '189_vblock_content.dts', use_real_dtb=True, update_dtb=True,
            entry_args=entry_args)[0]
        hashlen = 32  # SHA256 hash is 32 bytes
        self.assertEqual(U_BOOT_DATA, data[:len(U_BOOT_DATA)])
        hashval = data[-hashlen:]
        dtb = data[len(U_BOOT_DATA):-hashlen]

        expected_data = U_BOOT_DATA + dtb

        # The hashval should be a hash of the dtb
        m = hashlib.sha256()
        m.update(expected_data)
        expected_hashval = m.digest()
        self.assertEqual(expected_hashval, hashval)

    def testTpl(self):
        """Test that an image with TPL and its device tree can be created"""
        # ELF file with a '__bss_size' symbol
        self._SetupTplElf()
        data = self._DoReadFile('078_u_boot_tpl.dts')
        self.assertEqual(U_BOOT_TPL_DATA + U_BOOT_TPL_DTB_DATA, data)

    def testUsesPos(self):
        """Test that the 'pos' property cannot be used anymore"""
        with self.assertRaises(ValueError) as e:
           data = self._DoReadFile('079_uses_pos.dts')
        self.assertIn("Node '/binman/u-boot': Please use 'offset' instead of "
                      "'pos'", str(e.exception))

    def testFillZero(self):
        """Test for an fill entry type with a size of 0"""
        data = self._DoReadFile('080_fill_empty.dts')
        self.assertEqual(tools.GetBytes(0, 16), data)

    def testTextMissing(self):
        """Test for a text entry type where there is no text"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFileDtb('066_text.dts',)
        self.assertIn("Node '/binman/text': No value provided for text label "
                      "'test-id'", str(e.exception))

    def testPackStart16Tpl(self):
        """Test that an image with an x86 start16 TPL region can be created"""
        data = self._DoReadFile('081_x86_start16_tpl.dts')
        self.assertEqual(X86_START16_TPL_DATA, data[:len(X86_START16_TPL_DATA)])

    def testSelectImage(self):
        """Test that we can select which images to build"""
        expected = 'Skipping images: image1'

        # We should only get the expected message in verbose mode
        for verbosity in (0, 2):
            with test_util.capture_sys_output() as (stdout, stderr):
                retcode = self._DoTestFile('006_dual_image.dts',
                                           verbosity=verbosity,
                                           images=['image2'])
            self.assertEqual(0, retcode)
            if verbosity:
                self.assertIn(expected, stdout.getvalue())
            else:
                self.assertNotIn(expected, stdout.getvalue())

            self.assertFalse(os.path.exists(tools.GetOutputFilename('image1.bin')))
            self.assertTrue(os.path.exists(tools.GetOutputFilename('image2.bin')))
            self._CleanupOutputDir()

    def testUpdateFdtAll(self):
        """Test that all device trees are updated with offset/size info"""
        data = self._DoReadFileRealDtb('082_fdt_update_all.dts')

        base_expected = {
            'section:image-pos': 0,
            'u-boot-tpl-dtb:size': 513,
            'u-boot-spl-dtb:size': 513,
            'u-boot-spl-dtb:offset': 493,
            'image-pos': 0,
            'section/u-boot-dtb:image-pos': 0,
            'u-boot-spl-dtb:image-pos': 493,
            'section/u-boot-dtb:size': 493,
            'u-boot-tpl-dtb:image-pos': 1006,
            'section/u-boot-dtb:offset': 0,
            'section:size': 493,
            'offset': 0,
            'section:offset': 0,
            'u-boot-tpl-dtb:offset': 1006,
            'size': 1519
        }

        # We expect three device-tree files in the output, one after the other.
        # Read them in sequence. We look for an 'spl' property in the SPL tree,
        # and 'tpl' in the TPL tree, to make sure they are distinct from the
        # main U-Boot tree. All three should have the same postions and offset.
        start = 0
        for item in ['', 'spl', 'tpl']:
            dtb = fdt.Fdt.FromData(data[start:])
            dtb.Scan()
            props = self._GetPropTree(dtb, BASE_DTB_PROPS + REPACK_DTB_PROPS +
                                      ['spl', 'tpl'])
            expected = dict(base_expected)
            if item:
                expected[item] = 0
            self.assertEqual(expected, props)
            start += dtb._fdt_obj.totalsize()

    def testUpdateFdtOutput(self):
        """Test that output DTB files are updated"""
        try:
            data, dtb_data, _, _ = self._DoReadFileDtb('082_fdt_update_all.dts',
                    use_real_dtb=True, update_dtb=True, reset_dtbs=False)

            # Unfortunately, compiling a source file always results in a file
            # called source.dtb (see fdt_util.EnsureCompiled()). The test
            # source file (e.g. test/075_fdt_update_all.dts) thus does not enter
            # binman as a file called u-boot.dtb. To fix this, copy the file
            # over to the expected place.
            start = 0
            for fname in ['u-boot.dtb.out', 'spl/u-boot-spl.dtb.out',
                          'tpl/u-boot-tpl.dtb.out']:
                dtb = fdt.Fdt.FromData(data[start:])
                size = dtb._fdt_obj.totalsize()
                pathname = tools.GetOutputFilename(os.path.split(fname)[1])
                outdata = tools.ReadFile(pathname)
                name = os.path.split(fname)[0]

                if name:
                    orig_indata = self._GetDtbContentsForSplTpl(dtb_data, name)
                else:
                    orig_indata = dtb_data
                self.assertNotEqual(outdata, orig_indata,
                        "Expected output file '%s' be updated" % pathname)
                self.assertEqual(outdata, data[start:start + size],
                        "Expected output file '%s' to match output image" %
                        pathname)
                start += size
        finally:
            self._ResetDtbs()

    def _decompress(self, data):
        return tools.Decompress(data, 'lz4')

    def testCompress(self):
        """Test compression of blobs"""
        self._CheckLz4()
        data, _, _, out_dtb_fname = self._DoReadFileDtb('083_compress.dts',
                                            use_real_dtb=True, update_dtb=True)
        dtb = fdt.Fdt(out_dtb_fname)
        dtb.Scan()
        props = self._GetPropTree(dtb, ['size', 'uncomp-size'])
        orig = self._decompress(data)
        self.assertEquals(COMPRESS_DATA, orig)

        # Do a sanity check on various fields
        image = control.images['image']
        entries = image.GetEntries()
        self.assertEqual(1, len(entries))

        entry = entries['blob']
        self.assertEqual(COMPRESS_DATA, entry.uncomp_data)
        self.assertEqual(len(COMPRESS_DATA), entry.uncomp_size)
        orig = self._decompress(entry.data)
        self.assertEqual(orig, entry.uncomp_data)

        self.assertEqual(image.data, entry.data)

        expected = {
            'blob:uncomp-size': len(COMPRESS_DATA),
            'blob:size': len(data),
            'size': len(data),
            }
        self.assertEqual(expected, props)

    def testFiles(self):
        """Test bringing in multiple files"""
        data = self._DoReadFile('084_files.dts')
        self.assertEqual(FILES_DATA, data)

    def testFilesCompress(self):
        """Test bringing in multiple files and compressing them"""
        self._CheckLz4()
        data = self._DoReadFile('085_files_compress.dts')

        image = control.images['image']
        entries = image.GetEntries()
        files = entries['files']
        entries = files._entries

        orig = b''
        for i in range(1, 3):
            key = '%d.dat' % i
            start = entries[key].image_pos
            len = entries[key].size
            chunk = data[start:start + len]
            orig += self._decompress(chunk)

        self.assertEqual(FILES_DATA, orig)

    def testFilesMissing(self):
        """Test missing files"""
        with self.assertRaises(ValueError) as e:
            data = self._DoReadFile('086_files_none.dts')
        self.assertIn("Node '/binman/files': Pattern \'files/*.none\' matched "
                      'no files', str(e.exception))

    def testFilesNoPattern(self):
        """Test missing files"""
        with self.assertRaises(ValueError) as e:
            data = self._DoReadFile('087_files_no_pattern.dts')
        self.assertIn("Node '/binman/files': Missing 'pattern' property",
                      str(e.exception))

    def testExpandSize(self):
        """Test an expanding entry"""
        data, _, map_data, _ = self._DoReadFileDtb('088_expand_size.dts',
                                                   map=True)
        expect = (tools.GetBytes(ord('a'), 8) + U_BOOT_DATA +
                  MRC_DATA + tools.GetBytes(ord('b'), 1) + U_BOOT_DATA +
                  tools.GetBytes(ord('c'), 8) + U_BOOT_DATA +
                  tools.GetBytes(ord('d'), 8))
        self.assertEqual(expect, data)
        self.assertEqual('''ImagePos    Offset      Size  Name
00000000  00000000  00000028  main-section
00000000   00000000  00000008  fill
00000008   00000008  00000004  u-boot
0000000c   0000000c  00000004  section
0000000c    00000000  00000003  intel-mrc
00000010   00000010  00000004  u-boot2
00000014   00000014  0000000c  section2
00000014    00000000  00000008  fill
0000001c    00000008  00000004  u-boot
00000020   00000020  00000008  fill2
''', map_data)

    def testExpandSizeBad(self):
        """Test an expanding entry which fails to provide contents"""
        with test_util.capture_sys_output() as (stdout, stderr):
            with self.assertRaises(ValueError) as e:
                self._DoReadFileDtb('089_expand_size_bad.dts', map=True)
        self.assertIn("Node '/binman/_testing': Cannot obtain contents when "
                      'expanding entry', str(e.exception))

    def testHash(self):
        """Test hashing of the contents of an entry"""
        _, _, _, out_dtb_fname = self._DoReadFileDtb('090_hash.dts',
                use_real_dtb=True, update_dtb=True)
        dtb = fdt.Fdt(out_dtb_fname)
        dtb.Scan()
        hash_node = dtb.GetNode('/binman/u-boot/hash').props['value']
        m = hashlib.sha256()
        m.update(U_BOOT_DATA)
        self.assertEqual(m.digest(), b''.join(hash_node.value))

    def testHashNoAlgo(self):
        with self.assertRaises(ValueError) as e:
            self._DoReadFileDtb('091_hash_no_algo.dts', update_dtb=True)
        self.assertIn("Node \'/binman/u-boot\': Missing \'algo\' property for "
                      'hash node', str(e.exception))

    def testHashBadAlgo(self):
        with self.assertRaises(ValueError) as e:
            self._DoReadFileDtb('092_hash_bad_algo.dts', update_dtb=True)
        self.assertIn("Node '/binman/u-boot': Unknown hash algorithm",
                      str(e.exception))

    def testHashSection(self):
        """Test hashing of the contents of an entry"""
        _, _, _, out_dtb_fname = self._DoReadFileDtb('099_hash_section.dts',
                use_real_dtb=True, update_dtb=True)
        dtb = fdt.Fdt(out_dtb_fname)
        dtb.Scan()
        hash_node = dtb.GetNode('/binman/section/hash').props['value']
        m = hashlib.sha256()
        m.update(U_BOOT_DATA)
        m.update(tools.GetBytes(ord('a'), 16))
        self.assertEqual(m.digest(), b''.join(hash_node.value))

    def testPackUBootTplMicrocode(self):
        """Test that x86 microcode can be handled correctly in TPL

        We expect to see the following in the image, in order:
            u-boot-tpl-nodtb.bin with a microcode pointer inserted at the correct
                place
            u-boot-tpl.dtb with the microcode removed
            the microcode
        """
        self._SetupTplElf('u_boot_ucode_ptr')
        first, pos_and_size = self._RunMicrocodeTest('093_x86_tpl_ucode.dts',
                                                     U_BOOT_TPL_NODTB_DATA)
        self.assertEqual(b'tplnodtb with microc' + pos_and_size +
                         b'ter somewhere in here', first)

    def testFmapX86(self):
        """Basic test of generation of a flashrom fmap"""
        data = self._DoReadFile('094_fmap_x86.dts')
        fhdr, fentries = fmap_util.DecodeFmap(data[32:])
        expected = U_BOOT_DATA + MRC_DATA + tools.GetBytes(ord('a'), 32 - 7)
        self.assertEqual(expected, data[:32])
        fhdr, fentries = fmap_util.DecodeFmap(data[32:])

        self.assertEqual(0x100, fhdr.image_size)

        self.assertEqual(0, fentries[0].offset)
        self.assertEqual(4, fentries[0].size)
        self.assertEqual(b'U_BOOT', fentries[0].name)

        self.assertEqual(4, fentries[1].offset)
        self.assertEqual(3, fentries[1].size)
        self.assertEqual(b'INTEL_MRC', fentries[1].name)

        self.assertEqual(32, fentries[2].offset)
        self.assertEqual(fmap_util.FMAP_HEADER_LEN +
                         fmap_util.FMAP_AREA_LEN * 3, fentries[2].size)
        self.assertEqual(b'FMAP', fentries[2].name)

    def testFmapX86Section(self):
        """Basic test of generation of a flashrom fmap"""
        data = self._DoReadFile('095_fmap_x86_section.dts')
        expected = U_BOOT_DATA + MRC_DATA + tools.GetBytes(ord('b'), 32 - 7)
        self.assertEqual(expected, data[:32])
        fhdr, fentries = fmap_util.DecodeFmap(data[36:])

        self.assertEqual(0x180, fhdr.image_size)
        expect_size = fmap_util.FMAP_HEADER_LEN + fmap_util.FMAP_AREA_LEN * 4
        fiter = iter(fentries)

        fentry = next(fiter)
        self.assertEqual(b'U_BOOT', fentry.name)
        self.assertEqual(0, fentry.offset)
        self.assertEqual(4, fentry.size)

        fentry = next(fiter)
        self.assertEqual(b'SECTION', fentry.name)
        self.assertEqual(4, fentry.offset)
        self.assertEqual(0x20 + expect_size, fentry.size)

        fentry = next(fiter)
        self.assertEqual(b'INTEL_MRC', fentry.name)
        self.assertEqual(4, fentry.offset)
        self.assertEqual(3, fentry.size)

        fentry = next(fiter)
        self.assertEqual(b'FMAP', fentry.name)
        self.assertEqual(36, fentry.offset)
        self.assertEqual(expect_size, fentry.size)

    def testElf(self):
        """Basic test of ELF entries"""
        self._SetupSplElf()
        self._SetupTplElf()
        with open(self.ElfTestFile('bss_data'), 'rb') as fd:
            TestFunctional._MakeInputFile('-boot', fd.read())
        data = self._DoReadFile('096_elf.dts')

    def testElfStrip(self):
        """Basic test of ELF entries"""
        self._SetupSplElf()
        with open(self.ElfTestFile('bss_data'), 'rb') as fd:
            TestFunctional._MakeInputFile('-boot', fd.read())
        data = self._DoReadFile('097_elf_strip.dts')

    def testPackOverlapMap(self):
        """Test that overlapping regions are detected"""
        with test_util.capture_sys_output() as (stdout, stderr):
            with self.assertRaises(ValueError) as e:
                self._DoTestFile('014_pack_overlap.dts', map=True)
        map_fname = tools.GetOutputFilename('image.map')
        self.assertEqual("Wrote map file '%s' to show errors\n" % map_fname,
                         stdout.getvalue())

        # We should not get an inmage, but there should be a map file
        self.assertFalse(os.path.exists(tools.GetOutputFilename('image.bin')))
        self.assertTrue(os.path.exists(map_fname))
        map_data = tools.ReadFile(map_fname, binary=False)
        self.assertEqual('''ImagePos    Offset      Size  Name
<none>    00000000  00000008  main-section
<none>     00000000  00000004  u-boot
<none>     00000003  00000004  u-boot-align
''', map_data)

    def testPackRefCode(self):
        """Test that an image with an Intel Reference code binary works"""
        data = self._DoReadFile('100_intel_refcode.dts')
        self.assertEqual(REFCODE_DATA, data[:len(REFCODE_DATA)])

    def testSectionOffset(self):
        """Tests use of a section with an offset"""
        data, _, map_data, _ = self._DoReadFileDtb('101_sections_offset.dts',
                                                   map=True)
        self.assertEqual('''ImagePos    Offset      Size  Name
00000000  00000000  00000038  main-section
00000004   00000004  00000010  section@0
00000004    00000000  00000004  u-boot
00000018   00000018  00000010  section@1
00000018    00000000  00000004  u-boot
0000002c   0000002c  00000004  section@2
0000002c    00000000  00000004  u-boot
''', map_data)
        self.assertEqual(data,
                         tools.GetBytes(0x26, 4) + U_BOOT_DATA +
                             tools.GetBytes(0x21, 12) +
                         tools.GetBytes(0x26, 4) + U_BOOT_DATA +
                             tools.GetBytes(0x61, 12) +
                         tools.GetBytes(0x26, 4) + U_BOOT_DATA +
                             tools.GetBytes(0x26, 8))

    def testCbfsRaw(self):
        """Test base handling of a Coreboot Filesystem (CBFS)

        The exact contents of the CBFS is verified by similar tests in
        cbfs_util_test.py. The tests here merely check that the files added to
        the CBFS can be found in the final image.
        """
        data = self._DoReadFile('102_cbfs_raw.dts')
        size = 0xb0

        cbfs = cbfs_util.CbfsReader(data)
        self.assertEqual(size, cbfs.rom_size)

        self.assertIn('u-boot-dtb', cbfs.files)
        cfile = cbfs.files['u-boot-dtb']
        self.assertEqual(U_BOOT_DTB_DATA, cfile.data)

    def testCbfsArch(self):
        """Test on non-x86 architecture"""
        data = self._DoReadFile('103_cbfs_raw_ppc.dts')
        size = 0x100

        cbfs = cbfs_util.CbfsReader(data)
        self.assertEqual(size, cbfs.rom_size)

        self.assertIn('u-boot-dtb', cbfs.files)
        cfile = cbfs.files['u-boot-dtb']
        self.assertEqual(U_BOOT_DTB_DATA, cfile.data)

    def testCbfsStage(self):
        """Tests handling of a Coreboot Filesystem (CBFS)"""
        if not elf.ELF_TOOLS:
            self.skipTest('Python elftools not available')
        elf_fname = os.path.join(self._indir, 'cbfs-stage.elf')
        elf.MakeElf(elf_fname, U_BOOT_DATA, U_BOOT_DTB_DATA)
        size = 0xb0

        data = self._DoReadFile('104_cbfs_stage.dts')
        cbfs = cbfs_util.CbfsReader(data)
        self.assertEqual(size, cbfs.rom_size)

        self.assertIn('u-boot', cbfs.files)
        cfile = cbfs.files['u-boot']
        self.assertEqual(U_BOOT_DATA + U_BOOT_DTB_DATA, cfile.data)

    def testCbfsRawCompress(self):
        """Test handling of compressing raw files"""
        self._CheckLz4()
        data = self._DoReadFile('105_cbfs_raw_compress.dts')
        size = 0x140

        cbfs = cbfs_util.CbfsReader(data)
        self.assertIn('u-boot', cbfs.files)
        cfile = cbfs.files['u-boot']
        self.assertEqual(COMPRESS_DATA, cfile.data)

    def testCbfsBadArch(self):
        """Test handling of a bad architecture"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('106_cbfs_bad_arch.dts')
        self.assertIn("Invalid architecture 'bad-arch'", str(e.exception))

    def testCbfsNoSize(self):
        """Test handling of a missing size property"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('107_cbfs_no_size.dts')
        self.assertIn('entry must have a size property', str(e.exception))

    def testCbfsNoCOntents(self):
        """Test handling of a CBFS entry which does not provide contentsy"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('108_cbfs_no_contents.dts')
        self.assertIn('Could not complete processing of contents',
                      str(e.exception))

    def testCbfsBadCompress(self):
        """Test handling of a bad architecture"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('109_cbfs_bad_compress.dts')
        self.assertIn("Invalid compression in 'u-boot': 'invalid-algo'",
                      str(e.exception))

    def testCbfsNamedEntries(self):
        """Test handling of named entries"""
        data = self._DoReadFile('110_cbfs_name.dts')

        cbfs = cbfs_util.CbfsReader(data)
        self.assertIn('FRED', cbfs.files)
        cfile1 = cbfs.files['FRED']
        self.assertEqual(U_BOOT_DATA, cfile1.data)

        self.assertIn('hello', cbfs.files)
        cfile2 = cbfs.files['hello']
        self.assertEqual(U_BOOT_DTB_DATA, cfile2.data)

    def _SetupIfwi(self, fname):
        """Set up to run an IFWI test

        Args:
            fname: Filename of input file to provide (fitimage.bin or ifwi.bin)
        """
        self._SetupSplElf()
        self._SetupTplElf()

        # Intel Integrated Firmware Image (IFWI) file
        with gzip.open(self.TestFile('%s.gz' % fname), 'rb') as fd:
            data = fd.read()
        TestFunctional._MakeInputFile(fname,data)

    def _CheckIfwi(self, data):
        """Check that an image with an IFWI contains the correct output

        Args:
            data: Conents of output file
        """
        expected_desc = tools.ReadFile(self.TestFile('descriptor.bin'))
        if data[:0x1000] != expected_desc:
            self.fail('Expected descriptor binary at start of image')

        # We expect to find the TPL wil in subpart IBBP entry IBBL
        image_fname = tools.GetOutputFilename('image.bin')
        tpl_fname = tools.GetOutputFilename('tpl.out')
        tools.RunIfwiTool(image_fname, tools.CMD_EXTRACT, fname=tpl_fname,
                          subpart='IBBP', entry_name='IBBL')

        tpl_data = tools.ReadFile(tpl_fname)
        self.assertEqual(U_BOOT_TPL_DATA, tpl_data[:len(U_BOOT_TPL_DATA)])

    def testPackX86RomIfwi(self):
        """Test that an x86 ROM with Integrated Firmware Image can be created"""
        self._SetupIfwi('fitimage.bin')
        data = self._DoReadFile('111_x86_rom_ifwi.dts')
        self._CheckIfwi(data)

    def testPackX86RomIfwiNoDesc(self):
        """Test that an x86 ROM with IFWI can be created from an ifwi.bin file"""
        self._SetupIfwi('ifwi.bin')
        data = self._DoReadFile('112_x86_rom_ifwi_nodesc.dts')
        self._CheckIfwi(data)

    def testPackX86RomIfwiNoData(self):
        """Test that an x86 ROM with IFWI handles missing data"""
        self._SetupIfwi('ifwi.bin')
        with self.assertRaises(ValueError) as e:
            data = self._DoReadFile('113_x86_rom_ifwi_nodata.dts')
        self.assertIn('Could not complete processing of contents',
                      str(e.exception))

    def testCbfsOffset(self):
        """Test a CBFS with files at particular offsets

        Like all CFBS tests, this is just checking the logic that calls
        cbfs_util. See cbfs_util_test for fully tests (e.g. test_cbfs_offset()).
        """
        data = self._DoReadFile('114_cbfs_offset.dts')
        size = 0x200

        cbfs = cbfs_util.CbfsReader(data)
        self.assertEqual(size, cbfs.rom_size)

        self.assertIn('u-boot', cbfs.files)
        cfile = cbfs.files['u-boot']
        self.assertEqual(U_BOOT_DATA, cfile.data)
        self.assertEqual(0x40, cfile.cbfs_offset)

        self.assertIn('u-boot-dtb', cbfs.files)
        cfile2 = cbfs.files['u-boot-dtb']
        self.assertEqual(U_BOOT_DTB_DATA, cfile2.data)
        self.assertEqual(0x140, cfile2.cbfs_offset)

    def testFdtmap(self):
        """Test an FDT map can be inserted in the image"""
        data = self.data = self._DoReadFileRealDtb('115_fdtmap.dts')
        fdtmap_data = data[len(U_BOOT_DATA):]
        magic = fdtmap_data[:8]
        self.assertEqual(b'_FDTMAP_', magic)
        self.assertEqual(tools.GetBytes(0, 8), fdtmap_data[8:16])

        fdt_data = fdtmap_data[16:]
        dtb = fdt.Fdt.FromData(fdt_data)
        dtb.Scan()
        props = self._GetPropTree(dtb, BASE_DTB_PROPS, prefix='/')
        self.assertEqual({
            'image-pos': 0,
            'offset': 0,
            'u-boot:offset': 0,
            'u-boot:size': len(U_BOOT_DATA),
            'u-boot:image-pos': 0,
            'fdtmap:image-pos': 4,
            'fdtmap:offset': 4,
            'fdtmap:size': len(fdtmap_data),
            'size': len(data),
        }, props)

    def testFdtmapNoMatch(self):
        """Check handling of an FDT map when the section cannot be found"""
        self.data = self._DoReadFileRealDtb('115_fdtmap.dts')

        # Mangle the section name, which should cause a mismatch between the
        # correct FDT path and the one expected by the section
        image = control.images['image']
        image._node.path += '-suffix'
        entries = image.GetEntries()
        fdtmap = entries['fdtmap']
        with self.assertRaises(ValueError) as e:
            fdtmap._GetFdtmap()
        self.assertIn("Cannot locate node for path '/binman-suffix'",
                      str(e.exception))

    def testFdtmapHeader(self):
        """Test an FDT map and image header can be inserted in the image"""
        data = self.data = self._DoReadFileRealDtb('116_fdtmap_hdr.dts')
        fdtmap_pos = len(U_BOOT_DATA)
        fdtmap_data = data[fdtmap_pos:]
        fdt_data = fdtmap_data[16:]
        dtb = fdt.Fdt.FromData(fdt_data)
        fdt_size = dtb.GetFdtObj().totalsize()
        hdr_data = data[-8:]
        self.assertEqual(b'BinM', hdr_data[:4])
        offset = struct.unpack('<I', hdr_data[4:])[0] & 0xffffffff
        self.assertEqual(fdtmap_pos - 0x400, offset - (1 << 32))

    def testFdtmapHeaderStart(self):
        """Test an image header can be inserted at the image start"""
        data = self.data = self._DoReadFileRealDtb('117_fdtmap_hdr_start.dts')
        fdtmap_pos = 0x100 + len(U_BOOT_DATA)
        hdr_data = data[:8]
        self.assertEqual(b'BinM', hdr_data[:4])
        offset = struct.unpack('<I', hdr_data[4:])[0]
        self.assertEqual(fdtmap_pos, offset)

    def testFdtmapHeaderPos(self):
        """Test an image header can be inserted at a chosen position"""
        data = self.data = self._DoReadFileRealDtb('118_fdtmap_hdr_pos.dts')
        fdtmap_pos = 0x100 + len(U_BOOT_DATA)
        hdr_data = data[0x80:0x88]
        self.assertEqual(b'BinM', hdr_data[:4])
        offset = struct.unpack('<I', hdr_data[4:])[0]
        self.assertEqual(fdtmap_pos, offset)

    def testHeaderMissingFdtmap(self):
        """Test an image header requires an fdtmap"""
        with self.assertRaises(ValueError) as e:
            self.data = self._DoReadFileRealDtb('119_fdtmap_hdr_missing.dts')
        self.assertIn("'image_header' section must have an 'fdtmap' sibling",
                      str(e.exception))

    def testHeaderNoLocation(self):
        """Test an image header with a no specified location is detected"""
        with self.assertRaises(ValueError) as e:
            self.data = self._DoReadFileRealDtb('120_hdr_no_location.dts')
        self.assertIn("Invalid location 'None', expected 'start' or 'end'",
                      str(e.exception))

    def testEntryExpand(self):
        """Test expanding an entry after it is packed"""
        data = self._DoReadFile('121_entry_expand.dts')
        self.assertEqual(b'aaa', data[:3])
        self.assertEqual(U_BOOT_DATA, data[3:3 + len(U_BOOT_DATA)])
        self.assertEqual(b'aaa', data[-3:])

    def testEntryExpandBad(self):
        """Test expanding an entry after it is packed, twice"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('122_entry_expand_twice.dts')
        self.assertIn("Image '/binman': Entries changed size after packing",
                      str(e.exception))

    def testEntryExpandSection(self):
        """Test expanding an entry within a section after it is packed"""
        data = self._DoReadFile('123_entry_expand_section.dts')
        self.assertEqual(b'aaa', data[:3])
        self.assertEqual(U_BOOT_DATA, data[3:3 + len(U_BOOT_DATA)])
        self.assertEqual(b'aaa', data[-3:])

    def testCompressDtb(self):
        """Test that compress of device-tree files is supported"""
        self._CheckLz4()
        data = self.data = self._DoReadFileRealDtb('124_compress_dtb.dts')
        self.assertEqual(U_BOOT_DATA, data[:len(U_BOOT_DATA)])
        comp_data = data[len(U_BOOT_DATA):]
        orig = self._decompress(comp_data)
        dtb = fdt.Fdt.FromData(orig)
        dtb.Scan()
        props = self._GetPropTree(dtb, ['size', 'uncomp-size'])
        expected = {
            'u-boot:size': len(U_BOOT_DATA),
            'u-boot-dtb:uncomp-size': len(orig),
            'u-boot-dtb:size': len(comp_data),
            'size': len(data),
            }
        self.assertEqual(expected, props)

    def testCbfsUpdateFdt(self):
        """Test that we can update the device tree with CBFS offset/size info"""
        self._CheckLz4()
        data, _, _, out_dtb_fname = self._DoReadFileDtb('125_cbfs_update.dts',
                                                        update_dtb=True)
        dtb = fdt.Fdt(out_dtb_fname)
        dtb.Scan()
        props = self._GetPropTree(dtb, BASE_DTB_PROPS + ['uncomp-size'])
        del props['cbfs/u-boot:size']
        self.assertEqual({
            'offset': 0,
            'size': len(data),
            'image-pos': 0,
            'cbfs:offset': 0,
            'cbfs:size': len(data),
            'cbfs:image-pos': 0,
            'cbfs/u-boot:offset': 0x38,
            'cbfs/u-boot:uncomp-size': len(U_BOOT_DATA),
            'cbfs/u-boot:image-pos': 0x38,
            'cbfs/u-boot-dtb:offset': 0xb8,
            'cbfs/u-boot-dtb:size': len(U_BOOT_DATA),
            'cbfs/u-boot-dtb:image-pos': 0xb8,
            }, props)

    def testCbfsBadType(self):
        """Test an image header with a no specified location is detected"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('126_cbfs_bad_type.dts')
        self.assertIn("Unknown cbfs-type 'badtype'", str(e.exception))

    def testList(self):
        """Test listing the files in an image"""
        self._CheckLz4()
        data = self._DoReadFile('127_list.dts')
        image = control.images['image']
        entries = image.BuildEntryList()
        self.assertEqual(7, len(entries))

        ent = entries[0]
        self.assertEqual(0, ent.indent)
        self.assertEqual('main-section', ent.name)
        self.assertEqual('section', ent.etype)
        self.assertEqual(len(data), ent.size)
        self.assertEqual(0, ent.image_pos)
        self.assertEqual(None, ent.uncomp_size)
        self.assertEqual(0, ent.offset)

        ent = entries[1]
        self.assertEqual(1, ent.indent)
        self.assertEqual('u-boot', ent.name)
        self.assertEqual('u-boot', ent.etype)
        self.assertEqual(len(U_BOOT_DATA), ent.size)
        self.assertEqual(0, ent.image_pos)
        self.assertEqual(None, ent.uncomp_size)
        self.assertEqual(0, ent.offset)

        ent = entries[2]
        self.assertEqual(1, ent.indent)
        self.assertEqual('section', ent.name)
        self.assertEqual('section', ent.etype)
        section_size = ent.size
        self.assertEqual(0x100, ent.image_pos)
        self.assertEqual(None, ent.uncomp_size)
        self.assertEqual(0x100, ent.offset)

        ent = entries[3]
        self.assertEqual(2, ent.indent)
        self.assertEqual('cbfs', ent.name)
        self.assertEqual('cbfs', ent.etype)
        self.assertEqual(0x400, ent.size)
        self.assertEqual(0x100, ent.image_pos)
        self.assertEqual(None, ent.uncomp_size)
        self.assertEqual(0, ent.offset)

        ent = entries[4]
        self.assertEqual(3, ent.indent)
        self.assertEqual('u-boot', ent.name)
        self.assertEqual('u-boot', ent.etype)
        self.assertEqual(len(U_BOOT_DATA), ent.size)
        self.assertEqual(0x138, ent.image_pos)
        self.assertEqual(None, ent.uncomp_size)
        self.assertEqual(0x38, ent.offset)

        ent = entries[5]
        self.assertEqual(3, ent.indent)
        self.assertEqual('u-boot-dtb', ent.name)
        self.assertEqual('text', ent.etype)
        self.assertGreater(len(COMPRESS_DATA), ent.size)
        self.assertEqual(0x178, ent.image_pos)
        self.assertEqual(len(COMPRESS_DATA), ent.uncomp_size)
        self.assertEqual(0x78, ent.offset)

        ent = entries[6]
        self.assertEqual(2, ent.indent)
        self.assertEqual('u-boot-dtb', ent.name)
        self.assertEqual('u-boot-dtb', ent.etype)
        self.assertEqual(0x500, ent.image_pos)
        self.assertEqual(len(U_BOOT_DTB_DATA), ent.uncomp_size)
        dtb_size = ent.size
        # Compressing this data expands it since headers are added
        self.assertGreater(dtb_size, len(U_BOOT_DTB_DATA))
        self.assertEqual(0x400, ent.offset)

        self.assertEqual(len(data), 0x100 + section_size)
        self.assertEqual(section_size, 0x400 + dtb_size)

    def testFindFdtmap(self):
        """Test locating an FDT map in an image"""
        self._CheckLz4()
        data = self.data = self._DoReadFileRealDtb('128_decode_image.dts')
        image = control.images['image']
        entries = image.GetEntries()
        entry = entries['fdtmap']
        self.assertEqual(entry.image_pos, fdtmap.LocateFdtmap(data))

    def testFindFdtmapMissing(self):
        """Test failing to locate an FDP map"""
        data = self._DoReadFile('005_simple.dts')
        self.assertEqual(None, fdtmap.LocateFdtmap(data))

    def testFindImageHeader(self):
        """Test locating a image header"""
        self._CheckLz4()
        data = self.data = self._DoReadFileRealDtb('128_decode_image.dts')
        image = control.images['image']
        entries = image.GetEntries()
        entry = entries['fdtmap']
        # The header should point to the FDT map
        self.assertEqual(entry.image_pos, image_header.LocateHeaderOffset(data))

    def testFindImageHeaderStart(self):
        """Test locating a image header located at the start of an image"""
        data = self.data = self._DoReadFileRealDtb('117_fdtmap_hdr_start.dts')
        image = control.images['image']
        entries = image.GetEntries()
        entry = entries['fdtmap']
        # The header should point to the FDT map
        self.assertEqual(entry.image_pos, image_header.LocateHeaderOffset(data))

    def testFindImageHeaderMissing(self):
        """Test failing to locate an image header"""
        data = self._DoReadFile('005_simple.dts')
        self.assertEqual(None, image_header.LocateHeaderOffset(data))

    def testReadImage(self):
        """Test reading an image and accessing its FDT map"""
        self._CheckLz4()
        data = self.data = self._DoReadFileRealDtb('128_decode_image.dts')
        image_fname = tools.GetOutputFilename('image.bin')
        orig_image = control.images['image']
        image = Image.FromFile(image_fname)
        self.assertEqual(orig_image.GetEntries().keys(),
                         image.GetEntries().keys())

        orig_entry = orig_image.GetEntries()['fdtmap']
        entry = image.GetEntries()['fdtmap']
        self.assertEquals(orig_entry.offset, entry.offset)
        self.assertEquals(orig_entry.size, entry.size)
        self.assertEquals(orig_entry.image_pos, entry.image_pos)

    def testReadImageNoHeader(self):
        """Test accessing an image's FDT map without an image header"""
        self._CheckLz4()
        data = self._DoReadFileRealDtb('129_decode_image_nohdr.dts')
        image_fname = tools.GetOutputFilename('image.bin')
        image = Image.FromFile(image_fname)
        self.assertTrue(isinstance(image, Image))
        self.assertEqual('image', image.image_name[-5:])

    def testReadImageFail(self):
        """Test failing to read an image image's FDT map"""
        self._DoReadFile('005_simple.dts')
        image_fname = tools.GetOutputFilename('image.bin')
        with self.assertRaises(ValueError) as e:
            image = Image.FromFile(image_fname)
        self.assertIn("Cannot find FDT map in image", str(e.exception))

    def testListCmd(self):
        """Test listing the files in an image using an Fdtmap"""
        self._CheckLz4()
        data = self._DoReadFileRealDtb('130_list_fdtmap.dts')

        # lz4 compression size differs depending on the version
        image = control.images['image']
        entries = image.GetEntries()
        section_size = entries['section'].size
        fdt_size = entries['section'].GetEntries()['u-boot-dtb'].size
        fdtmap_offset = entries['fdtmap'].offset

        try:
            tmpdir, updated_fname = self._SetupImageInTmpdir()
            with test_util.capture_sys_output() as (stdout, stderr):
                self._DoBinman('ls', '-i', updated_fname)
        finally:
            shutil.rmtree(tmpdir)
        lines = stdout.getvalue().splitlines()
        expected = [
'Name              Image-pos  Size  Entry-type    Offset  Uncomp-size',
'----------------------------------------------------------------------',
'main-section              0   c00  section            0',
'  u-boot                  0     4  u-boot             0',
'  section               100   %x  section          100' % section_size,
'    cbfs                100   400  cbfs               0',
'      u-boot            138     4  u-boot            38',
'      u-boot-dtb        180   105  u-boot-dtb        80          3c9',
'    u-boot-dtb          500   %x  u-boot-dtb       400          3c9' % fdt_size,
'  fdtmap                %x   3bd  fdtmap           %x' %
        (fdtmap_offset, fdtmap_offset),
'  image-header          bf8     8  image-header     bf8',
            ]
        self.assertEqual(expected, lines)

    def testListCmdFail(self):
        """Test failing to list an image"""
        self._DoReadFile('005_simple.dts')
        try:
            tmpdir, updated_fname = self._SetupImageInTmpdir()
            with self.assertRaises(ValueError) as e:
                self._DoBinman('ls', '-i', updated_fname)
        finally:
            shutil.rmtree(tmpdir)
        self.assertIn("Cannot find FDT map in image", str(e.exception))

    def _RunListCmd(self, paths, expected):
        """List out entries and check the result

        Args:
            paths: List of paths to pass to the list command
            expected: Expected list of filenames to be returned, in order
        """
        self._CheckLz4()
        self._DoReadFileRealDtb('130_list_fdtmap.dts')
        image_fname = tools.GetOutputFilename('image.bin')
        image = Image.FromFile(image_fname)
        lines = image.GetListEntries(paths)[1]
        files = [line[0].strip() for line in lines[1:]]
        self.assertEqual(expected, files)

    def testListCmdSection(self):
        """Test listing the files in a section"""
        self._RunListCmd(['section'],
            ['section', 'cbfs', 'u-boot', 'u-boot-dtb', 'u-boot-dtb'])

    def testListCmdFile(self):
        """Test listing a particular file"""
        self._RunListCmd(['*u-boot-dtb'], ['u-boot-dtb', 'u-boot-dtb'])

    def testListCmdWildcard(self):
        """Test listing a wildcarded file"""
        self._RunListCmd(['*boot*'],
            ['u-boot', 'u-boot', 'u-boot-dtb', 'u-boot-dtb'])

    def testListCmdWildcardMulti(self):
        """Test listing a wildcarded file"""
        self._RunListCmd(['*cb*', '*head*'],
            ['cbfs', 'u-boot', 'u-boot-dtb', 'image-header'])

    def testListCmdEmpty(self):
        """Test listing a wildcarded file"""
        self._RunListCmd(['nothing'], [])

    def testListCmdPath(self):
        """Test listing the files in a sub-entry of a section"""
        self._RunListCmd(['section/cbfs'], ['cbfs', 'u-boot', 'u-boot-dtb'])

    def _RunExtractCmd(self, entry_name, decomp=True):
        """Extract an entry from an image

        Args:
            entry_name: Entry name to extract
            decomp: True to decompress the data if compressed, False to leave
                it in its raw uncompressed format

        Returns:
            data from entry
        """
        self._CheckLz4()
        self._DoReadFileRealDtb('130_list_fdtmap.dts')
        image_fname = tools.GetOutputFilename('image.bin')
        return control.ReadEntry(image_fname, entry_name, decomp)

    def testExtractSimple(self):
        """Test extracting a single file"""
        data = self._RunExtractCmd('u-boot')
        self.assertEqual(U_BOOT_DATA, data)

    def testExtractSection(self):
        """Test extracting the files in a section"""
        data = self._RunExtractCmd('section')
        cbfs_data = data[:0x400]
        cbfs = cbfs_util.CbfsReader(cbfs_data)
        self.assertEqual(['u-boot', 'u-boot-dtb', ''], list(cbfs.files.keys()))
        dtb_data = data[0x400:]
        dtb = self._decompress(dtb_data)
        self.assertEqual(EXTRACT_DTB_SIZE, len(dtb))

    def testExtractCompressed(self):
        """Test extracting compressed data"""
        data = self._RunExtractCmd('section/u-boot-dtb')
        self.assertEqual(EXTRACT_DTB_SIZE, len(data))

    def testExtractRaw(self):
        """Test extracting compressed data without decompressing it"""
        data = self._RunExtractCmd('section/u-boot-dtb', decomp=False)
        dtb = self._decompress(data)
        self.assertEqual(EXTRACT_DTB_SIZE, len(dtb))

    def testExtractCbfs(self):
        """Test extracting CBFS data"""
        data = self._RunExtractCmd('section/cbfs/u-boot')
        self.assertEqual(U_BOOT_DATA, data)

    def testExtractCbfsCompressed(self):
        """Test extracting CBFS compressed data"""
        data = self._RunExtractCmd('section/cbfs/u-boot-dtb')
        self.assertEqual(EXTRACT_DTB_SIZE, len(data))

    def testExtractCbfsRaw(self):
        """Test extracting CBFS compressed data without decompressing it"""
        data = self._RunExtractCmd('section/cbfs/u-boot-dtb', decomp=False)
        dtb = tools.Decompress(data, 'lzma', with_header=False)
        self.assertEqual(EXTRACT_DTB_SIZE, len(dtb))

    def testExtractBadEntry(self):
        """Test extracting a bad section path"""
        with self.assertRaises(ValueError) as e:
            self._RunExtractCmd('section/does-not-exist')
        self.assertIn("Entry 'does-not-exist' not found in '/section'",
                      str(e.exception))

    def testExtractMissingFile(self):
        """Test extracting file that does not exist"""
        with self.assertRaises(IOError) as e:
            control.ReadEntry('missing-file', 'name')

    def testExtractBadFile(self):
        """Test extracting an invalid file"""
        fname = os.path.join(self._indir, 'badfile')
        tools.WriteFile(fname, b'')
        with self.assertRaises(ValueError) as e:
            control.ReadEntry(fname, 'name')

    def testExtractCmd(self):
        """Test extracting a file fron an image on the command line"""
        self._CheckLz4()
        self._DoReadFileRealDtb('130_list_fdtmap.dts')
        fname = os.path.join(self._indir, 'output.extact')
        try:
            tmpdir, updated_fname = self._SetupImageInTmpdir()
            with test_util.capture_sys_output() as (stdout, stderr):
                self._DoBinman('extract', '-i', updated_fname, 'u-boot',
                               '-f', fname)
        finally:
            shutil.rmtree(tmpdir)
        data = tools.ReadFile(fname)
        self.assertEqual(U_BOOT_DATA, data)

    def testExtractOneEntry(self):
        """Test extracting a single entry fron an image """
        self._CheckLz4()
        self._DoReadFileRealDtb('130_list_fdtmap.dts')
        image_fname = tools.GetOutputFilename('image.bin')
        fname = os.path.join(self._indir, 'output.extact')
        control.ExtractEntries(image_fname, fname, None, ['u-boot'])
        data = tools.ReadFile(fname)
        self.assertEqual(U_BOOT_DATA, data)

    def _CheckExtractOutput(self, decomp):
        """Helper to test file output with and without decompression

        Args:
            decomp: True to decompress entry data, False to output it raw
        """
        def _CheckPresent(entry_path, expect_data, expect_size=None):
            """Check and remove expected file

            This checks the data/size of a file and removes the file both from
            the outfiles set and from the output directory. Once all files are
            processed, both the set and directory should be empty.

            Args:
                entry_path: Entry path
                expect_data: Data to expect in file, or None to skip check
                expect_size: Size of data to expect in file, or None to skip
            """
            path = os.path.join(outdir, entry_path)
            data = tools.ReadFile(path)
            os.remove(path)
            if expect_data:
                self.assertEqual(expect_data, data)
            elif expect_size:
                self.assertEqual(expect_size, len(data))
            outfiles.remove(path)

        def _CheckDirPresent(name):
            """Remove expected directory

            This gives an error if the directory does not exist as expected

            Args:
                name: Name of directory to remove
            """
            path = os.path.join(outdir, name)
            os.rmdir(path)

        self._DoReadFileRealDtb('130_list_fdtmap.dts')
        image_fname = tools.GetOutputFilename('image.bin')
        outdir = os.path.join(self._indir, 'extract')
        einfos = control.ExtractEntries(image_fname, None, outdir, [], decomp)

        # Create a set of all file that were output (should be 9)
        outfiles = set()
        for root, dirs, files in os.walk(outdir):
            outfiles |= set([os.path.join(root, fname) for fname in files])
        self.assertEqual(9, len(outfiles))
        self.assertEqual(9, len(einfos))

        image = control.images['image']
        entries = image.GetEntries()

        # Check the 9 files in various ways
        section = entries['section']
        section_entries = section.GetEntries()
        cbfs_entries = section_entries['cbfs'].GetEntries()
        _CheckPresent('u-boot', U_BOOT_DATA)
        _CheckPresent('section/cbfs/u-boot', U_BOOT_DATA)
        dtb_len = EXTRACT_DTB_SIZE
        if not decomp:
            dtb_len = cbfs_entries['u-boot-dtb'].size
        _CheckPresent('section/cbfs/u-boot-dtb', None, dtb_len)
        if not decomp:
            dtb_len = section_entries['u-boot-dtb'].size
        _CheckPresent('section/u-boot-dtb', None, dtb_len)

        fdtmap = entries['fdtmap']
        _CheckPresent('fdtmap', fdtmap.data)
        hdr = entries['image-header']
        _CheckPresent('image-header', hdr.data)

        _CheckPresent('section/root', section.data)
        cbfs = section_entries['cbfs']
        _CheckPresent('section/cbfs/root', cbfs.data)
        data = tools.ReadFile(image_fname)
        _CheckPresent('root', data)

        # There should be no files left. Remove all the directories to check.
        # If there are any files/dirs remaining, one of these checks will fail.
        self.assertEqual(0, len(outfiles))
        _CheckDirPresent('section/cbfs')
        _CheckDirPresent('section')
        _CheckDirPresent('')
        self.assertFalse(os.path.exists(outdir))

    def testExtractAllEntries(self):
        """Test extracting all entries"""
        self._CheckLz4()
        self._CheckExtractOutput(decomp=True)

    def testExtractAllEntriesRaw(self):
        """Test extracting all entries without decompressing them"""
        self._CheckLz4()
        self._CheckExtractOutput(decomp=False)

    def testExtractSelectedEntries(self):
        """Test extracting some entries"""
        self._CheckLz4()
        self._DoReadFileRealDtb('130_list_fdtmap.dts')
        image_fname = tools.GetOutputFilename('image.bin')
        outdir = os.path.join(self._indir, 'extract')
        einfos = control.ExtractEntries(image_fname, None, outdir,
                                        ['*cb*', '*head*'])

        # File output is tested by testExtractAllEntries(), so just check that
        # the expected entries are selected
        names = [einfo.name for einfo in einfos]
        self.assertEqual(names,
                         ['cbfs', 'u-boot', 'u-boot-dtb', 'image-header'])

    def testExtractNoEntryPaths(self):
        """Test extracting some entries"""
        self._CheckLz4()
        self._DoReadFileRealDtb('130_list_fdtmap.dts')
        image_fname = tools.GetOutputFilename('image.bin')
        with self.assertRaises(ValueError) as e:
            control.ExtractEntries(image_fname, 'fname', None, [])
        self.assertIn('Must specify an entry path to write with -f',
                      str(e.exception))

    def testExtractTooManyEntryPaths(self):
        """Test extracting some entries"""
        self._CheckLz4()
        self._DoReadFileRealDtb('130_list_fdtmap.dts')
        image_fname = tools.GetOutputFilename('image.bin')
        with self.assertRaises(ValueError) as e:
            control.ExtractEntries(image_fname, 'fname', None, ['a', 'b'])
        self.assertIn('Must specify exactly one entry path to write with -f',
                      str(e.exception))

    def testPackAlignSection(self):
        """Test that sections can have alignment"""
        self._DoReadFile('131_pack_align_section.dts')

        self.assertIn('image', control.images)
        image = control.images['image']
        entries = image.GetEntries()
        self.assertEqual(3, len(entries))

        # First u-boot
        self.assertIn('u-boot', entries)
        entry = entries['u-boot']
        self.assertEqual(0, entry.offset)
        self.assertEqual(0, entry.image_pos)
        self.assertEqual(len(U_BOOT_DATA), entry.contents_size)
        self.assertEqual(len(U_BOOT_DATA), entry.size)

        # Section0
        self.assertIn('section0', entries)
        section0 = entries['section0']
        self.assertEqual(0x10, section0.offset)
        self.assertEqual(0x10, section0.image_pos)
        self.assertEqual(len(U_BOOT_DATA), section0.size)

        # Second u-boot
        section_entries = section0.GetEntries()
        self.assertIn('u-boot', section_entries)
        entry = section_entries['u-boot']
        self.assertEqual(0, entry.offset)
        self.assertEqual(0x10, entry.image_pos)
        self.assertEqual(len(U_BOOT_DATA), entry.contents_size)
        self.assertEqual(len(U_BOOT_DATA), entry.size)

        # Section1
        self.assertIn('section1', entries)
        section1 = entries['section1']
        self.assertEqual(0x14, section1.offset)
        self.assertEqual(0x14, section1.image_pos)
        self.assertEqual(0x20, section1.size)

        # Second u-boot
        section_entries = section1.GetEntries()
        self.assertIn('u-boot', section_entries)
        entry = section_entries['u-boot']
        self.assertEqual(0, entry.offset)
        self.assertEqual(0x14, entry.image_pos)
        self.assertEqual(len(U_BOOT_DATA), entry.contents_size)
        self.assertEqual(len(U_BOOT_DATA), entry.size)

        # Section2
        self.assertIn('section2', section_entries)
        section2 = section_entries['section2']
        self.assertEqual(0x4, section2.offset)
        self.assertEqual(0x18, section2.image_pos)
        self.assertEqual(4, section2.size)

        # Third u-boot
        section_entries = section2.GetEntries()
        self.assertIn('u-boot', section_entries)
        entry = section_entries['u-boot']
        self.assertEqual(0, entry.offset)
        self.assertEqual(0x18, entry.image_pos)
        self.assertEqual(len(U_BOOT_DATA), entry.contents_size)
        self.assertEqual(len(U_BOOT_DATA), entry.size)

    def _RunReplaceCmd(self, entry_name, data, decomp=True, allow_resize=True,
                       dts='132_replace.dts'):
        """Replace an entry in an image

        This writes the entry data to update it, then opens the updated file and
        returns the value that it now finds there.

        Args:
            entry_name: Entry name to replace
            data: Data to replace it with
            decomp: True to compress the data if needed, False if data is
                already compressed so should be used as is
            allow_resize: True to allow entries to change size, False to raise
                an exception

        Returns:
            Tuple:
                data from entry
                data from fdtmap (excluding header)
                Image object that was modified
        """
        dtb_data = self._DoReadFileDtb(dts, use_real_dtb=True,
                                       update_dtb=True)[1]

        self.assertIn('image', control.images)
        image = control.images['image']
        entries = image.GetEntries()
        orig_dtb_data = entries['u-boot-dtb'].data
        orig_fdtmap_data = entries['fdtmap'].data

        image_fname = tools.GetOutputFilename('image.bin')
        updated_fname = tools.GetOutputFilename('image-updated.bin')
        tools.WriteFile(updated_fname, tools.ReadFile(image_fname))
        image = control.WriteEntry(updated_fname, entry_name, data, decomp,
                                   allow_resize)
        data = control.ReadEntry(updated_fname, entry_name, decomp)

        # The DT data should not change unless resized:
        if not allow_resize:
            new_dtb_data = entries['u-boot-dtb'].data
            self.assertEqual(new_dtb_data, orig_dtb_data)
            new_fdtmap_data = entries['fdtmap'].data
            self.assertEqual(new_fdtmap_data, orig_fdtmap_data)

        return data, orig_fdtmap_data[fdtmap.FDTMAP_HDR_LEN:], image

    def testReplaceSimple(self):
        """Test replacing a single file"""
        expected = b'x' * len(U_BOOT_DATA)
        data, expected_fdtmap, _ = self._RunReplaceCmd('u-boot', expected,
                                                    allow_resize=False)
        self.assertEqual(expected, data)

        # Test that the state looks right. There should be an FDT for the fdtmap
        # that we jsut read back in, and it should match what we find in the
        # 'control' tables. Checking for an FDT that does not exist should
        # return None.
        path, fdtmap = state.GetFdtContents('fdtmap')
        self.assertIsNotNone(path)
        self.assertEqual(expected_fdtmap, fdtmap)

        dtb = state.GetFdtForEtype('fdtmap')
        self.assertEqual(dtb.GetContents(), fdtmap)

        missing_path, missing_fdtmap = state.GetFdtContents('missing')
        self.assertIsNone(missing_path)
        self.assertIsNone(missing_fdtmap)

        missing_dtb = state.GetFdtForEtype('missing')
        self.assertIsNone(missing_dtb)

        self.assertEqual('/binman', state.fdt_path_prefix)

    def testReplaceResizeFail(self):
        """Test replacing a file by something larger"""
        expected = U_BOOT_DATA + b'x'
        with self.assertRaises(ValueError) as e:
            self._RunReplaceCmd('u-boot', expected, allow_resize=False,
                                dts='139_replace_repack.dts')
        self.assertIn("Node '/u-boot': Entry data size does not match, but resize is disabled",
                      str(e.exception))

    def testReplaceMulti(self):
        """Test replacing entry data where multiple images are generated"""
        data = self._DoReadFileDtb('133_replace_multi.dts', use_real_dtb=True,
                                   update_dtb=True)[0]
        expected = b'x' * len(U_BOOT_DATA)
        updated_fname = tools.GetOutputFilename('image-updated.bin')
        tools.WriteFile(updated_fname, data)
        entry_name = 'u-boot'
        control.WriteEntry(updated_fname, entry_name, expected,
                           allow_resize=False)
        data = control.ReadEntry(updated_fname, entry_name)
        self.assertEqual(expected, data)

        # Check the state looks right.
        self.assertEqual('/binman/image', state.fdt_path_prefix)

        # Now check we can write the first image
        image_fname = tools.GetOutputFilename('first-image.bin')
        updated_fname = tools.GetOutputFilename('first-updated.bin')
        tools.WriteFile(updated_fname, tools.ReadFile(image_fname))
        entry_name = 'u-boot'
        control.WriteEntry(updated_fname, entry_name, expected,
                           allow_resize=False)
        data = control.ReadEntry(updated_fname, entry_name)
        self.assertEqual(expected, data)

        # Check the state looks right.
        self.assertEqual('/binman/first-image', state.fdt_path_prefix)

    def testUpdateFdtAllRepack(self):
        """Test that all device trees are updated with offset/size info"""
        data = self._DoReadFileRealDtb('134_fdt_update_all_repack.dts')
        SECTION_SIZE = 0x300
        DTB_SIZE = 602
        FDTMAP_SIZE = 608
        base_expected = {
            'offset': 0,
            'size': SECTION_SIZE + DTB_SIZE * 2 + FDTMAP_SIZE,
            'image-pos': 0,
            'section:offset': 0,
            'section:size': SECTION_SIZE,
            'section:image-pos': 0,
            'section/u-boot-dtb:offset': 4,
            'section/u-boot-dtb:size': 636,
            'section/u-boot-dtb:image-pos': 4,
            'u-boot-spl-dtb:offset': SECTION_SIZE,
            'u-boot-spl-dtb:size': DTB_SIZE,
            'u-boot-spl-dtb:image-pos': SECTION_SIZE,
            'u-boot-tpl-dtb:offset': SECTION_SIZE + DTB_SIZE,
            'u-boot-tpl-dtb:image-pos': SECTION_SIZE + DTB_SIZE,
            'u-boot-tpl-dtb:size': DTB_SIZE,
            'fdtmap:offset': SECTION_SIZE + DTB_SIZE * 2,
            'fdtmap:size': FDTMAP_SIZE,
            'fdtmap:image-pos': SECTION_SIZE + DTB_SIZE * 2,
        }
        main_expected = {
            'section:orig-size': SECTION_SIZE,
            'section/u-boot-dtb:orig-offset': 4,
        }

        # We expect three device-tree files in the output, with the first one
        # within a fixed-size section.
        # Read them in sequence. We look for an 'spl' property in the SPL tree,
        # and 'tpl' in the TPL tree, to make sure they are distinct from the
        # main U-Boot tree. All three should have the same positions and offset
        # except that the main tree should include the main_expected properties
        start = 4
        for item in ['', 'spl', 'tpl', None]:
            if item is None:
                start += 16  # Move past fdtmap header
            dtb = fdt.Fdt.FromData(data[start:])
            dtb.Scan()
            props = self._GetPropTree(dtb,
                BASE_DTB_PROPS + REPACK_DTB_PROPS + ['spl', 'tpl'],
                prefix='/' if item is None else '/binman/')
            expected = dict(base_expected)
            if item:
                expected[item] = 0
            else:
                # Main DTB and fdtdec should include the 'orig-' properties
                expected.update(main_expected)
            # Helpful for debugging:
            #for prop in sorted(props):
                #print('prop %s %s %s' % (prop, props[prop], expected[prop]))
            self.assertEqual(expected, props)
            if item == '':
                start = SECTION_SIZE
            else:
                start += dtb._fdt_obj.totalsize()

    def testFdtmapHeaderMiddle(self):
        """Test an FDT map in the middle of an image when it should be at end"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFileRealDtb('135_fdtmap_hdr_middle.dts')
        self.assertIn("Invalid sibling order 'middle' for image-header: Must be at 'end' to match location",
                      str(e.exception))

    def testFdtmapHeaderStartBad(self):
        """Test an FDT map in middle of an image when it should be at start"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFileRealDtb('136_fdtmap_hdr_startbad.dts')
        self.assertIn("Invalid sibling order 'end' for image-header: Must be at 'start' to match location",
                      str(e.exception))

    def testFdtmapHeaderEndBad(self):
        """Test an FDT map at the start of an image when it should be at end"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFileRealDtb('137_fdtmap_hdr_endbad.dts')
        self.assertIn("Invalid sibling order 'start' for image-header: Must be at 'end' to match location",
                      str(e.exception))

    def testFdtmapHeaderNoSize(self):
        """Test an image header at the end of an image with undefined size"""
        self._DoReadFileRealDtb('138_fdtmap_hdr_nosize.dts')

    def testReplaceResize(self):
        """Test replacing a single file in an entry with a larger file"""
        expected = U_BOOT_DATA + b'x'
        data, _, image = self._RunReplaceCmd('u-boot', expected,
                                             dts='139_replace_repack.dts')
        self.assertEqual(expected, data)

        entries = image.GetEntries()
        dtb_data = entries['u-boot-dtb'].data
        dtb = fdt.Fdt.FromData(dtb_data)
        dtb.Scan()

        # The u-boot section should now be larger in the dtb
        node = dtb.GetNode('/binman/u-boot')
        self.assertEqual(len(expected), fdt_util.GetInt(node, 'size'))

        # Same for the fdtmap
        fdata = entries['fdtmap'].data
        fdtb = fdt.Fdt.FromData(fdata[fdtmap.FDTMAP_HDR_LEN:])
        fdtb.Scan()
        fnode = fdtb.GetNode('/u-boot')
        self.assertEqual(len(expected), fdt_util.GetInt(fnode, 'size'))

    def testReplaceResizeNoRepack(self):
        """Test replacing an entry with a larger file when not allowed"""
        expected = U_BOOT_DATA + b'x'
        with self.assertRaises(ValueError) as e:
            self._RunReplaceCmd('u-boot', expected)
        self.assertIn('Entry data size does not match, but allow-repack is not present for this image',
                      str(e.exception))

    def testEntryShrink(self):
        """Test contracting an entry after it is packed"""
        try:
            state.SetAllowEntryContraction(True)
            data = self._DoReadFileDtb('140_entry_shrink.dts',
                                       update_dtb=True)[0]
        finally:
            state.SetAllowEntryContraction(False)
        self.assertEqual(b'a', data[:1])
        self.assertEqual(U_BOOT_DATA, data[1:1 + len(U_BOOT_DATA)])
        self.assertEqual(b'a', data[-1:])

    def testEntryShrinkFail(self):
        """Test not being allowed to contract an entry after it is packed"""
        data = self._DoReadFileDtb('140_entry_shrink.dts', update_dtb=True)[0]

        # In this case there is a spare byte at the end of the data. The size of
        # the contents is only 1 byte but we still have the size before it
        # shrunk.
        self.assertEqual(b'a\0', data[:2])
        self.assertEqual(U_BOOT_DATA, data[2:2 + len(U_BOOT_DATA)])
        self.assertEqual(b'a\0', data[-2:])

    def testDescriptorOffset(self):
        """Test that the Intel descriptor is always placed at at the start"""
        data = self._DoReadFileDtb('141_descriptor_offset.dts')
        image = control.images['image']
        entries = image.GetEntries()
        desc = entries['intel-descriptor']
        self.assertEqual(0xff800000, desc.offset);
        self.assertEqual(0xff800000, desc.image_pos);

    def testReplaceCbfs(self):
        """Test replacing a single file in CBFS without changing the size"""
        self._CheckLz4()
        expected = b'x' * len(U_BOOT_DATA)
        data = self._DoReadFileRealDtb('142_replace_cbfs.dts')
        updated_fname = tools.GetOutputFilename('image-updated.bin')
        tools.WriteFile(updated_fname, data)
        entry_name = 'section/cbfs/u-boot'
        control.WriteEntry(updated_fname, entry_name, expected,
                           allow_resize=True)
        data = control.ReadEntry(updated_fname, entry_name)
        self.assertEqual(expected, data)

    def testReplaceResizeCbfs(self):
        """Test replacing a single file in CBFS with one of a different size"""
        self._CheckLz4()
        expected = U_BOOT_DATA + b'x'
        data = self._DoReadFileRealDtb('142_replace_cbfs.dts')
        updated_fname = tools.GetOutputFilename('image-updated.bin')
        tools.WriteFile(updated_fname, data)
        entry_name = 'section/cbfs/u-boot'
        control.WriteEntry(updated_fname, entry_name, expected,
                           allow_resize=True)
        data = control.ReadEntry(updated_fname, entry_name)
        self.assertEqual(expected, data)

    def _SetupForReplace(self):
        """Set up some files to use to replace entries

        This generates an image, copies it to a new file, extracts all the files
        in it and updates some of them

        Returns:
            List
                Image filename
                Output directory
                Expected values for updated entries, each a string
        """
        data = self._DoReadFileRealDtb('143_replace_all.dts')

        updated_fname = tools.GetOutputFilename('image-updated.bin')
        tools.WriteFile(updated_fname, data)

        outdir = os.path.join(self._indir, 'extract')
        einfos = control.ExtractEntries(updated_fname, None, outdir, [])

        expected1 = b'x' + U_BOOT_DATA + b'y'
        u_boot_fname1 = os.path.join(outdir, 'u-boot')
        tools.WriteFile(u_boot_fname1, expected1)

        expected2 = b'a' + U_BOOT_DATA + b'b'
        u_boot_fname2 = os.path.join(outdir, 'u-boot2')
        tools.WriteFile(u_boot_fname2, expected2)

        expected_text = b'not the same text'
        text_fname = os.path.join(outdir, 'text')
        tools.WriteFile(text_fname, expected_text)

        dtb_fname = os.path.join(outdir, 'u-boot-dtb')
        dtb = fdt.FdtScan(dtb_fname)
        node = dtb.GetNode('/binman/text')
        node.AddString('my-property', 'the value')
        dtb.Sync(auto_resize=True)
        dtb.Flush()

        return updated_fname, outdir, expected1, expected2, expected_text

    def _CheckReplaceMultiple(self, entry_paths):
        """Handle replacing the contents of multiple entries

        Args:
            entry_paths: List of entry paths to replace

        Returns:
            List
                Dict of entries in the image:
                    key: Entry name
                    Value: Entry object
            Expected values for updated entries, each a string
        """
        updated_fname, outdir, expected1, expected2, expected_text = (
            self._SetupForReplace())
        control.ReplaceEntries(updated_fname, None, outdir, entry_paths)

        image = Image.FromFile(updated_fname)
        image.LoadData()
        return image.GetEntries(), expected1, expected2, expected_text

    def testReplaceAll(self):
        """Test replacing the contents of all entries"""
        entries, expected1, expected2, expected_text = (
            self._CheckReplaceMultiple([]))
        data = entries['u-boot'].data
        self.assertEqual(expected1, data)

        data = entries['u-boot2'].data
        self.assertEqual(expected2, data)

        data = entries['text'].data
        self.assertEqual(expected_text, data)

        # Check that the device tree is updated
        data = entries['u-boot-dtb'].data
        dtb = fdt.Fdt.FromData(data)
        dtb.Scan()
        node = dtb.GetNode('/binman/text')
        self.assertEqual('the value', node.props['my-property'].value)

    def testReplaceSome(self):
        """Test replacing the contents of a few entries"""
        entries, expected1, expected2, expected_text = (
            self._CheckReplaceMultiple(['u-boot2', 'text']))

        # This one should not change
        data = entries['u-boot'].data
        self.assertEqual(U_BOOT_DATA, data)

        data = entries['u-boot2'].data
        self.assertEqual(expected2, data)

        data = entries['text'].data
        self.assertEqual(expected_text, data)

    def testReplaceCmd(self):
        """Test replacing a file fron an image on the command line"""
        self._DoReadFileRealDtb('143_replace_all.dts')

        try:
            tmpdir, updated_fname = self._SetupImageInTmpdir()

            fname = os.path.join(tmpdir, 'update-u-boot.bin')
            expected = b'x' * len(U_BOOT_DATA)
            tools.WriteFile(fname, expected)

            self._DoBinman('replace', '-i', updated_fname, 'u-boot', '-f', fname)
            data = tools.ReadFile(updated_fname)
            self.assertEqual(expected, data[:len(expected)])
            map_fname = os.path.join(tmpdir, 'image-updated.map')
            self.assertFalse(os.path.exists(map_fname))
        finally:
            shutil.rmtree(tmpdir)

    def testReplaceCmdSome(self):
        """Test replacing some files fron an image on the command line"""
        updated_fname, outdir, expected1, expected2, expected_text = (
            self._SetupForReplace())

        self._DoBinman('replace', '-i', updated_fname, '-I', outdir,
                       'u-boot2', 'text')

        tools.PrepareOutputDir(None)
        image = Image.FromFile(updated_fname)
        image.LoadData()
        entries = image.GetEntries()

        # This one should not change
        data = entries['u-boot'].data
        self.assertEqual(U_BOOT_DATA, data)

        data = entries['u-boot2'].data
        self.assertEqual(expected2, data)

        data = entries['text'].data
        self.assertEqual(expected_text, data)

    def testReplaceMissing(self):
        """Test replacing entries where the file is missing"""
        updated_fname, outdir, expected1, expected2, expected_text = (
            self._SetupForReplace())

        # Remove one of the files, to generate a warning
        u_boot_fname1 = os.path.join(outdir, 'u-boot')
        os.remove(u_boot_fname1)

        with test_util.capture_sys_output() as (stdout, stderr):
            control.ReplaceEntries(updated_fname, None, outdir, [])
        self.assertIn("Skipping entry '/u-boot' from missing file",
                      stderr.getvalue())

    def testReplaceCmdMap(self):
        """Test replacing a file fron an image on the command line"""
        self._DoReadFileRealDtb('143_replace_all.dts')

        try:
            tmpdir, updated_fname = self._SetupImageInTmpdir()

            fname = os.path.join(self._indir, 'update-u-boot.bin')
            expected = b'x' * len(U_BOOT_DATA)
            tools.WriteFile(fname, expected)

            self._DoBinman('replace', '-i', updated_fname, 'u-boot',
                           '-f', fname, '-m')
            map_fname = os.path.join(tmpdir, 'image-updated.map')
            self.assertTrue(os.path.exists(map_fname))
        finally:
            shutil.rmtree(tmpdir)

    def testReplaceNoEntryPaths(self):
        """Test replacing an entry without an entry path"""
        self._DoReadFileRealDtb('143_replace_all.dts')
        image_fname = tools.GetOutputFilename('image.bin')
        with self.assertRaises(ValueError) as e:
            control.ReplaceEntries(image_fname, 'fname', None, [])
        self.assertIn('Must specify an entry path to read with -f',
                      str(e.exception))

    def testReplaceTooManyEntryPaths(self):
        """Test extracting some entries"""
        self._DoReadFileRealDtb('143_replace_all.dts')
        image_fname = tools.GetOutputFilename('image.bin')
        with self.assertRaises(ValueError) as e:
            control.ReplaceEntries(image_fname, 'fname', None, ['a', 'b'])
        self.assertIn('Must specify exactly one entry path to write with -f',
                      str(e.exception))

    def testPackReset16(self):
        """Test that an image with an x86 reset16 region can be created"""
        data = self._DoReadFile('144_x86_reset16.dts')
        self.assertEqual(X86_RESET16_DATA, data[:len(X86_RESET16_DATA)])

    def testPackReset16Spl(self):
        """Test that an image with an x86 reset16-spl region can be created"""
        data = self._DoReadFile('145_x86_reset16_spl.dts')
        self.assertEqual(X86_RESET16_SPL_DATA, data[:len(X86_RESET16_SPL_DATA)])

    def testPackReset16Tpl(self):
        """Test that an image with an x86 reset16-tpl region can be created"""
        data = self._DoReadFile('146_x86_reset16_tpl.dts')
        self.assertEqual(X86_RESET16_TPL_DATA, data[:len(X86_RESET16_TPL_DATA)])

    def testPackIntelFit(self):
        """Test that an image with an Intel FIT and pointer can be created"""
        data = self._DoReadFile('147_intel_fit.dts')
        self.assertEqual(U_BOOT_DATA, data[:len(U_BOOT_DATA)])
        fit = data[16:32];
        self.assertEqual(b'_FIT_   \x01\x00\x00\x00\x00\x01\x80}' , fit)
        ptr = struct.unpack('<i', data[0x40:0x44])[0]

        image = control.images['image']
        entries = image.GetEntries()
        expected_ptr = entries['intel-fit'].image_pos - (1 << 32)
        self.assertEqual(expected_ptr, ptr)

    def testPackIntelFitMissing(self):
        """Test detection of a FIT pointer with not FIT region"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('148_intel_fit_missing.dts')
        self.assertIn("'intel-fit-ptr' section must have an 'intel-fit' sibling",
                      str(e.exception))

    def _CheckSymbolsTplSection(self, dts, expected_vals):
        data = self._DoReadFile(dts)
        sym_values = struct.pack('<LQLL', *expected_vals)
        upto1 = 4 + len(U_BOOT_SPL_DATA)
        expected1 = tools.GetBytes(0xff, 4) + sym_values + U_BOOT_SPL_DATA[20:]
        self.assertEqual(expected1, data[:upto1])

        upto2 = upto1 + 1 + len(U_BOOT_SPL_DATA)
        expected2 = tools.GetBytes(0xff, 1) + sym_values + U_BOOT_SPL_DATA[20:]
        self.assertEqual(expected2, data[upto1:upto2])

        upto3 = 0x34 + len(U_BOOT_DATA)
        expected3 = tools.GetBytes(0xff, 1) + U_BOOT_DATA
        self.assertEqual(expected3, data[upto2:upto3])

        expected4 = sym_values + U_BOOT_TPL_DATA[20:]
        self.assertEqual(expected4, data[upto3:upto3 + len(U_BOOT_TPL_DATA)])

    def testSymbolsTplSection(self):
        """Test binman can assign symbols embedded in U-Boot TPL in a section"""
        self._SetupSplElf('u_boot_binman_syms')
        self._SetupTplElf('u_boot_binman_syms')
        self._CheckSymbolsTplSection('149_symbols_tpl.dts',
                                     [0x04, 0x1c, 0x10 + 0x34, 0x04])

    def testSymbolsTplSectionX86(self):
        """Test binman can assign symbols in a section with end-at-4gb"""
        self._SetupSplElf('u_boot_binman_syms_x86')
        self._SetupTplElf('u_boot_binman_syms_x86')
        self._CheckSymbolsTplSection('155_symbols_tpl_x86.dts',
                                     [0xffffff04, 0xffffff1c, 0xffffff34,
                                      0x04])

    def testPackX86RomIfwiSectiom(self):
        """Test that a section can be placed in an IFWI region"""
        self._SetupIfwi('fitimage.bin')
        data = self._DoReadFile('151_x86_rom_ifwi_section.dts')
        self._CheckIfwi(data)

    def testPackFspM(self):
        """Test that an image with a FSP memory-init binary can be created"""
        data = self._DoReadFile('152_intel_fsp_m.dts')
        self.assertEqual(FSP_M_DATA, data[:len(FSP_M_DATA)])

    def testPackFspS(self):
        """Test that an image with a FSP silicon-init binary can be created"""
        data = self._DoReadFile('153_intel_fsp_s.dts')
        self.assertEqual(FSP_S_DATA, data[:len(FSP_S_DATA)])

    def testPackFspT(self):
        """Test that an image with a FSP temp-ram-init binary can be created"""
        data = self._DoReadFile('154_intel_fsp_t.dts')
        self.assertEqual(FSP_T_DATA, data[:len(FSP_T_DATA)])

    def testMkimage(self):
        """Test using mkimage to build an image"""
        data = self._DoReadFile('156_mkimage.dts')

        # Just check that the data appears in the file somewhere
        self.assertIn(U_BOOT_SPL_DATA, data)

    def testExtblob(self):
        """Test an image with an external blob"""
        data = self._DoReadFile('157_blob_ext.dts')
        self.assertEqual(REFCODE_DATA, data)

    def testExtblobMissing(self):
        """Test an image with a missing external blob"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('158_blob_ext_missing.dts')
        self.assertIn("Filename 'missing-file' not found in input path",
                      str(e.exception))

    def testExtblobMissingOk(self):
        """Test an image with an missing external blob that is allowed"""
        with test_util.capture_sys_output() as (stdout, stderr):
            self._DoTestFile('158_blob_ext_missing.dts', allow_missing=True)
        err = stderr.getvalue()
        self.assertRegex(err, "Image 'main-section'.*missing.*: blob-ext")

    def testExtblobMissingOkSect(self):
        """Test an image with an missing external blob that is allowed"""
        with test_util.capture_sys_output() as (stdout, stderr):
            self._DoTestFile('159_blob_ext_missing_sect.dts',
                             allow_missing=True)
        err = stderr.getvalue()
        self.assertRegex(err, "Image 'main-section'.*missing.*: "
                         "blob-ext blob-ext2")

    def testPackX86RomMeMissingDesc(self):
        """Test that an missing Intel descriptor entry is allowed"""
        with test_util.capture_sys_output() as (stdout, stderr):
            self._DoTestFile('164_x86_rom_me_missing.dts', allow_missing=True)
        err = stderr.getvalue()
        self.assertRegex(err,
                         "Image 'main-section'.*missing.*: intel-descriptor")

    def testPackX86RomMissingIfwi(self):
        """Test that an x86 ROM with Integrated Firmware Image can be created"""
        self._SetupIfwi('fitimage.bin')
        pathname = os.path.join(self._indir, 'fitimage.bin')
        os.remove(pathname)
        with test_util.capture_sys_output() as (stdout, stderr):
            self._DoTestFile('111_x86_rom_ifwi.dts', allow_missing=True)
        err = stderr.getvalue()
        self.assertRegex(err, "Image 'main-section'.*missing.*: intel-ifwi")

    def testPackOverlap(self):
        """Test that zero-size overlapping regions are ignored"""
        self._DoTestFile('160_pack_overlap_zero.dts')

    def testSimpleFit(self):
        """Test an image with a FIT inside"""
        data = self._DoReadFile('161_fit.dts')
        self.assertEqual(U_BOOT_DATA, data[:len(U_BOOT_DATA)])
        self.assertEqual(U_BOOT_NODTB_DATA, data[-len(U_BOOT_NODTB_DATA):])
        fit_data = data[len(U_BOOT_DATA):-len(U_BOOT_NODTB_DATA)]

        # The data should be inside the FIT
        dtb = fdt.Fdt.FromData(fit_data)
        dtb.Scan()
        fnode = dtb.GetNode('/images/kernel')
        self.assertIn('data', fnode.props)

        fname = os.path.join(self._indir, 'fit_data.fit')
        tools.WriteFile(fname, fit_data)
        out = tools.Run('dumpimage', '-l', fname)

        # Check a few features to make sure the plumbing works. We don't need
        # to test the operation of mkimage or dumpimage here. First convert the
        # output into a dict where the keys are the fields printed by dumpimage
        # and the values are a list of values for each field
        lines = out.splitlines()

        # Converts "Compression:  gzip compressed" into two groups:
        # 'Compression' and 'gzip compressed'
        re_line = re.compile(r'^ *([^:]*)(?:: *(.*))?$')
        vals = collections.defaultdict(list)
        for line in lines:
            mat = re_line.match(line)
            vals[mat.group(1)].append(mat.group(2))

        self.assertEquals('FIT description: test-desc', lines[0])
        self.assertIn('Created:', lines[1])
        self.assertIn('Image 0 (kernel)', vals)
        self.assertIn('Hash value', vals)
        data_sizes = vals.get('Data Size')
        self.assertIsNotNone(data_sizes)
        self.assertEqual(2, len(data_sizes))
        # Format is "4 Bytes = 0.00 KiB = 0.00 MiB" so take the first word
        self.assertEqual(len(U_BOOT_DATA), int(data_sizes[0].split()[0]))
        self.assertEqual(len(U_BOOT_SPL_DTB_DATA), int(data_sizes[1].split()[0]))

    def testFitExternal(self):
        """Test an image with an FIT with external images"""
        data = self._DoReadFile('162_fit_external.dts')
        fit_data = data[len(U_BOOT_DATA):-2]  # _testing is 2 bytes

        # The data should be outside the FIT
        dtb = fdt.Fdt.FromData(fit_data)
        dtb.Scan()
        fnode = dtb.GetNode('/images/kernel')
        self.assertNotIn('data', fnode.props)

    def testSectionIgnoreHashSignature(self):
        """Test that sections ignore hash, signature nodes for its data"""
        data = self._DoReadFile('165_section_ignore_hash_signature.dts')
        expected = (U_BOOT_DATA + U_BOOT_DATA)
        self.assertEqual(expected, data)

    def testPadInSections(self):
        """Test pad-before, pad-after for entries in sections"""
        data, _, _, out_dtb_fname = self._DoReadFileDtb(
            '166_pad_in_sections.dts', update_dtb=True)
        expected = (U_BOOT_DATA + tools.GetBytes(ord('!'), 12) +
                    U_BOOT_DATA + tools.GetBytes(ord('!'), 6) +
                    U_BOOT_DATA)
        self.assertEqual(expected, data)

        dtb = fdt.Fdt(out_dtb_fname)
        dtb.Scan()
        props = self._GetPropTree(dtb, ['size', 'image-pos', 'offset'])
        expected = {
            'image-pos': 0,
            'offset': 0,
            'size': 12 + 6 + 3 * len(U_BOOT_DATA),

            'section:image-pos': 0,
            'section:offset': 0,
            'section:size': 12 + 6 + 3 * len(U_BOOT_DATA),

            'section/before:image-pos': 0,
            'section/before:offset': 0,
            'section/before:size': len(U_BOOT_DATA),

            'section/u-boot:image-pos': 4,
            'section/u-boot:offset': 4,
            'section/u-boot:size': 12 + len(U_BOOT_DATA) + 6,

            'section/after:image-pos': 26,
            'section/after:offset': 26,
            'section/after:size': len(U_BOOT_DATA),
            }
        self.assertEqual(expected, props)

    def testFitImageSubentryAlignment(self):
        """Test relative alignability of FIT image subentries"""
        entry_args = {
            'test-id': TEXT_DATA,
        }
        data, _, _, _ = self._DoReadFileDtb('167_fit_image_subentry_alignment.dts',
                                            entry_args=entry_args)
        dtb = fdt.Fdt.FromData(data)
        dtb.Scan()

        node = dtb.GetNode('/images/kernel')
        data = dtb.GetProps(node)["data"].bytes
        align_pad = 0x10 - (len(U_BOOT_SPL_DATA) % 0x10)
        expected = (tools.GetBytes(0, 0x20) + U_BOOT_SPL_DATA +
                    tools.GetBytes(0, align_pad) + U_BOOT_DATA)
        self.assertEqual(expected, data)

        node = dtb.GetNode('/images/fdt-1')
        data = dtb.GetProps(node)["data"].bytes
        expected = (U_BOOT_SPL_DTB_DATA + tools.GetBytes(0, 20) +
                    tools.ToBytes(TEXT_DATA) + tools.GetBytes(0, 30) +
                    U_BOOT_DTB_DATA)
        self.assertEqual(expected, data)

    def testFitExtblobMissingOk(self):
        """Test a FIT with a missing external blob that is allowed"""
        with test_util.capture_sys_output() as (stdout, stderr):
            self._DoTestFile('168_fit_missing_blob.dts',
                             allow_missing=True)
        err = stderr.getvalue()
        self.assertRegex(err, "Image 'main-section'.*missing.*: atf-bl31")

    def testBlobNamedByArgMissing(self):
        """Test handling of a missing entry arg"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('068_blob_named_by_arg.dts')
        self.assertIn("Missing required properties/entry args: cros-ec-rw-path",
                      str(e.exception))

    def testPackBl31(self):
        """Test that an image with an ATF BL31 binary can be created"""
        data = self._DoReadFile('169_atf_bl31.dts')
        self.assertEqual(ATF_BL31_DATA, data[:len(ATF_BL31_DATA)])

    def testPackScp(self):
        """Test that an image with an SCP binary can be created"""
        data = self._DoReadFile('172_scp.dts')
        self.assertEqual(SCP_DATA, data[:len(SCP_DATA)])

    def testFitFdt(self):
        """Test an image with an FIT with multiple FDT images"""
        def _CheckFdt(seq, expected_data):
            """Check the FDT nodes

            Args:
                seq: Sequence number to check (0 or 1)
                expected_data: Expected contents of 'data' property
            """
            name = 'fdt-%d' % seq
            fnode = dtb.GetNode('/images/%s' % name)
            self.assertIsNotNone(fnode)
            self.assertEqual({'description','type', 'compression', 'data'},
                             set(fnode.props.keys()))
            self.assertEqual(expected_data, fnode.props['data'].bytes)
            self.assertEqual('fdt-test-fdt%d.dtb' % seq,
                             fnode.props['description'].value)

        def _CheckConfig(seq, expected_data):
            """Check the configuration nodes

            Args:
                seq: Sequence number to check (0 or 1)
                expected_data: Expected contents of 'data' property
            """
            cnode = dtb.GetNode('/configurations')
            self.assertIn('default', cnode.props)
            self.assertEqual('config-2', cnode.props['default'].value)

            name = 'config-%d' % seq
            fnode = dtb.GetNode('/configurations/%s' % name)
            self.assertIsNotNone(fnode)
            self.assertEqual({'description','firmware', 'loadables', 'fdt'},
                             set(fnode.props.keys()))
            self.assertEqual('conf-test-fdt%d.dtb' % seq,
                             fnode.props['description'].value)
            self.assertEqual('fdt-%d' % seq, fnode.props['fdt'].value)

        entry_args = {
            'of-list': 'test-fdt1 test-fdt2',
            'default-dt': 'test-fdt2',
        }
        data = self._DoReadFileDtb(
            '170_fit_fdt.dts',
            entry_args=entry_args,
            extra_indirs=[os.path.join(self._indir, TEST_FDT_SUBDIR)])[0]
        self.assertEqual(U_BOOT_NODTB_DATA, data[-len(U_BOOT_NODTB_DATA):])
        fit_data = data[len(U_BOOT_DATA):-len(U_BOOT_NODTB_DATA)]

        dtb = fdt.Fdt.FromData(fit_data)
        dtb.Scan()
        fnode = dtb.GetNode('/images/kernel')
        self.assertIn('data', fnode.props)

        # Check all the properties in fdt-1 and fdt-2
        _CheckFdt(1, TEST_FDT1_DATA)
        _CheckFdt(2, TEST_FDT2_DATA)

        # Check configurations
        _CheckConfig(1, TEST_FDT1_DATA)
        _CheckConfig(2, TEST_FDT2_DATA)

    def testFitFdtMissingList(self):
        """Test handling of a missing 'of-list' entry arg"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('170_fit_fdt.dts')
        self.assertIn("Generator node requires 'of-list' entry argument",
                      str(e.exception))

    def testFitFdtEmptyList(self):
        """Test handling of an empty 'of-list' entry arg"""
        entry_args = {
            'of-list': '',
        }
        data = self._DoReadFileDtb('170_fit_fdt.dts', entry_args=entry_args)[0]

    def testFitFdtMissingProp(self):
        """Test handling of a missing 'fit,fdt-list' property"""
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('171_fit_fdt_missing_prop.dts')
        self.assertIn("Generator node requires 'fit,fdt-list' property",
                      str(e.exception))

    def testFitFdtEmptyList(self):
        """Test handling of an empty 'of-list' entry arg"""
        entry_args = {
            'of-list': '',
        }
        data = self._DoReadFileDtb('170_fit_fdt.dts', entry_args=entry_args)[0]

    def testFitFdtMissing(self):
        """Test handling of a missing 'default-dt' entry arg"""
        entry_args = {
            'of-list': 'test-fdt1 test-fdt2',
        }
        with self.assertRaises(ValueError) as e:
            self._DoReadFileDtb(
                '170_fit_fdt.dts',
                entry_args=entry_args,
                extra_indirs=[os.path.join(self._indir, TEST_FDT_SUBDIR)])[0]
        self.assertIn("Generated 'default' node requires default-dt entry argument",
                      str(e.exception))

    def testFitFdtNotInList(self):
        """Test handling of a default-dt that is not in the of-list"""
        entry_args = {
            'of-list': 'test-fdt1 test-fdt2',
            'default-dt': 'test-fdt3',
        }
        with self.assertRaises(ValueError) as e:
            self._DoReadFileDtb(
                '170_fit_fdt.dts',
                entry_args=entry_args,
                extra_indirs=[os.path.join(self._indir, TEST_FDT_SUBDIR)])[0]
        self.assertIn("default-dt entry argument 'test-fdt3' not found in fdt list: test-fdt1, test-fdt2",
                      str(e.exception))

    def testFitExtblobMissingHelp(self):
        """Test display of help messages when an external blob is missing"""
        control.missing_blob_help = control._ReadMissingBlobHelp()
        control.missing_blob_help['wibble'] = 'Wibble test'
        control.missing_blob_help['another'] = 'Another test'
        with test_util.capture_sys_output() as (stdout, stderr):
            self._DoTestFile('168_fit_missing_blob.dts',
                             allow_missing=True)
        err = stderr.getvalue()

        # We can get the tag from the name, the type or the missing-msg
        # property. Check all three.
        self.assertIn('You may need to build ARM Trusted', err)
        self.assertIn('Wibble test', err)
        self.assertIn('Another test', err)

    def testMissingBlob(self):
        """Test handling of a blob containing a missing file"""
        with self.assertRaises(ValueError) as e:
            self._DoTestFile('173_missing_blob.dts', allow_missing=True)
        self.assertIn("Filename 'missing' not found in input path",
                      str(e.exception))

    def testEnvironment(self):
        """Test adding a U-Boot environment"""
        data = self._DoReadFile('174_env.dts')
        self.assertEqual(U_BOOT_DATA, data[:len(U_BOOT_DATA)])
        self.assertEqual(U_BOOT_NODTB_DATA, data[-len(U_BOOT_NODTB_DATA):])
        env = data[len(U_BOOT_DATA):-len(U_BOOT_NODTB_DATA)]
        self.assertEqual(b'\x1b\x97\x22\x7c\x01var1=1\0var2="2"\0\0\xff\xff',
                         env)

    def testEnvironmentNoSize(self):
        """Test that a missing 'size' property is detected"""
        with self.assertRaises(ValueError) as e:
            self._DoTestFile('175_env_no_size.dts')
        self.assertIn("'u-boot-env' entry must have a size property",
                      str(e.exception))

    def testEnvironmentTooSmall(self):
        """Test handling of an environment that does not fit"""
        with self.assertRaises(ValueError) as e:
            self._DoTestFile('176_env_too_small.dts')

        # checksum, start byte, environment with \0 terminator, final \0
        need = 4 + 1 + len(ENV_DATA) + 1 + 1
        short = need - 0x8
        self.assertIn("too small to hold data (need %#x more bytes)" % short,
                      str(e.exception))

    def testSkipAtStart(self):
        """Test handling of skip-at-start section"""
        data = self._DoReadFile('177_skip_at_start.dts')
        self.assertEqual(U_BOOT_DATA, data)

        image = control.images['image']
        entries = image.GetEntries()
        section = entries['section']
        self.assertEqual(0, section.offset)
        self.assertEqual(len(U_BOOT_DATA), section.size)
        self.assertEqual(U_BOOT_DATA, section.GetData())

        entry = section.GetEntries()['u-boot']
        self.assertEqual(16, entry.offset)
        self.assertEqual(len(U_BOOT_DATA), entry.size)
        self.assertEqual(U_BOOT_DATA, entry.data)

    def testSkipAtStartPad(self):
        """Test handling of skip-at-start section with padded entry"""
        data = self._DoReadFile('178_skip_at_start_pad.dts')
        before = tools.GetBytes(0, 8)
        after = tools.GetBytes(0, 4)
        all = before + U_BOOT_DATA + after
        self.assertEqual(all, data)

        image = control.images['image']
        entries = image.GetEntries()
        section = entries['section']
        self.assertEqual(0, section.offset)
        self.assertEqual(len(all), section.size)
        self.assertEqual(all, section.GetData())

        entry = section.GetEntries()['u-boot']
        self.assertEqual(16, entry.offset)
        self.assertEqual(len(all), entry.size)
        self.assertEqual(U_BOOT_DATA, entry.data)

    def testSkipAtStartSectionPad(self):
        """Test handling of skip-at-start section with padding"""
        data = self._DoReadFile('179_skip_at_start_section_pad.dts')
        before = tools.GetBytes(0, 8)
        after = tools.GetBytes(0, 4)
        all = before + U_BOOT_DATA + after
        self.assertEqual(all, data)

        image = control.images['image']
        entries = image.GetEntries()
        section = entries['section']
        self.assertEqual(0, section.offset)
        self.assertEqual(len(all), section.size)
        self.assertEqual(U_BOOT_DATA, section.data)
        self.assertEqual(all, section.GetPaddedData())

        entry = section.GetEntries()['u-boot']
        self.assertEqual(16, entry.offset)
        self.assertEqual(len(U_BOOT_DATA), entry.size)
        self.assertEqual(U_BOOT_DATA, entry.data)

    def testSectionPad(self):
        """Testing padding with sections"""
        data = self._DoReadFile('180_section_pad.dts')
        expected = (tools.GetBytes(ord('&'), 3) +
                    tools.GetBytes(ord('!'), 5) +
                    U_BOOT_DATA +
                    tools.GetBytes(ord('!'), 1) +
                    tools.GetBytes(ord('&'), 2))
        self.assertEqual(expected, data)

    def testSectionAlign(self):
        """Testing alignment with sections"""
        data = self._DoReadFileDtb('181_section_align.dts', map=True)[0]
        expected = (b'\0' +                         # fill section
                    tools.GetBytes(ord('&'), 1) +   # padding to section align
                    b'\0' +                         # fill section
                    tools.GetBytes(ord('!'), 3) +   # padding to u-boot align
                    U_BOOT_DATA +
                    tools.GetBytes(ord('!'), 4) +   # padding to u-boot size
                    tools.GetBytes(ord('!'), 4))    # padding to section size
        self.assertEqual(expected, data)

    def testCompressImage(self):
        """Test compression of the entire image"""
        self._CheckLz4()
        data, _, _, out_dtb_fname = self._DoReadFileDtb(
            '182_compress_image.dts', use_real_dtb=True, update_dtb=True)
        dtb = fdt.Fdt(out_dtb_fname)
        dtb.Scan()
        props = self._GetPropTree(dtb, ['offset', 'image-pos', 'size',
                                        'uncomp-size'])
        orig = self._decompress(data)
        self.assertEquals(COMPRESS_DATA + U_BOOT_DATA, orig)

        # Do a sanity check on various fields
        image = control.images['image']
        entries = image.GetEntries()
        self.assertEqual(2, len(entries))

        entry = entries['blob']
        self.assertEqual(COMPRESS_DATA, entry.data)
        self.assertEqual(len(COMPRESS_DATA), entry.size)

        entry = entries['u-boot']
        self.assertEqual(U_BOOT_DATA, entry.data)
        self.assertEqual(len(U_BOOT_DATA), entry.size)

        self.assertEqual(len(data), image.size)
        self.assertEqual(COMPRESS_DATA + U_BOOT_DATA, image.uncomp_data)
        self.assertEqual(len(COMPRESS_DATA + U_BOOT_DATA), image.uncomp_size)
        orig = self._decompress(image.data)
        self.assertEqual(orig, image.uncomp_data)

        expected = {
            'blob:offset': 0,
            'blob:size': len(COMPRESS_DATA),
            'u-boot:offset': len(COMPRESS_DATA),
            'u-boot:size': len(U_BOOT_DATA),
            'uncomp-size': len(COMPRESS_DATA + U_BOOT_DATA),
            'offset': 0,
            'image-pos': 0,
            'size': len(data),
            }
        self.assertEqual(expected, props)

    def testCompressImageLess(self):
        """Test compression where compression reduces the image size"""
        self._CheckLz4()
        data, _, _, out_dtb_fname = self._DoReadFileDtb(
            '183_compress_image_less.dts', use_real_dtb=True, update_dtb=True)
        dtb = fdt.Fdt(out_dtb_fname)
        dtb.Scan()
        props = self._GetPropTree(dtb, ['offset', 'image-pos', 'size',
                                        'uncomp-size'])
        orig = self._decompress(data)

        self.assertEquals(COMPRESS_DATA + COMPRESS_DATA + U_BOOT_DATA, orig)

        # Do a sanity check on various fields
        image = control.images['image']
        entries = image.GetEntries()
        self.assertEqual(2, len(entries))

        entry = entries['blob']
        self.assertEqual(COMPRESS_DATA_BIG, entry.data)
        self.assertEqual(len(COMPRESS_DATA_BIG), entry.size)

        entry = entries['u-boot']
        self.assertEqual(U_BOOT_DATA, entry.data)
        self.assertEqual(len(U_BOOT_DATA), entry.size)

        self.assertEqual(len(data), image.size)
        self.assertEqual(COMPRESS_DATA_BIG + U_BOOT_DATA, image.uncomp_data)
        self.assertEqual(len(COMPRESS_DATA_BIG + U_BOOT_DATA),
                         image.uncomp_size)
        orig = self._decompress(image.data)
        self.assertEqual(orig, image.uncomp_data)

        expected = {
            'blob:offset': 0,
            'blob:size': len(COMPRESS_DATA_BIG),
            'u-boot:offset': len(COMPRESS_DATA_BIG),
            'u-boot:size': len(U_BOOT_DATA),
            'uncomp-size': len(COMPRESS_DATA_BIG + U_BOOT_DATA),
            'offset': 0,
            'image-pos': 0,
            'size': len(data),
            }
        self.assertEqual(expected, props)

    def testCompressSectionSize(self):
        """Test compression of a section with a fixed size"""
        self._CheckLz4()
        data, _, _, out_dtb_fname = self._DoReadFileDtb(
            '184_compress_section_size.dts', use_real_dtb=True, update_dtb=True)
        dtb = fdt.Fdt(out_dtb_fname)
        dtb.Scan()
        props = self._GetPropTree(dtb, ['offset', 'image-pos', 'size',
                                        'uncomp-size'])
        orig = self._decompress(data)
        self.assertEquals(COMPRESS_DATA + U_BOOT_DATA, orig)
        expected = {
            'section/blob:offset': 0,
            'section/blob:size': len(COMPRESS_DATA),
            'section/u-boot:offset': len(COMPRESS_DATA),
            'section/u-boot:size': len(U_BOOT_DATA),
            'section:offset': 0,
            'section:image-pos': 0,
            'section:uncomp-size': len(COMPRESS_DATA + U_BOOT_DATA),
            'section:size': 0x30,
            'offset': 0,
            'image-pos': 0,
            'size': 0x30,
            }
        self.assertEqual(expected, props)

    def testCompressSection(self):
        """Test compression of a section with no fixed size"""
        self._CheckLz4()
        data, _, _, out_dtb_fname = self._DoReadFileDtb(
            '185_compress_section.dts', use_real_dtb=True, update_dtb=True)
        dtb = fdt.Fdt(out_dtb_fname)
        dtb.Scan()
        props = self._GetPropTree(dtb, ['offset', 'image-pos', 'size',
                                        'uncomp-size'])
        orig = self._decompress(data)
        self.assertEquals(COMPRESS_DATA + U_BOOT_DATA, orig)
        expected = {
            'section/blob:offset': 0,
            'section/blob:size': len(COMPRESS_DATA),
            'section/u-boot:offset': len(COMPRESS_DATA),
            'section/u-boot:size': len(U_BOOT_DATA),
            'section:offset': 0,
            'section:image-pos': 0,
            'section:uncomp-size': len(COMPRESS_DATA + U_BOOT_DATA),
            'section:size': len(data),
            'offset': 0,
            'image-pos': 0,
            'size': len(data),
            }
        self.assertEqual(expected, props)

    def testCompressExtra(self):
        """Test compression of a section with no fixed size"""
        self._CheckLz4()
        data, _, _, out_dtb_fname = self._DoReadFileDtb(
            '186_compress_extra.dts', use_real_dtb=True, update_dtb=True)
        dtb = fdt.Fdt(out_dtb_fname)
        dtb.Scan()
        props = self._GetPropTree(dtb, ['offset', 'image-pos', 'size',
                                        'uncomp-size'])

        base = data[len(U_BOOT_DATA):]
        self.assertEquals(U_BOOT_DATA, base[:len(U_BOOT_DATA)])
        rest = base[len(U_BOOT_DATA):]

        # Check compressed data
        section1 = self._decompress(rest)
        expect1 = tools.Compress(COMPRESS_DATA + U_BOOT_DATA, 'lz4')
        self.assertEquals(expect1, rest[:len(expect1)])
        self.assertEquals(COMPRESS_DATA + U_BOOT_DATA, section1)
        rest1 = rest[len(expect1):]

        section2 = self._decompress(rest1)
        expect2 = tools.Compress(COMPRESS_DATA + COMPRESS_DATA, 'lz4')
        self.assertEquals(expect2, rest1[:len(expect2)])
        self.assertEquals(COMPRESS_DATA + COMPRESS_DATA, section2)
        rest2 = rest1[len(expect2):]

        expect_size = (len(U_BOOT_DATA) + len(U_BOOT_DATA) + len(expect1) +
                       len(expect2) + len(U_BOOT_DATA))
        #self.assertEquals(expect_size, len(data))

        #self.assertEquals(U_BOOT_DATA, rest2)

        self.maxDiff = None
        expected = {
            'u-boot:offset': 0,
            'u-boot:image-pos': 0,
            'u-boot:size': len(U_BOOT_DATA),

            'base:offset': len(U_BOOT_DATA),
            'base:image-pos': len(U_BOOT_DATA),
            'base:size': len(data) - len(U_BOOT_DATA),
            'base/u-boot:offset': 0,
            'base/u-boot:image-pos': len(U_BOOT_DATA),
            'base/u-boot:size': len(U_BOOT_DATA),
            'base/u-boot2:offset': len(U_BOOT_DATA) + len(expect1) +
                len(expect2),
            'base/u-boot2:image-pos': len(U_BOOT_DATA) * 2 + len(expect1) +
                len(expect2),
            'base/u-boot2:size': len(U_BOOT_DATA),

            'base/section:offset': len(U_BOOT_DATA),
            'base/section:image-pos': len(U_BOOT_DATA) * 2,
            'base/section:size': len(expect1),
            'base/section:uncomp-size': len(COMPRESS_DATA + U_BOOT_DATA),
            'base/section/blob:offset': 0,
            'base/section/blob:size': len(COMPRESS_DATA),
            'base/section/u-boot:offset': len(COMPRESS_DATA),
            'base/section/u-boot:size': len(U_BOOT_DATA),

            'base/section2:offset': len(U_BOOT_DATA) + len(expect1),
            'base/section2:image-pos': len(U_BOOT_DATA) * 2 + len(expect1),
            'base/section2:size': len(expect2),
            'base/section2:uncomp-size': len(COMPRESS_DATA + COMPRESS_DATA),
            'base/section2/blob:offset': 0,
            'base/section2/blob:size': len(COMPRESS_DATA),
            'base/section2/blob2:offset': len(COMPRESS_DATA),
            'base/section2/blob2:size': len(COMPRESS_DATA),

            'offset': 0,
            'image-pos': 0,
            'size': len(data),
            }
        self.assertEqual(expected, props)

    def testSymbolsSubsection(self):
        """Test binman can assign symbols from a subsection"""
        self.checkSymbols('187_symbols_sub.dts', U_BOOT_SPL_DATA, 0x18)

    def testReadImageEntryArg(self):
        """Test reading an image that would need an entry arg to generate"""
        entry_args = {
            'cros-ec-rw-path': 'ecrw.bin',
        }
        data = self.data = self._DoReadFileDtb(
            '188_image_entryarg.dts',use_real_dtb=True, update_dtb=True,
            entry_args=entry_args)

        image_fname = tools.GetOutputFilename('image.bin')
        orig_image = control.images['image']

        # This should not generate an error about the missing 'cros-ec-rw-path'
        # since we are reading the image from a file. Compare with
        # testEntryArgsRequired()
        image = Image.FromFile(image_fname)
        self.assertEqual(orig_image.GetEntries().keys(),
                         image.GetEntries().keys())

    def testFilesAlign(self):
        """Test alignment with files"""
        data = self._DoReadFile('190_files_align.dts')

        # The first string is 15 bytes so will align to 16
        expect = FILES_DATA[:15] + b'\0' + FILES_DATA[15:]
        self.assertEqual(expect, data)

    def testReadImageSkip(self):
        """Test reading an image and accessing its FDT map"""
        data = self.data = self._DoReadFileRealDtb('191_read_image_skip.dts')
        image_fname = tools.GetOutputFilename('image.bin')
        orig_image = control.images['image']
        image = Image.FromFile(image_fname)
        self.assertEqual(orig_image.GetEntries().keys(),
                         image.GetEntries().keys())

        orig_entry = orig_image.GetEntries()['fdtmap']
        entry = image.GetEntries()['fdtmap']
        self.assertEqual(orig_entry.offset, entry.offset)
        self.assertEqual(orig_entry.size, entry.size)
        self.assertEqual(16, entry.image_pos)

        u_boot = image.GetEntries()['section'].GetEntries()['u-boot']

        self.assertEquals(U_BOOT_DATA, u_boot.ReadData())

    def testTplNoDtb(self):
        """Test that an image with tpl/u-boot-tpl-nodtb.bin can be created"""
        self._SetupTplElf()
        data = self._DoReadFile('192_u_boot_tpl_nodtb.dts')
        self.assertEqual(U_BOOT_TPL_NODTB_DATA,
                         data[:len(U_BOOT_TPL_NODTB_DATA)])

    def testTplBssPad(self):
        """Test that we can pad TPL's BSS with zeros"""
        # ELF file with a '__bss_size' symbol
        self._SetupTplElf()
        data = self._DoReadFile('193_tpl_bss_pad.dts')
        self.assertEqual(U_BOOT_TPL_DATA + tools.GetBytes(0, 10) + U_BOOT_DATA,
                         data)

    def testTplBssPadMissing(self):
        """Test that a missing symbol is detected"""
        self._SetupTplElf('u_boot_ucode_ptr')
        with self.assertRaises(ValueError) as e:
            self._DoReadFile('193_tpl_bss_pad.dts')
        self.assertIn('Expected __bss_size symbol in tpl/u-boot-tpl',
                      str(e.exception))

    def checkDtbSizes(self, data, pad_len, start):
        """Check the size arguments in a dtb embedded in an image

        Args:
            data: The image data
            pad_len: Length of the pad section in the image, in bytes
            start: Start offset of the devicetree to examine, within the image

        Returns:
            Size of the devicetree in bytes
        """
        dtb_data = data[start:]
        dtb = fdt.Fdt.FromData(dtb_data)
        fdt_size = dtb.GetFdtObj().totalsize()
        dtb.Scan()
        props = self._GetPropTree(dtb, 'size')
        self.assertEqual({
            'size': len(data),
            'u-boot-spl/u-boot-spl-bss-pad:size': pad_len,
            'u-boot-spl/u-boot-spl-dtb:size': 801,
            'u-boot-spl/u-boot-spl-nodtb:size': len(U_BOOT_SPL_NODTB_DATA),
            'u-boot-spl:size': 860,
            'u-boot-tpl:size': len(U_BOOT_TPL_DATA),
            'u-boot/u-boot-dtb:size': 781,
            'u-boot/u-boot-nodtb:size': len(U_BOOT_NODTB_DATA),
            'u-boot:size': 827,
            }, props)
        return fdt_size

    def testExpanded(self):
        """Test that an expanded entry type is selected when needed"""
        self._SetupSplElf()
        self._SetupTplElf()

        # SPL has a devicetree, TPL does not
        entry_args = {
            'spl-dtb': '1',
            'spl-bss-pad': 'y',
            'tpl-dtb': '',
        }
        self._DoReadFileDtb('194_fdt_incl.dts', use_expanded=True,
                            entry_args=entry_args)
        image = control.images['image']
        entries = image.GetEntries()
        self.assertEqual(3, len(entries))

        # First, u-boot, which should be expanded into u-boot-nodtb and dtb
        self.assertIn('u-boot', entries)
        entry = entries['u-boot']
        self.assertEqual('u-boot-expanded', entry.etype)
        subent = entry.GetEntries()
        self.assertEqual(2, len(subent))
        self.assertIn('u-boot-nodtb', subent)
        self.assertIn('u-boot-dtb', subent)

        # Second, u-boot-spl, which should be expanded into three parts
        self.assertIn('u-boot-spl', entries)
        entry = entries['u-boot-spl']
        self.assertEqual('u-boot-spl-expanded', entry.etype)
        subent = entry.GetEntries()
        self.assertEqual(3, len(subent))
        self.assertIn('u-boot-spl-nodtb', subent)
        self.assertIn('u-boot-spl-bss-pad', subent)
        self.assertIn('u-boot-spl-dtb', subent)

        # Third, u-boot-tpl, which should be not be expanded, since TPL has no
        # devicetree
        self.assertIn('u-boot-tpl', entries)
        entry = entries['u-boot-tpl']
        self.assertEqual('u-boot-tpl', entry.etype)
        self.assertEqual(None, entry.GetEntries())

    def testExpandedTpl(self):
        """Test that an expanded entry type is selected for TPL when needed"""
        self._SetupTplElf()

        entry_args = {
            'tpl-bss-pad': 'y',
            'tpl-dtb': 'y',
        }
        self._DoReadFileDtb('195_fdt_incl_tpl.dts', use_expanded=True,
                            entry_args=entry_args)
        image = control.images['image']
        entries = image.GetEntries()
        self.assertEqual(1, len(entries))

        # We only have u-boot-tpl, which be expanded
        self.assertIn('u-boot-tpl', entries)
        entry = entries['u-boot-tpl']
        self.assertEqual('u-boot-tpl-expanded', entry.etype)
        subent = entry.GetEntries()
        self.assertEqual(3, len(subent))
        self.assertIn('u-boot-tpl-nodtb', subent)
        self.assertIn('u-boot-tpl-bss-pad', subent)
        self.assertIn('u-boot-tpl-dtb', subent)

    def testExpandedNoPad(self):
        """Test an expanded entry without BSS pad enabled"""
        self._SetupSplElf()
        self._SetupTplElf()

        # SPL has a devicetree, TPL does not
        entry_args = {
            'spl-dtb': 'something',
            'spl-bss-pad': 'n',
            'tpl-dtb': '',
        }
        self._DoReadFileDtb('194_fdt_incl.dts', use_expanded=True,
                            entry_args=entry_args)
        image = control.images['image']
        entries = image.GetEntries()

        # Just check u-boot-spl, which should be expanded into two parts
        self.assertIn('u-boot-spl', entries)
        entry = entries['u-boot-spl']
        self.assertEqual('u-boot-spl-expanded', entry.etype)
        subent = entry.GetEntries()
        self.assertEqual(2, len(subent))
        self.assertIn('u-boot-spl-nodtb', subent)
        self.assertIn('u-boot-spl-dtb', subent)

    def testExpandedTplNoPad(self):
        """Test that an expanded entry type with padding disabled in TPL"""
        self._SetupTplElf()

        entry_args = {
            'tpl-bss-pad': '',
            'tpl-dtb': 'y',
        }
        self._DoReadFileDtb('195_fdt_incl_tpl.dts', use_expanded=True,
                            entry_args=entry_args)
        image = control.images['image']
        entries = image.GetEntries()
        self.assertEqual(1, len(entries))

        # We only have u-boot-tpl, which be expanded
        self.assertIn('u-boot-tpl', entries)
        entry = entries['u-boot-tpl']
        self.assertEqual('u-boot-tpl-expanded', entry.etype)
        subent = entry.GetEntries()
        self.assertEqual(2, len(subent))
        self.assertIn('u-boot-tpl-nodtb', subent)
        self.assertIn('u-boot-tpl-dtb', subent)

    def testFdtInclude(self):
        """Test that an Fdt is update within all binaries"""
        self._SetupSplElf()
        self._SetupTplElf()

        # SPL has a devicetree, TPL does not
        self.maxDiff = None
        entry_args = {
            'spl-dtb': '1',
            'spl-bss-pad': 'y',
            'tpl-dtb': '',
        }
        # Build the image. It includes two separate devicetree binaries, each
        # with their own contents, but all contain the binman definition.
        data = self._DoReadFileDtb(
            '194_fdt_incl.dts', use_real_dtb=True, use_expanded=True,
            update_dtb=True, entry_args=entry_args)[0]
        pad_len = 10

        # Check the U-Boot dtb
        start = len(U_BOOT_NODTB_DATA)
        fdt_size = self.checkDtbSizes(data, pad_len, start)

        # Now check SPL
        start += fdt_size + len(U_BOOT_SPL_NODTB_DATA) + pad_len
        fdt_size = self.checkDtbSizes(data, pad_len, start)

        # TPL has no devicetree
        start += fdt_size + len(U_BOOT_TPL_DATA)
        self.assertEqual(len(data), start)

    def testSymbolsExpanded(self):
        """Test binman can assign symbols in expanded entries"""
        entry_args = {
            'spl-dtb': '1',
        }
        self.checkSymbols('197_symbols_expand.dts', U_BOOT_SPL_NODTB_DATA +
                          U_BOOT_SPL_DTB_DATA, 0x38,
                          entry_args=entry_args, use_expanded=True)

    def testCollection(self):
        """Test a collection"""
        data = self._DoReadFile('198_collection.dts')
        self.assertEqual(U_BOOT_NODTB_DATA + U_BOOT_DTB_DATA +
                         tools.GetBytes(0xff, 2) + U_BOOT_NODTB_DATA +
                         tools.GetBytes(0xfe, 3) + U_BOOT_DTB_DATA,
                         data)

    def testCollectionSection(self):
        """Test a collection where a section must be built first"""
        # Sections never have their contents when GetData() is called, but when
        # _BuildSectionData() is called with required=True, a section will force
        # building the contents, producing an error is anything is still
        # missing.
        data = self._DoReadFile('199_collection_section.dts')
        section = U_BOOT_NODTB_DATA + U_BOOT_DTB_DATA
        self.assertEqual(section + U_BOOT_DATA + tools.GetBytes(0xff, 2) +
                         section + tools.GetBytes(0xfe, 3) + U_BOOT_DATA,
                         data)

    def testAlignDefault(self):
        """Test that default alignment works on sections"""
        data = self._DoReadFile('200_align_default.dts')
        expected = (U_BOOT_DATA + tools.GetBytes(0, 8 - len(U_BOOT_DATA)) +
                    U_BOOT_DATA)
        # Special alignment for section
        expected += tools.GetBytes(0, 32 - len(expected))
        # No alignment within the nested section
        expected += U_BOOT_DATA + U_BOOT_NODTB_DATA;
        # Now the final piece, which should be default-aligned
        expected += tools.GetBytes(0, 88 - len(expected)) + U_BOOT_NODTB_DATA
        self.assertEqual(expected, data)

    def testPackOpenSBI(self):
        """Test that an image with an OpenSBI binary can be created"""
        data = self._DoReadFile('201_opensbi.dts')
        self.assertEqual(OPENSBI_DATA, data[:len(OPENSBI_DATA)])

if __name__ == "__main__":
    unittest.main()
