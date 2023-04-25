# @file HostUnitTestDscCompleteCheck.py
#
# This is a copy of DscCompleteCheck with different filtering logic.
# It should be discussed if this should be one plugin
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import logging
import os
from edk2toolext.environment.plugintypes.ci_build_plugin import ICiBuildPlugin
from edk2toollib.uefi.edk2.parsers.dsc_parser import DscParser
from edk2toollib.uefi.edk2.parsers.inf_parser import InfParser
from edk2toolext.environment.var_dict import VarDict


class HostUnitTestDscCompleteCheck(ICiBuildPlugin):
    """
    A CiBuildPlugin that scans the package Host Unit Test dsc file and confirms all Host application modules (inf files) are
    listed in the components sections.

    Configuration options:
    "HostUnitTestDscCompleteCheck": {
        "DscPath": "", # Path to Host based unit test DSC file
        "IgnoreInf": []  # Ignore INF if found in filesystem but not dsc
    }
    """

    def GetTestName(self, packagename: str, environment: VarDict) -> tuple:
        """ Provide the testcase name and classname for use in reporting

            Args:
              packagename: string containing name of package to build
              environment: The VarDict for the test to run in
            Returns:
                a tuple containing the testcase name and the classname
                (testcasename, classname)
                testclassname: a descriptive string for the testcase can include whitespace
                classname: should be patterned <packagename>.<plugin>.<optionally any unique condition>
        """
        return ("Check the " + packagename + " Host Unit Test DSC for a being complete", packagename + ".HostUnitTestDscCompleteCheck")

    ##
    # External function of plugin.  This function is used to perform the task of the MuBuild Plugin
    #
    #   - package is the edk2 path to package.  This means workspace/packagepath relative.
    #   - edk2path object configured with workspace and packages path
    #   - PkgConfig Object (dict) for the pkg
    #   - VarDict containing the shell environment Build Vars
    #   - Plugin Manager Instance
    #   - Plugin Helper Obj Instance
    #   - Junit Logger
    #   - output_stream the StringIO output stream from this plugin via logging
    def RunBuildPlugin(self, packagename, Edk2pathObj, pkgconfig, environment, PLM, PLMHelper, tc, output_stream=None):
        overall_status = 0

        # Parse the config for required DscPath element
        if "DscPath" not in pkgconfig:
            tc.SetSkipped()
            tc.LogStdError(
                "DscPath not found in config file.  Nothing to check.")
            return -1

        abs_pkg_path = Edk2pathObj.GetAbsolutePathOnThisSystemFromEdk2RelativePath(
            packagename)
        abs_dsc_path = os.path.join(abs_pkg_path, pkgconfig["DscPath"].strip())
        wsr_dsc_path = Edk2pathObj.GetEdk2RelativePathFromAbsolutePath(
            abs_dsc_path)

        if abs_dsc_path is None or wsr_dsc_path == "" or not os.path.isfile(abs_dsc_path):
            tc.SetSkipped()
            tc.LogStdError("Package Host Unit Test Dsc not found")
            return 0

        # Get INF Files
        INFFiles = self.WalkDirectoryForExtension([".inf"], abs_pkg_path)
        INFFiles = [Edk2pathObj.GetEdk2RelativePathFromAbsolutePath(
            x) for x in INFFiles]  # make edk2relative path so can compare with DSC

        # remove ignores

        if "IgnoreInf" in pkgconfig:
            for a in pkgconfig["IgnoreInf"]:
                a = a.replace(os.sep, "/")
                try:
                    tc.LogStdOut("Ignoring INF {0}".format(a))
                    INFFiles.remove(a)
                except:
                    tc.LogStdError(
                        "HostUnitTestDscCompleteCheck.IgnoreInf -> {0} not found in filesystem.  Invalid ignore file".format(a))
                    logging.info(
                        "HostUnitTestDscCompleteCheck.IgnoreInf -> {0} not found in filesystem.  Invalid ignore file".format(a))

        # DSC Parser
        dp = DscParser()
        dp.SetBaseAbsPath(Edk2pathObj.WorkspacePath)
        dp.SetPackagePaths(Edk2pathObj.PackagePathList)
        dp.SetInputVars(environment.GetAllBuildKeyValues())
        dp.ParseFile(wsr_dsc_path)

        # Check if INF in component section
        for INF in INFFiles:
            if not any(INF.strip() in x for x in dp.ThreeMods) and \
               not any(INF.strip() in x for x in dp.SixMods) and \
               not any(INF.strip() in x for x in dp.OtherMods):

                infp = InfParser().SetBaseAbsPath(Edk2pathObj.WorkspacePath)
                infp.SetPackagePaths(Edk2pathObj.PackagePathList)
                infp.ParseFile(INF)
                if("MODULE_TYPE" not in infp.Dict):
                    tc.LogStdOut(
                        "Ignoring INF. Missing key for MODULE_TYPE {0}".format(INF))
                    continue

                if(infp.Dict["MODULE_TYPE"] == "HOST_APPLICATION"):
                    # should compile test a library that is declared type HOST_APPLICATION
                    pass

                elif len(infp.SupportedPhases) > 0 and \
                        "HOST_APPLICATION" in infp.SupportedPhases:
                    # should compile test a library that supports HOST_APPLICATION but
                    # require it to be an explicit opt-in
                    pass

                else:
                    tc.LogStdOut(
                        "Ignoring INF. MODULE_TYPE or suppored phases not HOST_APPLICATION {0}".format(INF))
                    continue

                logging.critical(INF + " not in " + wsr_dsc_path)
                tc.LogStdError("{0} not in {1}".format(INF, wsr_dsc_path))
                overall_status = overall_status + 1

        # If XML object exists, add result
        if overall_status != 0:
            tc.SetFailed("HostUnitTestDscCompleteCheck {0} Failed.  Errors {1}".format(
                wsr_dsc_path, overall_status), "CHECK_FAILED")
        else:
            tc.SetSuccess()
        return overall_status
