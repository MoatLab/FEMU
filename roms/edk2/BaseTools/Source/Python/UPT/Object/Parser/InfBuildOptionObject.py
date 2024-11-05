## @file
# This file is used to define class objects of INF file [BuildOptions] section.
# It will consumed by InfParser.
#
# Copyright (c) 2011 - 2018, Intel Corporation. All rights reserved.<BR>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent

'''
InfBuildOptionObject
'''

from Library import GlobalData

from Object.Parser.InfCommonObject import InfSectionCommonDef

class InfBuildOptionItem():
    def __init__(self):
        self.Content     = ''
        self.SupArchList = []
        self.AsBuildList = []

    def SetContent(self, Content):
        self.Content = Content
    def GetContent(self):
        return self.Content

    def SetSupArchList(self, SupArchList):
        self.SupArchList = SupArchList
    def GetSupArchList(self):
        return self.SupArchList

    #
    # AsBuild Information
    #
    def SetAsBuildList(self, AsBuildList):
        self.AsBuildList = AsBuildList
    def GetAsBuildList(self):
        return self.AsBuildList


## INF BuildOption section
#  Macro define is not permitted for this section.
#
#
class InfBuildOptionsObject(InfSectionCommonDef):
    def __init__(self):
        self.BuildOptions = []
        InfSectionCommonDef.__init__(self)
    ## SetBuildOptions function
    #
    # For BuildOptionName, need to validate its format
    # For BuildOptionValue, just ignore it.
    #
    # @param  Arch          Indicated which arch of build options belong to.
    # @param  BuildOptCont  A list contain BuildOption related information.
    #                       The element in the list contain 3 members.
    #                       BuildOptionName, BuildOptionValue and IsReplace
    #                       flag.
    #
    # @return True          Build options set/validate successfully
    # @return False         Build options set/validate failed
    #
    def SetBuildOptions(self, BuildOptCont, ArchList = None, SectionContent = ''):

        if not GlobalData.gIS_BINARY_INF:

            if SectionContent.strip() != '':
                InfBuildOptionItemObj = InfBuildOptionItem()
                InfBuildOptionItemObj.SetContent(SectionContent)
                InfBuildOptionItemObj.SetSupArchList(ArchList)

                self.BuildOptions.append(InfBuildOptionItemObj)
        else:
            #
            # For AsBuild INF file
            #
            if len(BuildOptCont) >= 1:
                InfBuildOptionItemObj = InfBuildOptionItem()
                InfBuildOptionItemObj.SetAsBuildList(BuildOptCont)
                InfBuildOptionItemObj.SetSupArchList(ArchList)
                self.BuildOptions.append(InfBuildOptionItemObj)

        return True

    def GetBuildOptions(self):
        return self.BuildOptions
