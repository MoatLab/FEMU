## @file GenMetaFileMisc.py
#
# This file contained the miscellaneous routines for GenMetaFile usage.
#
# Copyright (c) 2011 - 2018, Intel Corporation. All rights reserved.<BR>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#

'''
GenMetaFileMisc
'''

from Library import DataType as DT
from Library import GlobalData
from Parser.DecParser import Dec

# AddExternToDefineSec
#
#  @param SectionDict: string of source file path/name
#  @param Arch:     string of source file family field
#  @param ExternList:  string of source file FeatureFlag field
#
def AddExternToDefineSec(SectionDict, Arch, ExternList):
    LeftOffset = 31
    for ArchList, EntryPoint, UnloadImage, Constructor, Destructor, FFE, HelpStringList in ExternList:
        if Arch or ArchList:
            if EntryPoint:
                Statement = (u'%s ' % DT.TAB_INF_DEFINES_ENTRY_POINT).ljust(LeftOffset) + u'= %s' % EntryPoint
                if FFE:
                    Statement += ' | %s' % FFE
                if len(HelpStringList) > 0:
                    Statement = HelpStringList[0].GetString() + '\n' + Statement
                if len(HelpStringList) > 1:
                    Statement = Statement + HelpStringList[1].GetString()
                SectionDict[Arch] = SectionDict[Arch] + [Statement]

            if UnloadImage:
                Statement = (u'%s ' % DT.TAB_INF_DEFINES_UNLOAD_IMAGE).ljust(LeftOffset) + u'= %s' % UnloadImage
                if FFE:
                    Statement += ' | %s' % FFE

                if len(HelpStringList) > 0:
                    Statement = HelpStringList[0].GetString() + '\n' + Statement
                if len(HelpStringList) > 1:
                    Statement = Statement + HelpStringList[1].GetString()
                SectionDict[Arch] = SectionDict[Arch] + [Statement]

            if Constructor:
                Statement = (u'%s ' % DT.TAB_INF_DEFINES_CONSTRUCTOR).ljust(LeftOffset) + u'= %s' % Constructor
                if FFE:
                    Statement += ' | %s' % FFE

                if len(HelpStringList) > 0:
                    Statement = HelpStringList[0].GetString() + '\n' + Statement
                if len(HelpStringList) > 1:
                    Statement = Statement + HelpStringList[1].GetString()
                SectionDict[Arch] = SectionDict[Arch] + [Statement]

            if Destructor:
                Statement = (u'%s ' % DT.TAB_INF_DEFINES_DESTRUCTOR).ljust(LeftOffset) + u'= %s' % Destructor
                if FFE:
                    Statement += ' | %s' % FFE

                if len(HelpStringList) > 0:
                    Statement = HelpStringList[0].GetString() + '\n' + Statement
                if len(HelpStringList) > 1:
                    Statement = Statement + HelpStringList[1].GetString()
                SectionDict[Arch] = SectionDict[Arch] + [Statement]

## ObtainPcdName
#
# Using TokenSpaceGuidValue and Token to obtain PcdName from DEC file
#
def ObtainPcdName(Packages, TokenSpaceGuidValue, Token):
    TokenSpaceGuidName = ''
    PcdCName = ''
    TokenSpaceGuidNameFound = False

    for PackageDependency in Packages:
        #
        # Generate generic comment
        #
        Guid = PackageDependency.GetGuid()
        Version = PackageDependency.GetVersion()

        Path = None
        #
        # find package path/name
        #
        for PkgInfo in GlobalData.gWSPKG_LIST:
            if Guid == PkgInfo[1]:
                if (not Version) or (Version == PkgInfo[2]):
                    Path = PkgInfo[3]
                    break

        # The dependency package in workspace
        if Path:
            DecFile = None
            if Path not in GlobalData.gPackageDict:
                DecFile = Dec(Path)
                GlobalData.gPackageDict[Path] = DecFile
            else:
                DecFile = GlobalData.gPackageDict[Path]

            DecGuidsDict = DecFile.GetGuidSectionObject().ValueDict
            DecPcdsDict = DecFile.GetPcdSectionObject().ValueDict

            TokenSpaceGuidName = ''
            PcdCName = ''
            TokenSpaceGuidNameFound = False

            #
            # Get TokenSpaceGuidCName from Guids section
            #
            for GuidKey in DecGuidsDict:
                GuidList = DecGuidsDict[GuidKey]
                for GuidItem in GuidList:
                    if TokenSpaceGuidValue.upper() == GuidItem.GuidString.upper():
                        TokenSpaceGuidName = GuidItem.GuidCName
                        TokenSpaceGuidNameFound = True
                        break
                if TokenSpaceGuidNameFound:
                    break
            #
            # Retrieve PcdCName from Pcds Section
            #
            for PcdKey in DecPcdsDict:
                PcdList = DecPcdsDict[PcdKey]
                for PcdItem in PcdList:
                    if TokenSpaceGuidName == PcdItem.TokenSpaceGuidCName and Token == PcdItem.TokenValue:
                        PcdCName = PcdItem.TokenCName
                        return TokenSpaceGuidName, PcdCName

        # The dependency package in ToBeInstalledDist
        else:
            for Dist in GlobalData.gTO_BE_INSTALLED_DIST_LIST:
                for Package in Dist.PackageSurfaceArea.values():
                    if Guid == Package.Guid:
                        for GuidItem in Package.GuidList:
                            if TokenSpaceGuidValue.upper() == GuidItem.Guid.upper():
                                TokenSpaceGuidName = GuidItem.CName
                                TokenSpaceGuidNameFound = True
                                break
                        for PcdItem in Package.PcdList:
                            if TokenSpaceGuidName == PcdItem.TokenSpaceGuidCName and Token == PcdItem.Token:
                                PcdCName = PcdItem.CName
                                return TokenSpaceGuidName, PcdCName

    return TokenSpaceGuidName, PcdCName

## _TransferDict
#  transfer dict that using (Statement, SortedArch) as key,
#  (GenericComment, UsageComment) as value into a dict that using SortedArch as
#  key and NewStatement as value
#
def TransferDict(OrigDict, Type=None):
    NewDict = {}
    LeftOffset = 0
    if Type in ['INF_GUID', 'INF_PPI_PROTOCOL']:
        LeftOffset = 45
    if Type in ['INF_PCD']:
        LeftOffset = 75
    if LeftOffset > 0:
        for Statement, SortedArch in OrigDict:
            if len(Statement) > LeftOffset:
                LeftOffset = len(Statement)

    for Statement, SortedArch in OrigDict:
        Comment = OrigDict[Statement, SortedArch]
        #
        # apply the NComment/1Comment rule
        #
        if Comment.find('\n') != len(Comment) - 1:
            NewStateMent = Comment + Statement
        else:
            if LeftOffset:
                NewStateMent = Statement.ljust(LeftOffset) + ' ' + Comment.rstrip('\n')
            else:
                NewStateMent = Statement + ' ' + Comment.rstrip('\n')

        if SortedArch in NewDict:
            NewDict[SortedArch] = NewDict[SortedArch] + [NewStateMent]
        else:
            NewDict[SortedArch] = [NewStateMent]

    return NewDict

