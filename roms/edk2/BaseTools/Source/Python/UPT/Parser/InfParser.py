## @file
# This file contained the parser for INF file
#
# Copyright (c) 2011 - 2018, Intel Corporation. All rights reserved.<BR>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#

'''
InfParser
'''

##
# Import Modules
#
import re
import os
from copy import deepcopy

from Library.StringUtils import GetSplitValueList
from Library.StringUtils import ConvertSpecialChar
from Library.Misc import ProcessLineExtender
from Library.Misc import ProcessEdkComment
from Library.Parsing import NormPath
from Library.ParserValidate import IsValidInfMoudleTypeList
from Library.ParserValidate import IsValidArch
from Library import DataType as DT
from Library import GlobalData

import Logger.Log as Logger
from Logger import StringTable as ST
from Logger.ToolError import FORMAT_INVALID
from Logger.ToolError import FILE_READ_FAILURE
from Logger.ToolError import PARSER_ERROR

from Object.Parser.InfCommonObject import InfSectionCommonDef
from Parser.InfSectionParser import InfSectionParser
from Parser.InfParserMisc import gINF_SECTION_DEF
from Parser.InfParserMisc import IsBinaryInf

## OpenInfFile
#
#
def OpenInfFile(Filename):
    FileLinesList = []

    try:
        FInputfile = open(Filename, "r")
        try:
            FileLinesList = FInputfile.readlines()
        except BaseException:
            Logger.Error("InfParser",
                         FILE_READ_FAILURE,
                         ST.ERR_FILE_OPEN_FAILURE,
                         File=Filename)
        finally:
            FInputfile.close()
    except BaseException:
        Logger.Error("InfParser",
                     FILE_READ_FAILURE,
                     ST.ERR_FILE_OPEN_FAILURE,
                     File=Filename)

    return FileLinesList

## InfParser
#
# This class defined the structure used in InfParser object
#
# @param InfObject:         Inherited from InfSectionParser class
# @param Filename:          Input value for Filename of INF file, default is
#                           None
# @param WorkspaceDir:      Input value for current workspace directory,
#                           default is None
#
class InfParser(InfSectionParser):

    def __init__(self, Filename = None, WorkspaceDir = None):

        #
        # Call parent class construct function
        #
        InfSectionParser.__init__()

        self.WorkspaceDir    = WorkspaceDir
        self.SupArchList     = DT.ARCH_LIST
        self.EventList    = []
        self.HobList      = []
        self.BootModeList = []

        #
        # Load Inf file if filename is not None
        #
        if Filename is not None:
            self.ParseInfFile(Filename)

    ## Parse INF file
    #
    # Parse the file if it exists
    #
    # @param Filename:  Input value for filename of INF file
    #
    def ParseInfFile(self, Filename):

        Filename = NormPath(Filename)
        (Path, Name) = os.path.split(Filename)
        self.FullPath = Filename
        self.RelaPath = Path
        self.FileName = Name
        GlobalData.gINF_MODULE_DIR = Path
        GlobalData.gINF_MODULE_NAME = self.FullPath
        GlobalData.gIS_BINARY_INF = False
        #
        # Initialize common data
        #
        LineNo             = 0
        CurrentSection     = DT.MODEL_UNKNOWN
        SectionLines       = []

        #
        # Flags
        #
        HeaderCommentStart = False
        HeaderCommentEnd   = False
        HeaderStarLineNo = -1
        BinaryHeaderCommentStart = False
        BinaryHeaderCommentEnd   = False
        BinaryHeaderStarLineNo = -1

        #
        # While Section ends. parse whole section contents.
        #
        NewSectionStartFlag = False
        FirstSectionStartFlag = False

        #
        # Parse file content
        #
        CommentBlock       = []

        #
        # Variables for Event/Hob/BootMode
        #
        self.EventList    = []
        self.HobList      = []
        self.BootModeList = []
        SectionType = ''

        FileLinesList = OpenInfFile (Filename)

        #
        # One INF file can only has one [Defines] section.
        #
        DefineSectionParsedFlag = False

        #
        # Convert special characters in lines to space character.
        #
        FileLinesList = ConvertSpecialChar(FileLinesList)

        #
        # Process Line Extender
        #
        FileLinesList = ProcessLineExtender(FileLinesList)

        #
        # Process EdkI INF style comment if found
        #
        OrigLines = [Line for Line in FileLinesList]
        FileLinesList, EdkCommentStartPos = ProcessEdkComment(FileLinesList)

        #
        # Judge whether the INF file is Binary INF or not
        #
        if IsBinaryInf(FileLinesList):
            GlobalData.gIS_BINARY_INF = True

        InfSectionCommonDefObj = None

        for Line in FileLinesList:
            LineNo   = LineNo + 1
            Line     = Line.strip()
            if (LineNo < len(FileLinesList) - 1):
                NextLine = FileLinesList[LineNo].strip()

            #
            # blank line
            #
            if (Line == '' or not Line) and LineNo == len(FileLinesList):
                LastSectionFalg = True

            #
            # check whether file header comment section started
            #
            if Line.startswith(DT.TAB_SPECIAL_COMMENT) and \
               (Line.find(DT.TAB_HEADER_COMMENT) > -1) and \
               not HeaderCommentStart and not HeaderCommentEnd:

                CurrentSection = DT.MODEL_META_DATA_FILE_HEADER
                #
                # Append the first line to section lines.
                #
                HeaderStarLineNo = LineNo
                SectionLines.append((Line, LineNo))
                HeaderCommentStart = True
                continue

            #
            # Collect Header content.
            #
            if (Line.startswith(DT.TAB_COMMENT_SPLIT) and CurrentSection == DT.MODEL_META_DATA_FILE_HEADER) and\
                HeaderCommentStart and not Line.startswith(DT.TAB_SPECIAL_COMMENT) and not\
                HeaderCommentEnd and NextLine != '':
                SectionLines.append((Line, LineNo))
                continue
            #
            # Header content end
            #
            if (Line.startswith(DT.TAB_SPECIAL_COMMENT) or not Line.strip().startswith("#")) and HeaderCommentStart \
                and not HeaderCommentEnd:
                HeaderCommentEnd = True
                BinaryHeaderCommentStart = False
                BinaryHeaderCommentEnd   = False
                HeaderCommentStart = False
                if Line.find(DT.TAB_BINARY_HEADER_COMMENT) > -1:
                    self.InfHeaderParser(SectionLines, self.InfHeader, self.FileName)
                    SectionLines = []
                else:
                    SectionLines.append((Line, LineNo))
                    #
                    # Call Header comment parser.
                    #
                    self.InfHeaderParser(SectionLines, self.InfHeader, self.FileName)
                    SectionLines = []
                    continue

            #
            # check whether binary header comment section started
            #
            if Line.startswith(DT.TAB_SPECIAL_COMMENT) and \
                (Line.find(DT.TAB_BINARY_HEADER_COMMENT) > -1) and \
                not BinaryHeaderCommentStart:
                SectionLines = []
                CurrentSection = DT.MODEL_META_DATA_FILE_HEADER
                #
                # Append the first line to section lines.
                #
                BinaryHeaderStarLineNo = LineNo
                SectionLines.append((Line, LineNo))
                BinaryHeaderCommentStart = True
                HeaderCommentEnd = True
                continue

            #
            # check whether there are more than one binary header exist
            #
            if Line.startswith(DT.TAB_SPECIAL_COMMENT) and BinaryHeaderCommentStart and \
                not BinaryHeaderCommentEnd and (Line.find(DT.TAB_BINARY_HEADER_COMMENT) > -1):
                Logger.Error('Parser',
                             FORMAT_INVALID,
                             ST.ERR_MULTIPLE_BINARYHEADER_EXIST,
                             File=Filename)

            #
            # Collect Binary Header content.
            #
            if (Line.startswith(DT.TAB_COMMENT_SPLIT) and CurrentSection == DT.MODEL_META_DATA_FILE_HEADER) and\
                BinaryHeaderCommentStart and not Line.startswith(DT.TAB_SPECIAL_COMMENT) and not\
                BinaryHeaderCommentEnd and NextLine != '':
                SectionLines.append((Line, LineNo))
                continue
            #
            # Binary Header content end
            #
            if (Line.startswith(DT.TAB_SPECIAL_COMMENT) or not Line.strip().startswith(DT.TAB_COMMENT_SPLIT)) and \
                BinaryHeaderCommentStart and not BinaryHeaderCommentEnd:
                SectionLines.append((Line, LineNo))
                BinaryHeaderCommentStart = False
                #
                # Call Binary Header comment parser.
                #
                self.InfHeaderParser(SectionLines, self.InfBinaryHeader, self.FileName, True)
                SectionLines = []
                BinaryHeaderCommentEnd   = True
                continue
            #
            # Find a new section tab
            # Or at the last line of INF file,
            # need to process the last section.
            #
            LastSectionFalg = False
            if LineNo == len(FileLinesList):
                LastSectionFalg = True

            if Line.startswith(DT.TAB_COMMENT_SPLIT) and not Line.startswith(DT.TAB_SPECIAL_COMMENT):
                SectionLines.append((Line, LineNo))
                if not LastSectionFalg:
                    continue

            #
            # Encountered a section. start with '[' and end with ']'
            #
            if (Line.startswith(DT.TAB_SECTION_START) and \
               Line.find(DT.TAB_SECTION_END) > -1) or LastSectionFalg:

                HeaderCommentEnd = True
                BinaryHeaderCommentEnd = True

                if not LastSectionFalg:
                    #
                    # check to prevent '#' inside section header
                    #
                    HeaderContent = Line[1:Line.find(DT.TAB_SECTION_END)]
                    if HeaderContent.find(DT.TAB_COMMENT_SPLIT) != -1:
                        Logger.Error("InfParser",
                                     FORMAT_INVALID,
                                     ST.ERR_INF_PARSER_DEFINE_SECTION_HEADER_INVALID,
                                     File=self.FullPath,
                                     Line=LineNo,
                                     ExtraData=Line)

                    #
                    # Keep last time section header content for section parser
                    # usage.
                    #
                    self.LastSectionHeaderContent = deepcopy(self.SectionHeaderContent)

                    #
                    # TailComments in section define.
                    #
                    TailComments = ''
                    CommentIndex = Line.find(DT.TAB_COMMENT_SPLIT)
                    if  CommentIndex > -1:
                        TailComments = Line[CommentIndex:]
                        Line = Line[:CommentIndex]

                    InfSectionCommonDefObj = InfSectionCommonDef()
                    if TailComments != '':
                        InfSectionCommonDefObj.SetTailComments(TailComments)
                    if CommentBlock != '':
                        InfSectionCommonDefObj.SetHeaderComments(CommentBlock)
                        CommentBlock = []
                    #
                    # Call section parser before section header parer to avoid encounter EDKI INF file
                    #
                    if CurrentSection == DT.MODEL_META_DATA_DEFINE:
                        DefineSectionParsedFlag = self._CallSectionParsers(CurrentSection,
                                                                   DefineSectionParsedFlag, SectionLines,
                                                                   InfSectionCommonDefObj, LineNo)
                    #
                    # Compare the new section name with current
                    #
                    self.SectionHeaderParser(Line, self.FileName, LineNo)

                    self._CheckSectionHeaders(Line, LineNo)

                    SectionType = _ConvertSecNameToType(self.SectionHeaderContent[0][0])

                if not FirstSectionStartFlag:
                    CurrentSection = SectionType
                    FirstSectionStartFlag = True
                else:
                    NewSectionStartFlag = True
            else:
                SectionLines.append((Line, LineNo))
                continue

            if LastSectionFalg:
                SectionLines, CurrentSection = self._ProcessLastSection(SectionLines, Line, LineNo, CurrentSection)

            #
            # End of section content collect.
            # Parser the section content collected previously.
            #
            if NewSectionStartFlag or LastSectionFalg:
                if CurrentSection != DT.MODEL_META_DATA_DEFINE or \
                    (LastSectionFalg and CurrentSection == DT.MODEL_META_DATA_DEFINE):
                    DefineSectionParsedFlag = self._CallSectionParsers(CurrentSection,
                                                                       DefineSectionParsedFlag, SectionLines,
                                                                       InfSectionCommonDefObj, LineNo)

                CurrentSection = SectionType
                #
                # Clear section lines
                #
                SectionLines = []

        if HeaderStarLineNo == -1:
            Logger.Error("InfParser",
                        FORMAT_INVALID,
                        ST.ERR_NO_SOURCE_HEADER,
                        File=self.FullPath)
        if BinaryHeaderStarLineNo > -1 and HeaderStarLineNo > -1  and HeaderStarLineNo > BinaryHeaderStarLineNo:
            Logger.Error("InfParser",
                        FORMAT_INVALID,
                        ST.ERR_BINARY_HEADER_ORDER,
                        File=self.FullPath)
        #
        # EDKII INF should not have EDKI style comment
        #
        if EdkCommentStartPos != -1:
            Logger.Error("InfParser",
                         FORMAT_INVALID,
                         ST.ERR_INF_PARSER_EDKI_COMMENT_IN_EDKII,
                         File=self.FullPath,
                         Line=EdkCommentStartPos + 1,
                         ExtraData=OrigLines[EdkCommentStartPos])

        #
        # extract [Event] [Hob] [BootMode] sections
        #
        self._ExtractEventHobBootMod(FileLinesList)

    ## _CheckSectionHeaders
    #
    #
    def _CheckSectionHeaders(self, Line, LineNo):
        if len(self.SectionHeaderContent) == 0:
            Logger.Error("InfParser",
                         FORMAT_INVALID,
                         ST.ERR_INF_PARSER_DEFINE_SECTION_HEADER_INVALID,
                         File=self.FullPath,
                         Line=LineNo, ExtraData=Line)
        else:
            for SectionItem in self.SectionHeaderContent:
                ArchList = []
                #
                # Not cover Depex/UserExtension section header
                # check.
                #
                if SectionItem[0].strip().upper() == DT.TAB_INF_FIXED_PCD.upper() or \
                    SectionItem[0].strip().upper() == DT.TAB_INF_PATCH_PCD.upper() or \
                    SectionItem[0].strip().upper() == DT.TAB_INF_PCD_EX.upper() or \
                    SectionItem[0].strip().upper() == DT.TAB_INF_PCD.upper() or \
                    SectionItem[0].strip().upper() == DT.TAB_INF_FEATURE_PCD.upper():
                    ArchList = GetSplitValueList(SectionItem[1].strip(), ' ')
                else:
                    ArchList = [SectionItem[1].strip()]

                for Arch in ArchList:
                    if (not IsValidArch(Arch)) and \
                        (SectionItem[0].strip().upper() != DT.TAB_DEPEX.upper()) and \
                        (SectionItem[0].strip().upper() != DT.TAB_USER_EXTENSIONS.upper()) and \
                        (SectionItem[0].strip().upper() != DT.TAB_COMMON_DEFINES.upper()):
                        Logger.Error("InfParser",
                                     FORMAT_INVALID,
                                     ST.ERR_INF_PARSER_DEFINE_FROMAT_INVALID%(SectionItem[1]),
                                     File=self.FullPath,
                                     Line=LineNo, ExtraData=Line)
                #
                # Check if the ModuleType is valid
                #
                ChkModSectionList = ['LIBRARYCLASSES']
                if (self.SectionHeaderContent[0][0].upper() in ChkModSectionList):
                    if SectionItem[2].strip().upper():
                        MoudleTypeList = GetSplitValueList(
                                    SectionItem[2].strip().upper())
                        if (not IsValidInfMoudleTypeList(MoudleTypeList)):
                            Logger.Error("InfParser",
                                         FORMAT_INVALID,
                                         ST.ERR_INF_PARSER_DEFINE_FROMAT_INVALID%(SectionItem[2]),
                                         File=self.FullPath, Line=LineNo,
                                         ExtraData=Line)

    ## _CallSectionParsers
    #
    #
    def _CallSectionParsers(self, CurrentSection, DefineSectionParsedFlag,
                            SectionLines, InfSectionCommonDefObj, LineNo):
        if CurrentSection == DT.MODEL_META_DATA_DEFINE:
            if not DefineSectionParsedFlag:
                self.InfDefineParser(SectionLines,
                                     self.InfDefSection,
                                     self.FullPath,
                                     InfSectionCommonDefObj)
                DefineSectionParsedFlag = True
            else:
                Logger.Error("Parser",
                             PARSER_ERROR,
                             ST.ERR_INF_PARSER_MULTI_DEFINE_SECTION,
                             File=self.FullPath,
                             RaiseError = Logger.IS_RAISE_ERROR)

        elif CurrentSection == DT.MODEL_META_DATA_BUILD_OPTION:
            self.InfBuildOptionParser(SectionLines,
                                      self.InfBuildOptionSection,
                                      self.FullPath)

        elif CurrentSection == DT.MODEL_EFI_LIBRARY_CLASS:
            self.InfLibraryParser(SectionLines,
                                  self.InfLibraryClassSection,
                                  self.FullPath)

        elif CurrentSection == DT.MODEL_META_DATA_PACKAGE:
            self.InfPackageParser(SectionLines,
                                  self.InfPackageSection,
                                  self.FullPath)
        #
        # [Pcd] Sections, put it together
        #
        elif CurrentSection == DT.MODEL_PCD_FIXED_AT_BUILD or \
             CurrentSection == DT.MODEL_PCD_PATCHABLE_IN_MODULE or \
             CurrentSection == DT.MODEL_PCD_FEATURE_FLAG or \
             CurrentSection == DT.MODEL_PCD_DYNAMIC_EX or \
             CurrentSection == DT.MODEL_PCD_DYNAMIC:
            self.InfPcdParser(SectionLines,
                              self.InfPcdSection,
                              self.FullPath)

        elif CurrentSection == DT.MODEL_EFI_SOURCE_FILE:
            self.InfSourceParser(SectionLines,
                                 self.InfSourcesSection,
                                 self.FullPath)

        elif CurrentSection == DT.MODEL_META_DATA_USER_EXTENSION:
            self.InfUserExtensionParser(SectionLines,
                                        self.InfUserExtensionSection,
                                        self.FullPath)

        elif CurrentSection == DT.MODEL_EFI_PROTOCOL:
            self.InfProtocolParser(SectionLines,
                                   self.InfProtocolSection,
                                   self.FullPath)

        elif CurrentSection == DT.MODEL_EFI_PPI:
            self.InfPpiParser(SectionLines,
                              self.InfPpiSection,
                              self.FullPath)

        elif CurrentSection == DT.MODEL_EFI_GUID:
            self.InfGuidParser(SectionLines,
                               self.InfGuidSection,
                               self.FullPath)

        elif CurrentSection == DT.MODEL_EFI_DEPEX:
            self.InfDepexParser(SectionLines,
                                self.InfDepexSection,
                                self.FullPath)

        elif CurrentSection == DT.MODEL_EFI_BINARY_FILE:
            self.InfBinaryParser(SectionLines,
                                 self.InfBinariesSection,
                                 self.FullPath)
        #
        # Unknown section type found, raise error.
        #
        else:
            if len(self.SectionHeaderContent) >= 1:
                Logger.Error("Parser",
                             PARSER_ERROR,
                             ST.ERR_INF_PARSER_UNKNOWN_SECTION,
                             File=self.FullPath, Line=LineNo,
                             RaiseError = Logger.IS_RAISE_ERROR)
            else:
                Logger.Error("Parser",
                             PARSER_ERROR,
                             ST.ERR_INF_PARSER_NO_SECTION_ERROR,
                             File=self.FullPath, Line=LineNo,
                             RaiseError = Logger.IS_RAISE_ERROR)

        return DefineSectionParsedFlag

    def _ExtractEventHobBootMod(self, FileLinesList):
        SpecialSectionStart = False
        CheckLocation = False
        GFindSpecialCommentRe = \
        re.compile(r"""#(?:\s*)\[(.*?)\](?:.*)""", re.DOTALL)
        GFindNewSectionRe2 = \
        re.compile(r"""#?(\s*)\[(.*?)\](.*)""", re.DOTALL)
        LineNum = 0
        Element = []
        for Line in FileLinesList:
            Line = Line.strip()
            LineNum += 1
            MatchObject = GFindSpecialCommentRe.search(Line)
            if MatchObject:
                SpecialSectionStart = True
                Element = []
                if MatchObject.group(1).upper().startswith("EVENT"):
                    List = self.EventList
                elif MatchObject.group(1).upper().startswith("HOB"):
                    List = self.HobList
                elif MatchObject.group(1).upper().startswith("BOOTMODE"):
                    List = self.BootModeList
                else:
                    SpecialSectionStart = False
                    CheckLocation = False
                if SpecialSectionStart:
                    Element.append([Line, LineNum])
                    List.append(Element)
            else:
                #
                # if currently in special section, try to detect end of current section
                #
                MatchObject = GFindNewSectionRe2.search(Line)
                if SpecialSectionStart:
                    if MatchObject:
                        SpecialSectionStart = False
                        CheckLocation = False
                        Element = []
                    elif not Line:
                        SpecialSectionStart = False
                        CheckLocation = True
                        Element = []
                    else:
                        if not Line.startswith(DT.TAB_COMMENT_SPLIT):
                            Logger.Warn("Parser",
                                         ST.WARN_SPECIAL_SECTION_LOCATION_WRONG,
                                         File=self.FullPath, Line=LineNum)
                            SpecialSectionStart = False
                            CheckLocation = False
                            Element = []
                        else:
                            Element.append([Line, LineNum])
                else:
                    if CheckLocation:
                        if MatchObject:
                            CheckLocation = False
                        elif Line:
                            Logger.Warn("Parser",
                                         ST.WARN_SPECIAL_SECTION_LOCATION_WRONG,
                                         File=self.FullPath, Line=LineNum)
                            CheckLocation = False

        if len(self.BootModeList) >= 1:
            self.InfSpecialCommentParser(self.BootModeList,
                                         self.InfSpecialCommentSection,
                                         self.FileName,
                                         DT.TYPE_BOOTMODE_SECTION)

        if len(self.EventList) >= 1:
            self.InfSpecialCommentParser(self.EventList,
                                         self.InfSpecialCommentSection,
                                         self.FileName,
                                         DT.TYPE_EVENT_SECTION)

        if len(self.HobList) >= 1:
            self.InfSpecialCommentParser(self.HobList,
                                         self.InfSpecialCommentSection,
                                         self.FileName,
                                         DT.TYPE_HOB_SECTION)
    ## _ProcessLastSection
    #
    #
    def _ProcessLastSection(self, SectionLines, Line, LineNo, CurrentSection):
        #
        # The last line is a section header. will discard it.
        #
        if not (Line.startswith(DT.TAB_SECTION_START) and Line.find(DT.TAB_SECTION_END) > -1):
            SectionLines.append((Line, LineNo))

        if len(self.SectionHeaderContent) >= 1:
            TemSectionName = self.SectionHeaderContent[0][0].upper()
            if TemSectionName.upper() not in gINF_SECTION_DEF.keys():
                Logger.Error("InfParser",
                             FORMAT_INVALID,
                             ST.ERR_INF_PARSER_UNKNOWN_SECTION,
                             File=self.FullPath,
                             Line=LineNo,
                             ExtraData=Line,
                             RaiseError = Logger.IS_RAISE_ERROR
                             )
            else:
                CurrentSection = gINF_SECTION_DEF[TemSectionName]
                self.LastSectionHeaderContent = self.SectionHeaderContent

        return SectionLines, CurrentSection

## _ConvertSecNameToType
#
#
def _ConvertSecNameToType(SectionName):
    SectionType = ''
    if SectionName.upper() not in gINF_SECTION_DEF.keys():
        SectionType = DT.MODEL_UNKNOWN
    else:
        SectionType = gINF_SECTION_DEF[SectionName.upper()]

    return SectionType

