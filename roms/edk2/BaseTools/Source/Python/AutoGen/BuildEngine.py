## @file
# The engine for building files
#
# Copyright (c) 2007 - 2018, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#

##
# Import Modules
#
from __future__ import print_function
import Common.LongFilePathOs as os
import re
import copy
import string
from Common.LongFilePathSupport import OpenLongFilePath as open

from Common.GlobalData import *
from Common.BuildToolError import *
from Common.Misc import tdict, PathClass
from Common.StringUtils import NormPath
from Common.DataType import *
from Common.TargetTxtClassObject import TargetTxtDict
gDefaultBuildRuleFile = 'build_rule.txt'
AutoGenReqBuildRuleVerNum = '0.1'

import Common.EdkLogger as EdkLogger

## Convert file type to file list macro name
#
#   @param      FileType    The name of file type
#
#   @retval     string      The name of macro
#
def FileListMacro(FileType):
    return "%sS" % FileType.replace("-", "_").upper()

## Convert file type to list file macro name
#
#   @param      FileType    The name of file type
#
#   @retval     string      The name of macro
#
def ListFileMacro(FileType):
    return "%s_LIST" % FileListMacro(FileType)

class TargetDescBlock(object):
    def __init__(self, Inputs, Outputs, Commands, Dependencies):
        self.InitWorker(Inputs, Outputs, Commands, Dependencies)

    def InitWorker(self, Inputs, Outputs, Commands, Dependencies):
        self.Inputs = Inputs
        self.Outputs = Outputs
        self.Commands = Commands
        self.Dependencies = Dependencies
        if self.Outputs:
            self.Target = self.Outputs[0]
        else:
            self.Target = None

    def __str__(self):
        return self.Target.Path

    def __hash__(self):
        return hash(self.Target.Path)

    def __eq__(self, Other):
        if isinstance(Other, type(self)):
            return Other.Target.Path == self.Target.Path
        else:
            return str(Other) == self.Target.Path

    def AddInput(self, Input):
        if Input not in self.Inputs:
            self.Inputs.append(Input)

    def IsMultipleInput(self):
        return len(self.Inputs) > 1

## Class for one build rule
#
# This represents a build rule which can give out corresponding command list for
# building the given source file(s). The result can be used for generating the
# target for makefile.
#
class FileBuildRule:
    INC_LIST_MACRO = "INC_LIST"
    INC_MACRO = "INC"

    ## constructor
    #
    #   @param  Input       The dictionary representing input file(s) for a rule
    #   @param  Output      The list representing output file(s) for a rule
    #   @param  Command     The list containing commands to generate the output from input
    #
    def __init__(self, Type, Input, Output, Command, ExtraDependency=None):
        # The Input should not be empty
        if not Input:
            Input = []
        if not Output:
            Output = []
        if not Command:
            Command = []

        self.FileListMacro = FileListMacro(Type)
        self.ListFileMacro = ListFileMacro(Type)
        self.IncListFileMacro = self.INC_LIST_MACRO

        self.SourceFileType = Type
        # source files listed not in TAB_STAR or "?" pattern format
        if not ExtraDependency:
            self.ExtraSourceFileList = []
        else:
            self.ExtraSourceFileList = ExtraDependency

        #
        # Search macros used in command lines for <FILE_TYPE>_LIST and INC_LIST.
        # If found, generate a file to keep the input files used to get over the
        # limitation of command line length
        #
        self.MacroList = []
        self.CommandList = []
        for CmdLine in Command:
            self.MacroList.extend(gMacroRefPattern.findall(CmdLine))
            # replace path separator with native one
            self.CommandList.append(CmdLine)

        # Indicate what should be generated
        if self.FileListMacro in self.MacroList:
            self.GenFileListMacro = True
        else:
            self.GenFileListMacro = False

        if self.ListFileMacro in self.MacroList:
            self.GenListFile = True
            self.GenFileListMacro = True
        else:
            self.GenListFile = False

        if self.INC_LIST_MACRO in self.MacroList:
            self.GenIncListFile = True
        else:
            self.GenIncListFile = False

        # Check input files
        self.IsMultipleInput = False
        self.SourceFileExtList = set()
        for File in Input:
            Base, Ext = os.path.splitext(File)
            if Base.find(TAB_STAR) >= 0:
                # There's TAB_STAR in the file name
                self.IsMultipleInput = True
                self.GenFileListMacro = True
            elif Base.find("?") < 0:
                # There's no TAB_STAR and "?" in file name
                self.ExtraSourceFileList.append(File)
                continue
            self.SourceFileExtList.add(Ext)

        # Check output files
        self.DestFileList = []
        for File in Output:
            self.DestFileList.append(File)

        # All build targets generated by this rule for a module
        self.BuildTargets = {}

    ## str() function support
    #
    #   @retval     string
    #
    def __str__(self):
        SourceString = ""
        SourceString += " %s %s %s" % (self.SourceFileType, " ".join(self.SourceFileExtList), self.ExtraSourceFileList)
        DestString = ", ".join([str(i) for i in self.DestFileList])
        CommandString = "\n\t".join(self.CommandList)
        return "%s : %s\n\t%s" % (DestString, SourceString, CommandString)

    def Instantiate(self, Macros = None):
        if Macros is None:
            Macros = {}
        NewRuleObject = copy.copy(self)
        NewRuleObject.BuildTargets = {}
        NewRuleObject.DestFileList = []
        for File in self.DestFileList:
            NewRuleObject.DestFileList.append(PathClass(NormPath(File, Macros)))
        return NewRuleObject

    ## Apply the rule to given source file(s)
    #
    #   @param  SourceFile      One file or a list of files to be built
    #   @param  RelativeToDir   The relative path of the source file
    #   @param  PathSeparator   Path separator
    #
    #   @retval     tuple       (Source file in full path, List of individual sourcefiles, Destination file, List of build commands)
    #
    def Apply(self, SourceFile, BuildRuleOrder=None):
        if not self.CommandList or not self.DestFileList:
            return None

        # source file
        if self.IsMultipleInput:
            SrcFileName = ""
            SrcFileBase = ""
            SrcFileExt = ""
            SrcFileDir = ""
            SrcPath = ""
            # SourceFile must be a list
            SrcFile = "$(%s)" % self.FileListMacro
        else:
            SrcFileName, SrcFileBase, SrcFileExt = SourceFile.Name, SourceFile.BaseName, SourceFile.Ext
            if SourceFile.Root:
                SrcFileDir = SourceFile.SubDir
                if SrcFileDir == "":
                    SrcFileDir = "."
            else:
                SrcFileDir = "."
            SrcFile = SourceFile.Path
            SrcPath = SourceFile.Dir

        # destination file (the first one)
        if self.DestFileList:
            DestFile = self.DestFileList[0].Path
            DestPath = self.DestFileList[0].Dir
            DestFileName = self.DestFileList[0].Name
            DestFileBase, DestFileExt = self.DestFileList[0].BaseName, self.DestFileList[0].Ext
        else:
            DestFile = ""
            DestPath = ""
            DestFileName = ""
            DestFileBase = ""
            DestFileExt = ""

        BuildRulePlaceholderDict = {
            # source file
            "src"       :   SrcFile,
            "s_path"    :   SrcPath,
            "s_dir"     :   SrcFileDir,
            "s_name"    :   SrcFileName,
            "s_base"    :   SrcFileBase,
            "s_ext"     :   SrcFileExt,
            # destination file
            "dst"       :   DestFile,
            "d_path"    :   DestPath,
            "d_name"    :   DestFileName,
            "d_base"    :   DestFileBase,
            "d_ext"     :   DestFileExt,
        }

        DstFile = []
        for File in self.DestFileList:
            File = string.Template(str(File)).safe_substitute(BuildRulePlaceholderDict)
            File = string.Template(str(File)).safe_substitute(BuildRulePlaceholderDict)
            DstFile.append(PathClass(File, IsBinary=True))

        if DstFile[0] in self.BuildTargets:
            TargetDesc = self.BuildTargets[DstFile[0]]
            if BuildRuleOrder and SourceFile.Ext in BuildRuleOrder:
                Index = BuildRuleOrder.index(SourceFile.Ext)
                for Input in TargetDesc.Inputs:
                    if Input.Ext not in BuildRuleOrder or BuildRuleOrder.index(Input.Ext) > Index:
                        #
                        # Command line should be regenerated since some macros are different
                        #
                        CommandList = self._BuildCommand(BuildRulePlaceholderDict)
                        TargetDesc.InitWorker([SourceFile], DstFile, CommandList, self.ExtraSourceFileList)
                        break
            else:
                TargetDesc.AddInput(SourceFile)
        else:
            CommandList = self._BuildCommand(BuildRulePlaceholderDict)
            TargetDesc = TargetDescBlock([SourceFile], DstFile, CommandList, self.ExtraSourceFileList)
            TargetDesc.ListFileMacro = self.ListFileMacro
            TargetDesc.FileListMacro = self.FileListMacro
            TargetDesc.IncListFileMacro = self.IncListFileMacro
            TargetDesc.GenFileListMacro = self.GenFileListMacro
            TargetDesc.GenListFile = self.GenListFile
            TargetDesc.GenIncListFile = self.GenIncListFile
            self.BuildTargets[DstFile[0]] = TargetDesc
        return TargetDesc

    def _BuildCommand(self, Macros):
        CommandList = []
        for CommandString in self.CommandList:
            CommandString = string.Template(CommandString).safe_substitute(Macros)
            CommandString = string.Template(CommandString).safe_substitute(Macros)
            CommandList.append(CommandString)
        return CommandList

## Class for build rules
#
# BuildRule class parses rules defined in a file or passed by caller, and converts
# the rule into FileBuildRule object.
#
class BuildRule:
    _SectionHeader = "SECTIONHEADER"
    _Section = "SECTION"
    _SubSectionHeader = "SUBSECTIONHEADER"
    _SubSection = "SUBSECTION"
    _InputFile = "INPUTFILE"
    _OutputFile = "OUTPUTFILE"
    _ExtraDependency = "EXTRADEPENDENCY"
    _Command = "COMMAND"
    _UnknownSection = "UNKNOWNSECTION"

    _SubSectionList = [_InputFile, _OutputFile, _Command]

    _PATH_SEP = "(+)"
    _FileTypePattern = re.compile("^[_a-zA-Z][_\-0-9a-zA-Z]*$")
    _BinaryFileRule = FileBuildRule(TAB_DEFAULT_BINARY_FILE, [], [os.path.join("$(OUTPUT_DIR)", "${s_name}")],
                                    ["$(CP) ${src} ${dst}"], [])

    ## Constructor
    #
    #   @param  File                The file containing build rules in a well defined format
    #   @param  Content             The string list of build rules in a well defined format
    #   @param  LineIndex           The line number from which the parsing will begin
    #   @param  SupportedFamily     The list of supported tool chain families
    #
    def __init__(self, File=None, Content=None, LineIndex=0, SupportedFamily=[TAB_COMPILER_MSFT, "INTEL", "GCC"]):
        self.RuleFile = File
        # Read build rules from file if it's not none
        if File is not None:
            try:
                self.RuleContent = open(File, 'r').readlines()
            except:
                EdkLogger.error("build", FILE_OPEN_FAILURE, ExtraData=File)
        elif Content is not None:
            self.RuleContent = Content
        else:
            EdkLogger.error("build", PARAMETER_MISSING, ExtraData="No rule file or string given")

        self.SupportedToolChainFamilyList = SupportedFamily
        self.RuleDatabase = tdict(True, 4)  # {FileExt, ModuleType, Arch, Family : FileBuildRule object}
        self.Ext2FileType = {}  # {ext : file-type}
        self.FileTypeList = set()

        self._LineIndex = LineIndex
        self._State = ""
        self._RuleInfo = tdict(True, 2)     # {toolchain family : {"InputFile": {}, "OutputFile" : [], "Command" : []}}
        self._FileType = ''
        self._BuildTypeList = set()
        self._ArchList = set()
        self._FamilyList = []
        self._TotalToolChainFamilySet = set()
        self._RuleObjectList = [] # FileBuildRule object list
        self._FileVersion = ""

        self.Parse()

        # some intrinsic rules
        self.RuleDatabase[TAB_DEFAULT_BINARY_FILE, TAB_COMMON, TAB_COMMON, TAB_COMMON] = self._BinaryFileRule
        self.FileTypeList.add(TAB_DEFAULT_BINARY_FILE)

    ## Parse the build rule strings
    def Parse(self):
        self._State = self._Section
        for Index in range(self._LineIndex, len(self.RuleContent)):
            # Clean up the line and replace path separator with native one
            Line = self.RuleContent[Index].strip().replace(self._PATH_SEP, os.path.sep)
            self.RuleContent[Index] = Line

            # find the build_rule_version
            if Line and Line[0] == "#" and Line.find(TAB_BUILD_RULE_VERSION) != -1:
                if Line.find("=") != -1 and Line.find("=") < (len(Line) - 1) and (Line[(Line.find("=") + 1):]).split():
                    self._FileVersion = (Line[(Line.find("=") + 1):]).split()[0]
            # skip empty or comment line
            if Line == "" or Line[0] == "#":
                continue

            # find out section header, enclosed by []
            if Line[0] == '[' and Line[-1] == ']':
                # merge last section information into rule database
                self.EndOfSection()
                self._State = self._SectionHeader
            # find out sub-section header, enclosed by <>
            elif Line[0] == '<' and Line[-1] == '>':
                if self._State != self._UnknownSection:
                    self._State = self._SubSectionHeader

            # call section handler to parse each (sub)section
            self._StateHandler[self._State](self, Index)
        # merge last section information into rule database
        self.EndOfSection()

    ## Parse definitions under a section
    #
    #   @param  LineIndex   The line index of build rule text
    #
    def ParseSection(self, LineIndex):
        pass

    ## Parse definitions under a subsection
    #
    #   @param  LineIndex   The line index of build rule text
    #
    def ParseSubSection(self, LineIndex):
        # currently nothing here
        pass

    ## Placeholder for not supported sections
    #
    #   @param  LineIndex   The line index of build rule text
    #
    def SkipSection(self, LineIndex):
        pass

    ## Merge section information just got into rule database
    def EndOfSection(self):
        Database = self.RuleDatabase
        # if there's specific toolchain family, 'COMMON' doesn't make sense any more
        if len(self._TotalToolChainFamilySet) > 1 and TAB_COMMON in self._TotalToolChainFamilySet:
            self._TotalToolChainFamilySet.remove(TAB_COMMON)
        for Family in self._TotalToolChainFamilySet:
            Input = self._RuleInfo[Family, self._InputFile]
            Output = self._RuleInfo[Family, self._OutputFile]
            Command = self._RuleInfo[Family, self._Command]
            ExtraDependency = self._RuleInfo[Family, self._ExtraDependency]

            BuildRule = FileBuildRule(self._FileType, Input, Output, Command, ExtraDependency)
            for BuildType in self._BuildTypeList:
                for Arch in self._ArchList:
                    Database[self._FileType, BuildType, Arch, Family] = BuildRule
                    for FileExt in BuildRule.SourceFileExtList:
                        self.Ext2FileType[FileExt] = self._FileType

    ## Parse section header
    #
    #   @param  LineIndex   The line index of build rule text
    #
    def ParseSectionHeader(self, LineIndex):
        self._RuleInfo = tdict(True, 2)
        self._BuildTypeList = set()
        self._ArchList = set()
        self._FamilyList = []
        self._TotalToolChainFamilySet = set()
        FileType = ''
        RuleNameList = self.RuleContent[LineIndex][1:-1].split(',')
        for RuleName in RuleNameList:
            Arch = TAB_COMMON
            BuildType = TAB_COMMON
            TokenList = [Token.strip().upper() for Token in RuleName.split('.')]
            # old format: Build.File-Type
            if TokenList[0] == "BUILD":
                if len(TokenList) == 1:
                    EdkLogger.error("build", FORMAT_INVALID, "Invalid rule section",
                                    File=self.RuleFile, Line=LineIndex + 1,
                                    ExtraData=self.RuleContent[LineIndex])

                FileType = TokenList[1]
                if FileType == '':
                    EdkLogger.error("build", FORMAT_INVALID, "No file type given",
                                    File=self.RuleFile, Line=LineIndex + 1,
                                    ExtraData=self.RuleContent[LineIndex])
                if self._FileTypePattern.match(FileType) is None:
                    EdkLogger.error("build", FORMAT_INVALID, File=self.RuleFile, Line=LineIndex + 1,
                                    ExtraData="Only character, number (non-first character), '_' and '-' are allowed in file type")
            # new format: File-Type.Build-Type.Arch
            else:
                if FileType == '':
                    FileType = TokenList[0]
                elif FileType != TokenList[0]:
                    EdkLogger.error("build", FORMAT_INVALID,
                                    "Different file types are not allowed in the same rule section",
                                    File=self.RuleFile, Line=LineIndex + 1,
                                    ExtraData=self.RuleContent[LineIndex])
                if len(TokenList) > 1:
                    BuildType = TokenList[1]
                if len(TokenList) > 2:
                    Arch = TokenList[2]
            self._BuildTypeList.add(BuildType)
            self._ArchList.add(Arch)

        if TAB_COMMON in self._BuildTypeList and len(self._BuildTypeList) > 1:
            EdkLogger.error("build", FORMAT_INVALID,
                            "Specific build types must not be mixed with common one",
                            File=self.RuleFile, Line=LineIndex + 1,
                            ExtraData=self.RuleContent[LineIndex])
        if TAB_COMMON in self._ArchList and len(self._ArchList) > 1:
            EdkLogger.error("build", FORMAT_INVALID,
                            "Specific ARCH must not be mixed with common one",
                            File=self.RuleFile, Line=LineIndex + 1,
                            ExtraData=self.RuleContent[LineIndex])

        self._FileType = FileType
        self._State = self._Section
        self.FileTypeList.add(FileType)

    ## Parse sub-section header
    #
    #   @param  LineIndex   The line index of build rule text
    #
    def ParseSubSectionHeader(self, LineIndex):
        SectionType = ""
        List = self.RuleContent[LineIndex][1:-1].split(',')
        FamilyList = []
        for Section in List:
            TokenList = Section.split('.')
            Type = TokenList[0].strip().upper()

            if SectionType == "":
                SectionType = Type
            elif SectionType != Type:
                EdkLogger.error("build", FORMAT_INVALID,
                                "Two different section types are not allowed in the same sub-section",
                                File=self.RuleFile, Line=LineIndex + 1,
                                ExtraData=self.RuleContent[LineIndex])

            if len(TokenList) > 1:
                Family = TokenList[1].strip().upper()
            else:
                Family = TAB_COMMON

            if Family not in FamilyList:
                FamilyList.append(Family)

        self._FamilyList = FamilyList
        self._TotalToolChainFamilySet.update(FamilyList)
        self._State = SectionType.upper()
        if TAB_COMMON in FamilyList and len(FamilyList) > 1:
            EdkLogger.error("build", FORMAT_INVALID,
                            "Specific tool chain family should not be mixed with general one",
                            File=self.RuleFile, Line=LineIndex + 1,
                            ExtraData=self.RuleContent[LineIndex])
        if self._State not in self._StateHandler:
            EdkLogger.error("build", FORMAT_INVALID, File=self.RuleFile, Line=LineIndex + 1,
                            ExtraData="Unknown subsection: %s" % self.RuleContent[LineIndex])
    ## Parse <InputFile> sub-section
    #
    #   @param  LineIndex   The line index of build rule text
    #
    def ParseInputFileSubSection(self, LineIndex):
        FileList = [File.strip() for File in self.RuleContent[LineIndex].split(",")]
        for ToolChainFamily in self._FamilyList:
            if self._RuleInfo[ToolChainFamily, self._State] is None:
                self._RuleInfo[ToolChainFamily, self._State] = []
            self._RuleInfo[ToolChainFamily, self._State].extend(FileList)

    ## Parse <ExtraDependency> sub-section
    ## Parse <OutputFile> sub-section
    ## Parse <Command> sub-section
    #
    #   @param  LineIndex   The line index of build rule text
    #
    def ParseCommonSubSection(self, LineIndex):
        for ToolChainFamily in self._FamilyList:
            if self._RuleInfo[ToolChainFamily, self._State] is None:
                self._RuleInfo[ToolChainFamily, self._State] = []
            self._RuleInfo[ToolChainFamily, self._State].append(self.RuleContent[LineIndex])

    ## Get a build rule via [] operator
    #
    #   @param  FileExt             The extension of a file
    #   @param  ToolChainFamily     The tool chain family name
    #   @param  BuildVersion        The build version number. TAB_STAR means any rule
    #                               is applicable.
    #
    #   @retval FileType        The file type string
    #   @retval FileBuildRule   The object of FileBuildRule
    #
    # Key = (FileExt, ModuleType, Arch, ToolChainFamily)
    def __getitem__(self, Key):
        if not Key:
            return None

        if Key[0] in self.Ext2FileType:
            Type = self.Ext2FileType[Key[0]]
        elif Key[0].upper() in self.FileTypeList:
            Type = Key[0].upper()
        else:
            return None

        if len(Key) > 1:
            Key = (Type,) + Key[1:]
        else:
            Key = (Type,)
        return self.RuleDatabase[Key]

    _StateHandler = {
        _SectionHeader     : ParseSectionHeader,
        _Section           : ParseSection,
        _SubSectionHeader  : ParseSubSectionHeader,
        _SubSection        : ParseSubSection,
        _InputFile         : ParseInputFileSubSection,
        _OutputFile        : ParseCommonSubSection,
        _ExtraDependency   : ParseCommonSubSection,
        _Command           : ParseCommonSubSection,
        _UnknownSection    : SkipSection,
    }

class ToolBuildRule():

    def __new__(cls, *args, **kw):
        if not hasattr(cls, '_instance'):
            orig = super(ToolBuildRule, cls)
            cls._instance = orig.__new__(cls, *args, **kw)
        return cls._instance

    def __init__(self):
        if not hasattr(self, 'ToolBuildRule'):
            self._ToolBuildRule = None

    @property
    def ToolBuildRule(self):
        if not self._ToolBuildRule:
            self._GetBuildRule()
        return self._ToolBuildRule

    def _GetBuildRule(self):
        BuildRuleFile = None
        TargetObj = TargetTxtDict()
        TargetTxt = TargetObj.Target
        if TAB_TAT_DEFINES_BUILD_RULE_CONF in TargetTxt.TargetTxtDictionary:
            BuildRuleFile = TargetTxt.TargetTxtDictionary[TAB_TAT_DEFINES_BUILD_RULE_CONF]
        if not BuildRuleFile:
            BuildRuleFile = gDefaultBuildRuleFile
        RetVal = BuildRule(BuildRuleFile)
        if RetVal._FileVersion == "":
            RetVal._FileVersion = AutoGenReqBuildRuleVerNum
        else:
            if RetVal._FileVersion < AutoGenReqBuildRuleVerNum :
                # If Build Rule's version is less than the version number required by the tools, halting the build.
                EdkLogger.error("build", AUTOGEN_ERROR,
                                ExtraData="The version number [%s] of build_rule.txt is less than the version number required by the AutoGen.(the minimum required version number is [%s])"\
                                 % (RetVal._FileVersion, AutoGenReqBuildRuleVerNum))
        self._ToolBuildRule = RetVal

# This acts like the main() function for the script, unless it is 'import'ed into another
# script.
if __name__ == '__main__':
    import sys
    EdkLogger.Initialize()
    if len(sys.argv) > 1:
        Br = BuildRule(sys.argv[1])
        print(str(Br[".c", SUP_MODULE_DXE_DRIVER, "IA32", TAB_COMPILER_MSFT][1]))
        print()
        print(str(Br[".c", SUP_MODULE_DXE_DRIVER, "IA32", "INTEL"][1]))
        print()
        print(str(Br[".c", SUP_MODULE_DXE_DRIVER, "IA32", "GCC"][1]))
        print()
        print(str(Br[".ac", "ACPI_TABLE", "IA32", TAB_COMPILER_MSFT][1]))
        print()
        print(str(Br[".h", "ACPI_TABLE", "IA32", "INTEL"][1]))
        print()
        print(str(Br[".ac", "ACPI_TABLE", "IA32", TAB_COMPILER_MSFT][1]))
        print()
        print(str(Br[".s", SUP_MODULE_SEC, "IPF", "COMMON"][1]))
        print()
        print(str(Br[".s", SUP_MODULE_SEC][1]))

