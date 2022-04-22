## @file
# This file is used to parse a PCD file of .PKG file
#
# Copyright (c) 2011 - 2018, Intel Corporation. All rights reserved.<BR>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#

'''
CommonXml
'''

##
# Import Modules
#

from Core.DistributionPackageClass import DistributionPackageHeaderObject
from Library.StringUtils import ConvertNEToNOTEQ
from Library.StringUtils import ConvertNOTEQToNE
from Library.StringUtils import GetSplitValueList
from Library.StringUtils import GetStringOfList
from Library.Xml.XmlRoutines import XmlElement
from Library.Xml.XmlRoutines import XmlElement2
from Library.Xml.XmlRoutines import XmlAttribute
from Library.Xml.XmlRoutines import XmlNode
from Library.Xml.XmlRoutines import XmlList
from Library.Xml.XmlRoutines import CreateXmlElement
from Library.UniClassObject import ConvertSpecialUnicodes
from Library.UniClassObject import GetLanguageCode1766
from Object.POM.CommonObject import FileObject
from Object.POM.CommonObject import MiscFileObject
from Object.POM.CommonObject import UserExtensionObject
from Object.POM.CommonObject import ClonedRecordObject
from Object.POM.CommonObject import LibraryClassObject
from Object.POM.CommonObject import FileNameObject
from Object.POM.ModuleObject import ModuleObject
from Xml.XmlParserMisc import IsRequiredItemListNull
from Xml.XmlParserMisc import GetHelpTextList
import Library.DataType as DataType

##
# ClonedFromXml
#
class ClonedFromXml(object):
    def __init__(self):
        self.GUID = ''
        self.Version = ''

    def FromXml(self, Item, Key):
        self.GUID = XmlElement(Item, '%s/GUID' % Key)
        self.Version = XmlAttribute(XmlNode(Item, '%s/GUID' % Key), 'Version')
        if self.GUID == '' and self.Version == '':
            return None
        ClonedFrom = ClonedRecordObject()
        ClonedFrom.SetPackageGuid(self.GUID)
        ClonedFrom.SetPackageVersion(self.Version)
        return ClonedFrom

    def ToXml(self, ClonedFrom, Key):
        if self.GUID:
            pass
        Element1 = CreateXmlElement('GUID', ClonedFrom.GetPackageGuid(), [],
                                    [['Version', ClonedFrom.GetPackageVersion()]])
        AttributeList = []
        NodeList = [Element1]
        Root = CreateXmlElement('%s' % Key, '', NodeList, AttributeList)
        return Root

    def __str__(self):
        return "GUID = %s Version = %s" % (self.GUID, self.Version)


##
# CommonDefinesXml
#
class CommonDefinesXml(object):
    def __init__(self):
        self.Usage = ''
        self.SupArchList = []
        self.SupModList = []
        self.FeatureFlag = ''

    def FromXml(self, Item, Key):
        if Key:
            pass
        self.Usage = XmlAttribute(Item, 'Usage')
        self.SupArchList = \
        [Arch for Arch in GetSplitValueList(XmlAttribute(Item, 'SupArchList'), DataType.TAB_SPACE_SPLIT) if Arch]
        self.SupModList = \
        [Mod for Mod in GetSplitValueList(XmlAttribute(Item, 'SupModList'), DataType.TAB_SPACE_SPLIT) if Mod]
        self.FeatureFlag = ConvertNOTEQToNE(XmlAttribute(Item, 'FeatureFlag'))

    def ToXml(self):
        pass

    def __str__(self):
        return "Usage = %s SupArchList = %s SupModList = %s FeatureFlag = %s" \
                % (self.Usage, self.SupArchList, self.SupModList, self.FeatureFlag)

##
# PromptXml
#
class PromptXml(object):
    def __init__(self):
        self.Prompt = ''
        self.Lang = ''

    def FromXml(self, Item, Key):
        if Key:
            pass
        self.Prompt = XmlElement2(Item, 'Prompt')
        self.Lang = XmlAttribute(Item, 'Lang')

    def ToXml(self, Prompt, Key='Prompt'):
        if self.Prompt:
            pass
        return CreateXmlElement('%s' % Key, Prompt.GetString(), [], [['Lang', Prompt.GetLang()]])
    def __str__(self):
        return "Prompt = %s Lang = %s" % (self.Prompt, self.Lang)

##
# HelpTextXml
#
class HelpTextXml(object):
    def __init__(self):
        self.HelpText = ''
        self.Lang = ''

    def FromXml(self, Item, Key):
        if Key:
            pass
        self.HelpText = XmlElement2(Item, 'HelpText')
        self.Lang = XmlAttribute(Item, 'Lang')

    def ToXml(self, HelpText, Key='HelpText'):
        if self.HelpText:
            pass
        return CreateXmlElement('%s' % Key, HelpText.GetString(), [], [['Lang', HelpText.GetLang()]])
    def __str__(self):
        return "HelpText = %s Lang = %s" % (self.HelpText, self.Lang)

##
# HeaderXml
#
class HeaderXml(object):
    def __init__(self):
        self.Name = ''
        self.BaseName = ''
        self.GUID = ''
        self.Version = ''
        self.CopyrightList = []
        self.LicenseList = []
        self.AbstractList = []
        self.DescriptionList = []

    def FromXml(self, Item, Key, IsRequiredCheck=False, IsStandAlongModule=False):
        if not Item and IsRequiredCheck:
            XmlTreeLevel = []
            if IsStandAlongModule:
                XmlTreeLevel = ['DistributionPackage', 'ModuleSurfaceArea']
            else:
                XmlTreeLevel = ['DistributionPackage', 'PackageSurfaceArea', 'ModuleSurfaceArea']
            CheckDict = {'Header':''}
            IsRequiredItemListNull(CheckDict, XmlTreeLevel)
        self.Name = XmlElement(Item, '%s/Name' % Key)
        self.BaseName = XmlAttribute(XmlNode(Item, '%s/Name' % Key), 'BaseName')
        self.GUID = XmlElement(Item, '%s/GUID' % Key)
        self.Version = XmlAttribute(XmlNode(Item, '%s/GUID' % Key), 'Version')

        for SubItem in XmlList(Item, '%s/Abstract' % Key):
            HeaderAbstractLang = XmlAttribute(SubItem, 'Lang')
            self.AbstractList.append((HeaderAbstractLang, XmlElement(SubItem, '%s/Abstract' % Key)))
        for SubItem in XmlList(Item, '%s/Description' % Key):
            HeaderDescriptionLang = XmlAttribute(SubItem, 'Lang')
            self.DescriptionList.append((HeaderDescriptionLang, XmlElement(SubItem, '%s/Description' % Key)))
        for SubItem in XmlList(Item, '%s/Copyright' % Key):
            HeaderCopyrightLang = XmlAttribute(SubItem, 'Lang')
            self.CopyrightList.append((HeaderCopyrightLang, XmlElement(SubItem, '%s/Copyright' % Key)))
        for SubItem in XmlList(Item, '%s/License' % Key):
            HeaderLicenseLang = XmlAttribute(SubItem, 'Lang')
            self.LicenseList.append((HeaderLicenseLang, XmlElement(SubItem, '%s/License' % Key)))
        ModuleHeader = ModuleObject()
        ModuleHeader.SetName(self.Name)
        ModuleHeader.SetBaseName(self.BaseName)
        ModuleHeader.SetGuid(self.GUID)
        ModuleHeader.SetVersion(self.Version)
        ModuleHeader.SetCopyright(self.CopyrightList)
        ModuleHeader.SetLicense(self.LicenseList)
        ModuleHeader.SetAbstract(self.AbstractList)
        ModuleHeader.SetDescription(self.DescriptionList)
        return ModuleHeader

    def ToXml(self, Header, Key):
        if self.GUID:
            pass
        Element1 = CreateXmlElement('Name', Header.GetName(), [], [['BaseName', Header.GetBaseName()]])
        Element2 = CreateXmlElement('GUID', Header.GetGuid(), [], [['Version', Header.GetVersion()]])
        NodeList = [Element1,
                    Element2,
                    ]

        UNIInfAbstractList = []
        UNIInfDescriptionList = []
        # Get Abstract and Description from Uni File
        # if the Uni File exists
        if Header.UniFileClassObject is not None:
            UniStrDict = Header.UniFileClassObject.OrderedStringList
            for Lang in UniStrDict:
                for StringDefClassObject in UniStrDict[Lang]:
                    if not StringDefClassObject.StringValue:
                        continue
                    if StringDefClassObject.StringName == DataType.TAB_INF_ABSTRACT:
                        UNIInfAbstractList.append((GetLanguageCode1766(Lang),
                                                   ConvertSpecialUnicodes(StringDefClassObject.StringValue)))

                    if StringDefClassObject.StringName == DataType.TAB_INF_DESCRIPTION:
                        UNIInfDescriptionList.append((GetLanguageCode1766(Lang),
                                                      ConvertSpecialUnicodes(StringDefClassObject.StringValue)))

        # Get Abstract and Description from INF File Header
        for (Lang, Value) in Header.GetCopyright():
            if Value:
                NodeList.append(CreateXmlElement('Copyright', Value, [], []))
        for (Lang, Value) in Header.GetLicense():
            if Value:
                NodeList.append(CreateXmlElement('License', Value, [], []))
        for (Lang, Value) in Header.GetAbstract() + UNIInfAbstractList:
            if Value:
                NodeList.append(CreateXmlElement('Abstract', Value, [], [['Lang', Lang]]))
        for (Lang, Value) in Header.GetDescription() + UNIInfDescriptionList:
            if Value:
                NodeList.append(CreateXmlElement('Description', Value, [], [['Lang', Lang]]))

        AttributeList = []
        Root = CreateXmlElement('%s' % Key, '', NodeList, AttributeList)
        return Root

    def __str__(self):
        return "Name = %s BaseName = %s GUID = %s Version = %s Copyright = %s \
        License = %s Abstract = %s Description = %s" % \
        (self.Name, self.BaseName, self.GUID, self.Version, self.CopyrightList, \
         self.LicenseList, self.AbstractList, self.DescriptionList)
##
# DistributionPackageHeaderXml
#
class DistributionPackageHeaderXml(object):
    def __init__(self):
        self.Header = HeaderXml()
        self.ReadOnly = ''
        self.RePackage = ''
        self.Vendor = ''
        self.Date = ''
        self.Signature = ''
        self.XmlSpecification = ''

    def FromXml(self, Item, Key):
        if not Item:
            return None
        self.ReadOnly = XmlAttribute(XmlNode(Item, '%s' % Key), 'ReadOnly')
        self.RePackage = XmlAttribute(XmlNode(Item, '%s' % Key), 'RePackage')
        self.Vendor = XmlElement(Item, '%s/Vendor' % Key)
        self.Date = XmlElement(Item, '%s/Date' % Key)
        self.Signature = XmlElement(Item, '%s/Signature' % Key)
        self.XmlSpecification = XmlElement(Item, '%s/XmlSpecification' % Key)
        self.Header.FromXml(Item, Key)
        DistributionPackageHeader = DistributionPackageHeaderObject()
        if self.ReadOnly.upper() == 'TRUE':
            DistributionPackageHeader.ReadOnly = True
        elif self.ReadOnly.upper() == 'FALSE':
            DistributionPackageHeader.ReadOnly = False
        if self.RePackage.upper() == 'TRUE':
            DistributionPackageHeader.RePackage = True
        elif self.RePackage.upper() == 'FALSE':
            DistributionPackageHeader.RePackage = False
        DistributionPackageHeader.Vendor = self.Vendor
        DistributionPackageHeader.Date = self.Date
        DistributionPackageHeader.Signature = self.Signature
        DistributionPackageHeader.XmlSpecification = self.XmlSpecification
        DistributionPackageHeader.SetName(self.Header.Name)
        DistributionPackageHeader.SetBaseName(self.Header.BaseName)
        DistributionPackageHeader.SetGuid(self.Header.GUID)
        DistributionPackageHeader.SetVersion(self.Header.Version)
        DistributionPackageHeader.SetCopyright(self.Header.CopyrightList)
        DistributionPackageHeader.SetLicense(self.Header.LicenseList)
        DistributionPackageHeader.SetAbstract(self.Header.AbstractList)
        DistributionPackageHeader.SetDescription(self.Header.DescriptionList)
        return DistributionPackageHeader

    def ToXml(self, DistributionPackageHeader, Key):
        if self.Header:
            pass
        Element1 = CreateXmlElement('Name', \
                                    DistributionPackageHeader.GetName(), [], \
                                    [['BaseName', \
                                    DistributionPackageHeader.GetBaseName()]])
        Element2 = CreateXmlElement('GUID', \
                                    DistributionPackageHeader.GetGuid(), [], \
                                    [['Version', \
                                    DistributionPackageHeader.GetVersion()]])
        AttributeList = []
        if DistributionPackageHeader.ReadOnly != '':
            AttributeList.append(['ReadOnly', str(DistributionPackageHeader.ReadOnly).lower()])
        if DistributionPackageHeader.RePackage != '':
            AttributeList.append(['RePackage', str(DistributionPackageHeader.RePackage).lower()])
        if DistributionPackageHeader.GetAbstract():
            DPAbstract = DistributionPackageHeader.GetAbstract()[0][1]
        else:
            DPAbstract = ''
        if DistributionPackageHeader.GetDescription():
            DPDescription = DistributionPackageHeader.GetDescription()[0][1]
        else:
            DPDescription = ''
        if DistributionPackageHeader.GetCopyright():
            DPCopyright = DistributionPackageHeader.GetCopyright()[0][1]
        else:
            DPCopyright = ''
        if DistributionPackageHeader.GetLicense():
            DPLicense = DistributionPackageHeader.GetLicense()[0][1]
        else:
            DPLicense = ''
        NodeList = [Element1,
                    Element2,
                    ['Vendor', DistributionPackageHeader.Vendor],
                    ['Date', DistributionPackageHeader.Date],
                    ['Copyright', DPCopyright],
                    ['License', DPLicense],
                    ['Abstract', DPAbstract],
                    ['Description', DPDescription],
                    ['Signature', DistributionPackageHeader.Signature],
                    ['XmlSpecification', \
                     DistributionPackageHeader.XmlSpecification],
                    ]
        Root = CreateXmlElement('%s' % Key, '', NodeList, AttributeList)
        return Root

    def __str__(self):
        return "ReadOnly = %s RePackage = %s Vendor = %s Date = %s \
        Signature = %s XmlSpecification = %s %s" % \
        (self.ReadOnly, self.RePackage, self.Vendor, self.Date, \
         self.Signature, self.XmlSpecification, self.Header)
##
# PackageHeaderXml
#
class PackageHeaderXml(object):
    def __init__(self):
        self.Header = HeaderXml()
        self.PackagePath = ''

    def FromXml(self, Item, Key, PackageObject2):
        if not Item:
            XmlTreeLevel = ['DistributionPackage', 'PackageSurfaceArea']
            CheckDict = {'PackageHeader': None, }
            IsRequiredItemListNull(CheckDict, XmlTreeLevel)
        self.PackagePath = XmlElement(Item, '%s/PackagePath' % Key)
        self.Header.FromXml(Item, Key)
        PackageObject2.SetName(self.Header.Name)
        PackageObject2.SetBaseName(self.Header.BaseName)
        PackageObject2.SetGuid(self.Header.GUID)
        PackageObject2.SetVersion(self.Header.Version)
        PackageObject2.SetCopyright(self.Header.CopyrightList)
        PackageObject2.SetLicense(self.Header.LicenseList)
        PackageObject2.SetAbstract(self.Header.AbstractList)
        PackageObject2.SetDescription(self.Header.DescriptionList)
        PackageObject2.SetPackagePath(self.PackagePath)

    def ToXml(self, PackageObject2, Key):
        if self.PackagePath:
            pass
        Element1 = CreateXmlElement('Name', PackageObject2.GetName(), [], \
                         [['BaseName', PackageObject2.GetBaseName()]])
        Element2 = CreateXmlElement('GUID', PackageObject2.GetGuid(), [], \
                                    [['Version', PackageObject2.GetVersion()]])
        NodeList = [Element1,
                    Element2
                    ]

        UNIPackageAbrstractList = []
        UNIPackageDescriptionList = []
        # Get Abstract and Description from Uni File
        # if the Uni File exists
        if PackageObject2.UniFileClassObject is not None:
            UniStrDict = PackageObject2.UniFileClassObject.OrderedStringList
            for Lang in UniStrDict:
                for StringDefClassObject in UniStrDict[Lang]:
                    if not StringDefClassObject.StringValue:
                        continue
                    if StringDefClassObject.StringName == DataType.TAB_DEC_PACKAGE_ABSTRACT:
                        UNIPackageAbrstractList.append((GetLanguageCode1766(Lang),
                                                        ConvertSpecialUnicodes(StringDefClassObject.StringValue)))

                    if StringDefClassObject.StringName == DataType.TAB_DEC_PACKAGE_DESCRIPTION:
                        UNIPackageDescriptionList.append((GetLanguageCode1766(Lang),
                                                          ConvertSpecialUnicodes(StringDefClassObject.StringValue)))

        # Get Abstract and Description from DEC File Header
        for (Lang, Value) in PackageObject2.GetCopyright():
            if Value:
                NodeList.append(CreateXmlElement(DataType.TAB_HEADER_COPYRIGHT, Value, [], []))
        for (Lang, Value) in PackageObject2.GetLicense():
            if Value:
                NodeList.append(CreateXmlElement(DataType.TAB_HEADER_LICENSE, Value, [], []))
        for (Lang, Value) in PackageObject2.GetAbstract() + UNIPackageAbrstractList:
            if Value:
                NodeList.append(CreateXmlElement(DataType.TAB_HEADER_ABSTRACT, Value, [], [['Lang', Lang]]))
        for (Lang, Value) in PackageObject2.GetDescription() + UNIPackageDescriptionList:
            if Value:
                NodeList.append(CreateXmlElement(DataType.TAB_HEADER_DESCRIPTION, Value, [], [['Lang', Lang]]))


        NodeList.append(['PackagePath', PackageObject2.GetPackagePath()])
        AttributeList = []
        Root = CreateXmlElement('%s' % Key, '', NodeList, AttributeList)
        return Root

    def __str__(self):
        return "PackagePath = %s %s" \
               % (self.PackagePath, self.Header)

##
# MiscellaneousFileXml
#
class MiscellaneousFileXml(object):
    def __init__(self):
        self.Header = HeaderXml()
        self.Files = []
    ##
    # This API is used for Package or Module's MiscellaneousFile section
    #
    def FromXml(self, Item, Key):
        if not Item:
            return None
        self.Header.FromXml(Item, Key)
        NewItem = XmlNode(Item, '%s/Header' % Key)
        self.Header.FromXml(NewItem, 'Header')
        for SubItem in XmlList(Item, '%s/Filename' % Key):
            Filename = XmlElement(SubItem, '%s/Filename' % Key)
            Executable = XmlAttribute(XmlNode(SubItem, '%s/Filename' % Key), 'Executable')
            if Executable.upper() == "TRUE":
                Executable = True
            elif Executable.upper() == "FALSE":
                Executable = False
            else:
                Executable = ''
            self.Files.append([Filename, Executable])
        MiscFile = MiscFileObject()
        MiscFile.SetCopyright(self.Header.CopyrightList)
        MiscFile.SetLicense(self.Header.LicenseList)
        MiscFile.SetAbstract(self.Header.AbstractList)
        MiscFile.SetDescription(self.Header.DescriptionList)
        MiscFileList = []
        for File in self.Files:
            FileObj = FileObject()
            FileObj.SetURI(File[0])
            FileObj.SetExecutable(File[1])
            MiscFileList.append(FileObj)
        MiscFile.SetFileList(MiscFileList)
        return MiscFile
    ##
    # This API is used for DistP's tool section
    #
    def FromXml2(self, Item, Key):
        if Item is None:
            return None
        NewItem = XmlNode(Item, '%s/Header' % Key)
        self.Header.FromXml(NewItem, 'Header')
        for SubItem in XmlList(Item, '%s/Filename' % Key):
            Filename = XmlElement(SubItem, '%s/Filename' % Key)
            Executable = \
            XmlAttribute(XmlNode(SubItem, '%s/Filename' % Key), 'Executable')
            OsType = XmlAttribute(XmlNode(SubItem, '%s/Filename' % Key), 'OS')
            if Executable.upper() == "TRUE":
                Executable = True
            elif Executable.upper() == "FALSE":
                Executable = False
            else:
                Executable = ''
            self.Files.append([Filename, Executable, OsType])
        MiscFile = MiscFileObject()
        MiscFile.SetName(self.Header.Name)
        MiscFile.SetCopyright(self.Header.CopyrightList)
        MiscFile.SetLicense(self.Header.LicenseList)
        MiscFile.SetAbstract(self.Header.AbstractList)
        MiscFile.SetDescription(self.Header.DescriptionList)
        MiscFileList = []
        for File in self.Files:
            FileObj = FileObject()
            FileObj.SetURI(File[0])
            FileObj.SetExecutable(File[1])
            FileObj.SetOS(File[2])
            MiscFileList.append(FileObj)
        MiscFile.SetFileList(MiscFileList)
        return MiscFile

    ##
    # This API is used for Package or Module's MiscellaneousFile section
    #
    def ToXml(self, MiscFile, Key):
        if self.Header:
            pass
        if MiscFile:
            if MiscFile.GetAbstract():
                DPAbstract = MiscFile.GetAbstract()[0][1]
            else:
                DPAbstract = ''
            if MiscFile.GetDescription():
                DPDescription = MiscFile.GetDescription()[0][1]
            else:
                DPDescription = ''
            if MiscFile.GetCopyright():
                DPCopyright = MiscFile.GetCopyright()[0][1]
            else:
                DPCopyright = ''
            if MiscFile.GetLicense():
                DPLicense = MiscFile.GetLicense()[0][1]
            else:
                DPLicense = ''
            NodeList = [['Copyright', DPCopyright],
                        ['License', DPLicense],
                        ['Abstract', DPAbstract],
                        ['Description', DPDescription],
                       ]
            for File in MiscFile.GetFileList():
                NodeList.append\
                (CreateXmlElement\
                 ('Filename', File.GetURI(), [], \
                  [['Executable', str(File.GetExecutable()).lower()]]))
            Root = CreateXmlElement('%s' % Key, '', NodeList, [])
            return Root
    ##
    # This API is used for DistP's tool section
    #
    def ToXml2(self, MiscFile, Key):
        if self.Header:
            pass
        if MiscFile:
            if MiscFile.GetAbstract():
                DPAbstract = MiscFile.GetAbstract()[0][1]
            else:
                DPAbstract = ''
            if MiscFile.GetDescription():
                DPDescription = MiscFile.GetDescription()[0][1]
            else:
                DPDescription = ''
            if MiscFile.GetCopyright():
                DPCopyright = MiscFile.GetCopyright()[0][1]
            else:
                DPCopyright = ''
            if MiscFile.GetLicense():
                DPLicense = MiscFile.GetLicense()[0][1]
            else:
                DPLicense = ''
            NodeList = [['Name', MiscFile.GetName()],
                        ['Copyright', DPCopyright],
                        ['License', DPLicense],
                        ['Abstract', DPAbstract],
                        ['Description', DPDescription],
                       ]
            HeaderNode = CreateXmlElement('Header', '', NodeList, [])
            NodeList = [HeaderNode]
            for File in MiscFile.GetFileList():
                NodeList.append\
                (CreateXmlElement\
                 ('Filename', File.GetURI(), [], \
                  [['Executable', str(File.GetExecutable()).lower()], \
                   ['OS', File.GetOS()]]))
            Root = CreateXmlElement('%s' % Key, '', NodeList, [])
            return Root

    def __str__(self):
        Str = str(self.Header)
        for Item in self.Files:
            Str = Str + '\n\tFilename:' + str(Item)
        return Str
##
# UserExtensionsXml
#
class UserExtensionsXml(object):
    def __init__(self):
        self.UserId = ''
        self.Identifier = ''
        self.BinaryAbstractList = []
        self.BinaryDescriptionList = []
        self.BinaryCopyrightList = []
        self.BinaryLicenseList = []
        self.LangDefsList = []
        self.DefineDict = {}
        self.BuildOptionDict = {}
        self.IncludesDict = {}
        self.SourcesDict = {}
        self.BinariesDict = {}
        self.SupArchList = []
        self.Statement = ''
        self.Defines = ''
        self.BuildOptions = ''

    def FromXml2(self, Item, Key):
        self.UserId = XmlAttribute(XmlNode(Item, '%s' % Key), 'UserId')
        self.Identifier = XmlAttribute(XmlNode(Item, '%s' % Key), 'Identifier')
        UserExtension = UserExtensionObject()
        UserExtension.SetUserID(self.UserId)
        UserExtension.SetIdentifier(self.Identifier)
        return UserExtension

    def FromXml(self, Item, Key):
        self.UserId = XmlAttribute(XmlNode(Item, '%s' % Key), 'UserId')
        self.Identifier = XmlAttribute(XmlNode(Item, '%s' % Key), 'Identifier')
        if self.UserId == DataType.TAB_BINARY_HEADER_USERID \
        and self.Identifier == DataType.TAB_BINARY_HEADER_IDENTIFIER:
            for SubItem in XmlList(Item, '%s/BinaryAbstract' % Key):
                BinaryAbstractLang = XmlAttribute(SubItem, 'Lang')
                self.BinaryAbstractList.append((BinaryAbstractLang, XmlElement(SubItem, '%s/BinaryAbstract' % Key)))
            for SubItem in XmlList(Item, '%s/BinaryDescription' % Key):
                BinaryDescriptionLang = XmlAttribute(SubItem, 'Lang')
                self.BinaryDescriptionList.append((BinaryDescriptionLang,
                                                       XmlElement(SubItem, '%s/BinaryDescription' % Key)))
            for SubItem in XmlList(Item, '%s/BinaryCopyright' % Key):
                BinaryCopyrightLang = XmlAttribute(SubItem, 'Lang')
                self.BinaryCopyrightList.append((BinaryCopyrightLang,
                                                     XmlElement(SubItem, '%s/BinaryCopyright' % Key)))
            for SubItem in XmlList(Item, '%s/BinaryLicense' % Key):
                BinaryLicenseLang = XmlAttribute(SubItem, 'Lang')
                self.BinaryLicenseList.append((BinaryLicenseLang,
                                                   XmlElement(SubItem, '%s/BinaryLicense' % Key)))

        DefineItem = XmlNode(Item, '%s/Define' % Key)
        for SubItem in XmlList(DefineItem, 'Define/Statement'):
            Statement = XmlElement(SubItem, '%s/Statement' % Key)
            self.DefineDict[Statement] = ""
        BuildOptionItem = XmlNode(Item, '%s/BuildOption' % Key)
        for SubItem in XmlList(BuildOptionItem, 'BuildOption/Statement'):
            Statement = XmlElement(SubItem, '%s/Statement' % Key)
            Arch = XmlAttribute(XmlNode(SubItem, '%s/Statement' % Key), 'SupArchList')
            self.BuildOptionDict[Arch] = Statement
        IncludesItem = XmlNode(Item, '%s/Includes' % Key)
        for SubItem in XmlList(IncludesItem, 'Includes/Statement'):
            Statement = XmlElement(SubItem, '%s/Statement' % Key)
            Arch = XmlAttribute(XmlNode(SubItem, '%s/Statement' % Key), 'SupArchList')
            self.IncludesDict[Statement] = Arch
        SourcesItem = XmlNode(Item, '%s/Sources' % Key)
        Tmp = UserExtensionSourceXml()
        SourceDict = Tmp.FromXml(SourcesItem, 'Sources')
        self.SourcesDict = SourceDict
        BinariesItem = XmlNode(Item, '%s/Binaries' % Key)
        Tmp = UserExtensionBinaryXml()
        BinariesDict = Tmp.FromXml(BinariesItem, 'Binaries')
        self.BinariesDict = BinariesDict
        self.Statement = XmlElement(Item, 'UserExtensions')
        SupArch = XmlAttribute(XmlNode(Item, '%s' % Key), 'SupArchList')
        self.SupArchList = [Arch for Arch in GetSplitValueList(SupArch, DataType.TAB_SPACE_SPLIT) if Arch]
        UserExtension = UserExtensionObject()
        UserExtension.SetUserID(self.UserId)
        UserExtension.SetIdentifier(self.Identifier)
        UserExtension.SetBinaryAbstract(self.BinaryAbstractList)
        UserExtension.SetBinaryDescription(self.BinaryDescriptionList)
        UserExtension.SetBinaryCopyright(self.BinaryCopyrightList)
        UserExtension.SetBinaryLicense(self.BinaryLicenseList)
        UserExtension.SetStatement(self.Statement)
        UserExtension.SetSupArchList(self.SupArchList)
        UserExtension.SetDefinesDict(self.DefineDict)
        UserExtension.SetBuildOptionDict(self.BuildOptionDict)
        UserExtension.SetIncludesDict(self.IncludesDict)
        UserExtension.SetSourcesDict(self.SourcesDict)
        UserExtension.SetBinariesDict(self.BinariesDict)
        return UserExtension

    def ToXml(self, UserExtension, Key):
        if self.UserId:
            pass
        AttributeList = [['UserId', str(UserExtension.GetUserID())],
                         ['Identifier', str(UserExtension.GetIdentifier())],
                         ['SupArchList', \
                          GetStringOfList(UserExtension.GetSupArchList())],
                        ]
        Root = CreateXmlElement('%s' % Key, UserExtension.GetStatement(), [], \
                                    AttributeList)
        if UserExtension.GetIdentifier() == DataType.TAB_BINARY_HEADER_IDENTIFIER and \
        UserExtension.GetUserID() == DataType.TAB_BINARY_HEADER_USERID:
            for (Lang, Value) in UserExtension.GetBinaryAbstract():
                if Value:
                    ChildElement = CreateXmlElement('BinaryAbstract', Value, [], [['Lang', Lang]])
                    Root.appendChild(ChildElement)
            for (Lang, Value) in UserExtension.GetBinaryDescription():
                if Value:
                    ChildElement = CreateXmlElement('BinaryDescription', Value, [], [['Lang', Lang]])
                    Root.appendChild(ChildElement)
            for (Lang, Value) in UserExtension.GetBinaryCopyright():
                if Value:
                    ChildElement = CreateXmlElement('BinaryCopyright', Value, [], [])
                    Root.appendChild(ChildElement)
            for (Lang, Value) in UserExtension.GetBinaryLicense():
                if Value:
                    ChildElement = CreateXmlElement('BinaryLicense', Value, [], [])
                    Root.appendChild(ChildElement)

        NodeList = []
        DefineDict = UserExtension.GetDefinesDict()
        if DefineDict:
            for Item in DefineDict.keys():
                NodeList.append(CreateXmlElement\
                                ('Statement', Item, [], []))
            DefineElement = CreateXmlElement('Define', '', NodeList, [])
            Root.appendChild(DefineElement)
        NodeList = []
        BuildOptionDict = UserExtension.GetBuildOptionDict()
        if BuildOptionDict:
            for Item in BuildOptionDict.keys():
                NodeList.append(CreateXmlElement\
                                ('Statement', BuildOptionDict[Item], [], \
                                 [['SupArchList', Item]]))
            BuildOptionElement = \
            CreateXmlElement('BuildOption', '', NodeList, [])
            Root.appendChild(BuildOptionElement)
        NodeList = []
        IncludesDict = UserExtension.GetIncludesDict()
        if IncludesDict:
            for Item in IncludesDict.keys():
                NodeList.append(CreateXmlElement\
                                ('Statement', Item, [], \
                                 [['SupArchList', IncludesDict[Item]]]))
            IncludesElement = CreateXmlElement('Includes', '', NodeList, [])
            Root.appendChild(IncludesElement)
        NodeList = []
        SourcesDict = UserExtension.GetSourcesDict()
        if SourcesDict:
            Tmp = UserExtensionSourceXml()
            Root.appendChild(Tmp.ToXml(SourcesDict, 'Sources'))
        NodeList = []
        BinariesDict = UserExtension.GetBinariesDict()
        if BinariesDict:
            Tmp = UserExtensionBinaryXml()
            Root.appendChild(Tmp.ToXml(BinariesDict, 'Binaries'))
        return Root

    def __str__(self):
        Str = "UserId = %s Identifier = %s" % (self.UserId, self.Identifier)
        Str = Str + '\n\tDefines:' + str(self.Defines)
        Str = Str + '\n\tBuildOptions:' + str(self.BuildOptions)
        return Str

##
# UserExtensionSourceXml
#
class UserExtensionSourceXml(object):
    def __init__(self):
        self.UserExtensionSource = ''

    def FromXml(self, Item, Key):
        if Key:
            pass
        if self.UserExtensionSource:
            pass
        Dict = {}
        #SourcesItem = XmlNode(Item, '%s/Sources' % Key)
        for SubItem in XmlList(Item, 'Sources/SourceFile'):
            FileName = XmlElement(SubItem, 'SourceFile/FileName')
            Family = XmlElement(SubItem, 'SourceFile/Family')
            FeatureFlag = XmlElement(SubItem, 'SourceFile/FeatureFlag')
            SupArchStr = XmlElement(SubItem, 'SourceFile/SupArchList')
            DictKey = (FileName, Family, FeatureFlag, SupArchStr)
            ValueList = []
            for ValueNodeItem in XmlList(SubItem, \
                                         'SourceFile/SourceFileOtherAttr'):
                TagName = XmlElement(ValueNodeItem, \
                                     'SourceFileOtherAttr/TagName')
                ToolCode = XmlElement(ValueNodeItem, \
                                      'SourceFileOtherAttr/ToolCode')
                Comment = XmlElement(ValueNodeItem, \
                                     'SourceFileOtherAttr/Comment')
                if (TagName == ' ') and (ToolCode == ' ') and (Comment == ' '):
                    TagName = ''
                    ToolCode = ''
                    Comment = ''
                ValueList.append((TagName, ToolCode, Comment))
            Dict[DictKey] = ValueList
        return Dict

    def ToXml(self, Dict, Key):
        if self.UserExtensionSource:
            pass
        SourcesNodeList = []
        for Item in Dict:
            ValueList = Dict[Item]
            (FileName, Family, FeatureFlag, SupArchStr) = Item
            SourceFileNodeList = []
            SourceFileNodeList.append(["FileName", FileName])
            SourceFileNodeList.append(["Family", Family])
            SourceFileNodeList.append(["FeatureFlag", FeatureFlag])
            SourceFileNodeList.append(["SupArchList", SupArchStr])
            for (TagName, ToolCode, Comment) in ValueList:
                ValueNodeList = []
                if not (TagName or ToolCode or Comment):
                    TagName = ' '
                    ToolCode = ' '
                    Comment = ' '
                ValueNodeList.append(["TagName", TagName])
                ValueNodeList.append(["ToolCode", ToolCode])
                ValueNodeList.append(["Comment", Comment])
                ValueNodeXml = CreateXmlElement('SourceFileOtherAttr', '', \
                                                ValueNodeList, [])
                SourceFileNodeList.append(ValueNodeXml)
            SourceFileNodeXml = CreateXmlElement('SourceFile', '', \
                                                 SourceFileNodeList, [])
            SourcesNodeList.append(SourceFileNodeXml)
        Root = CreateXmlElement('%s' % Key, '', SourcesNodeList, [])
        return Root

##
# UserExtensionBinaryXml
#
class UserExtensionBinaryXml(object):
    def __init__(self):
        self.UserExtensionBinary = ''

    def FromXml(self, Item, Key):
        if Key:
            pass
        if self.UserExtensionBinary:
            pass
        Dict = {}
        for SubItem in XmlList(Item, 'Binaries/Binary'):
            FileName = XmlElement(SubItem, 'Binary/FileName')
            FileType = XmlElement(SubItem, 'Binary/FileType')
            FFE = XmlElement(SubItem, 'Binary/FeatureFlag')
            SupArch = XmlElement(SubItem, 'Binary/SupArchList')
            DictKey = (FileName, FileType, ConvertNOTEQToNE(FFE), SupArch)
            ValueList = []
            for ValueNodeItem in XmlList(SubItem, \
                                         'Binary/BinaryFileOtherAttr'):
                Target = XmlElement(ValueNodeItem, \
                                    'BinaryFileOtherAttr/Target')
                Family = XmlElement(ValueNodeItem, \
                                    'BinaryFileOtherAttr/Family')
                TagName = XmlElement(ValueNodeItem, \
                                     'BinaryFileOtherAttr/TagName')
                Comment = XmlElement(ValueNodeItem, \
                                     'BinaryFileOtherAttr/Comment')
                if (Target == ' ') and (Family == ' ') and \
                   (TagName == ' ') and (Comment == ' '):
                    Target = ''
                    Family = ''
                    TagName = ''
                    Comment = ''

                ValueList.append((Target, Family, TagName, Comment))
            Dict[DictKey] = ValueList
        return Dict

    def ToXml(self, Dict, Key):
        if self.UserExtensionBinary:
            pass
        BinariesNodeList = []
        for Item in Dict:
            ValueList = Dict[Item]
            (FileName, FileType, FeatureFlag, SupArch) = Item
            FileNodeList = []
            FileNodeList.append(["FileName", FileName])
            FileNodeList.append(["FileType", FileType])
            FileNodeList.append(["FeatureFlag", ConvertNEToNOTEQ(FeatureFlag)])
            FileNodeList.append(["SupArchList", SupArch])
            for (Target, Family, TagName, Comment) in ValueList:
                ValueNodeList = []
                if not (Target or Family or TagName or Comment):
                    Target = ' '
                    Family = ' '
                    TagName = ' '
                    Comment = ' '
                ValueNodeList.append(["Target", Target])
                ValueNodeList.append(["Family", Family])
                ValueNodeList.append(["TagName", TagName])
                ValueNodeList.append(["Comment", Comment])
                ValueNodeXml = CreateXmlElement('BinaryFileOtherAttr', '', \
                                                ValueNodeList, [])
                FileNodeList.append(ValueNodeXml)
            FileNodeXml = CreateXmlElement('Binary', '', FileNodeList, [])
            BinariesNodeList.append(FileNodeXml)
        Root = CreateXmlElement('%s' % Key, '', BinariesNodeList, [])
        return Root

##
# LibraryClassXml
#
class LibraryClassXml(object):
    def __init__(self):
        self.Keyword = ''
        self.HeaderFile = ''
        self.RecommendedInstanceGuid = ''
        self.RecommendedInstanceVersion = ''
        self.CommonDefines = CommonDefinesXml()
        self.HelpText = []

    def FromXml(self, Item, Key):
        self.Keyword = XmlAttribute(XmlNode(Item, '%s' % Key), 'Keyword')
        if self.Keyword == '':
            self.Keyword = XmlElement(Item, '%s/Keyword' % Key)
        self.HeaderFile = XmlElement(Item, '%s/HeaderFile' % Key)
        self.CommonDefines.FromXml(XmlNode(Item, '%s' % Key), Key)
        for HelpTextItem in XmlList(Item, '%s/HelpText' % Key):
            HelpTextObj = HelpTextXml()
            HelpTextObj.FromXml(HelpTextItem, '%s/HelpText' % Key)
            self.HelpText.append(HelpTextObj)
        LibraryClass = LibraryClassObject()
        LibraryClass.SetLibraryClass(self.Keyword)
        LibraryClass.SetIncludeHeader(self.HeaderFile)
        if self.CommonDefines.Usage:
            LibraryClass.SetUsage(self.CommonDefines.Usage)
        LibraryClass.SetSupArchList(self.CommonDefines.SupArchList)
        LibraryClass.SetSupModuleList(self.CommonDefines.SupModList)
        LibraryClass.SetFeatureFlag(ConvertNOTEQToNE(self.CommonDefines.FeatureFlag))
        LibraryClass.SetHelpTextList(GetHelpTextList(self.HelpText))
        return LibraryClass

    def ToXml(self, LibraryClass, Key):
        if self.HeaderFile:
            pass
        AttributeList = \
        [['Keyword', LibraryClass.GetLibraryClass()],
         ['SupArchList', GetStringOfList(LibraryClass.GetSupArchList())],
         ['SupModList', GetStringOfList(LibraryClass.GetSupModuleList())]
         ]
        NodeList = [['HeaderFile', LibraryClass.GetIncludeHeader()]]
        for Item in LibraryClass.GetHelpTextList():
            Tmp = HelpTextXml()
            NodeList.append(Tmp.ToXml(Item))
        Root = CreateXmlElement('%s' % Key, '', NodeList, AttributeList)
        return Root

    def ToXml2(self, LibraryClass, Key):
        if self.HeaderFile:
            pass
        FeatureFlag = ConvertNEToNOTEQ(LibraryClass.GetFeatureFlag())
        AttributeList = \
        [['Usage', LibraryClass.GetUsage()], \
         ['SupArchList', GetStringOfList(LibraryClass.GetSupArchList())], \
         ['SupModList', GetStringOfList(LibraryClass.GetSupModuleList())], \
         ['FeatureFlag', FeatureFlag]
         ]
        NodeList = [['Keyword', LibraryClass.GetLibraryClass()], ]
        for Item in LibraryClass.GetHelpTextList():
            Tmp = HelpTextXml()
            NodeList.append(Tmp.ToXml(Item))
        Root = CreateXmlElement('%s' % Key, '', NodeList, AttributeList)
        return Root

    def __str__(self):
        Str = "Keyword = %s HeaderFile = %s RecommendedInstanceGuid = %s RecommendedInstanceVersion = %s %s" % \
              (self.Keyword, self.HeaderFile, self.RecommendedInstanceGuid, self.RecommendedInstanceVersion, \
              self.CommonDefines)
        for Item in self.HelpText:
            Str = Str + "\n\t" + str(Item)
        return Str

##
# FilenameXml
#
class FilenameXml(object):
    def __init__(self):
        self.FileType = ''
        self.Filename = ''
        self.CommonDefines = CommonDefinesXml()

    def FromXml(self, Item, Key):
        self.FileType = XmlAttribute(Item, 'FileType')
        Guid = XmlAttribute(Item, 'GUID')
        self.Filename = XmlElement(Item, 'Filename')
        self.CommonDefines.FromXml(Item, Key)
        FeatureFlag = ConvertNOTEQToNE(self.CommonDefines.FeatureFlag)
        Filename = FileNameObject()
        #
        # Convert File Type
        #
        if self.FileType == 'UEFI_IMAGE':
            self.FileType = 'PE32'

        Filename.SetGuidValue(Guid)
        Filename.SetFileType(self.FileType)
        Filename.SetFilename(self.Filename)
        Filename.SetSupArchList(self.CommonDefines.SupArchList)
        Filename.SetFeatureFlag(FeatureFlag)

        return Filename

    def ToXml(self, Filename, Key):
        if self.Filename:
            pass
        AttributeList = [['SupArchList', \
                          GetStringOfList(Filename.GetSupArchList())],
                         ['FileType', Filename.GetFileType()],
                         ['FeatureFlag', ConvertNEToNOTEQ(Filename.GetFeatureFlag())],
                         ['GUID', Filename.GetGuidValue()]
                        ]
        Root = CreateXmlElement('%s' % Key, Filename.GetFilename(), [], AttributeList)

        return Root

    def __str__(self):
        return "FileType = %s Filename = %s %s" \
             % (self.FileType, self.Filename, self.CommonDefines)
