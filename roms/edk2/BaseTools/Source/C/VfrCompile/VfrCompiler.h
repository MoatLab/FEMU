/** @file

  VfrCompiler internal definitions.

Copyright (c) 2004 - 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _VFRCOMPILER_H_
#define _VFRCOMPILER_H_

#include "Common/UefiBaseTypes.h"
#include "EfiVfr.h"
#include "VfrFormPkg.h"
#include "VfrUtilityLib.h"
#include "ParseInf.h"

#define PROGRAM_NAME                       "VfrCompile"
#define VFR_COMPILER_VERSION               " 2.01 (UEFI 2.4) "
//
// This is how we invoke the C preprocessor on the VFR source file
// to resolve #defines, #includes, etc. To make C source files
// shareable between VFR and drivers, define VFRCOMPILE so that
// #ifdefs can be used in shared .h files.
//
#define PREPROCESSOR_COMMAND                "cl "
#define PREPROCESSOR_OPTIONS                "/nologo /E /TC /DVFRCOMPILE "

//
// Specify the filename extensions for the files we generate.
//
#define VFR_PREPROCESS_FILENAME_EXTENSION   ".i"
#define VFR_PACKAGE_FILENAME_EXTENSION      ".hpk"
#define VFR_RECORDLIST_FILENAME_EXTENSION   ".lst"

typedef struct {
  CHAR8   *VfrFileName;
  CHAR8   *RecordListFile;
  CHAR8   *PkgOutputFileName;
  CHAR8   *COutputFileName;
  bool    CreateRecordListFile;
  bool    CreateIfrPkgFile;
  CHAR8   *OutputDirectory;
  CHAR8   *PreprocessorOutputFileName;
  CHAR8   *VfrBaseFileName;  // name of input VFR file with no path or extension
  CHAR8   *IncludePaths;
  bool    SkipCPreprocessor;
  CHAR8   *CPreprocessorOptions;
  BOOLEAN HasOverrideClassGuid;
  EFI_GUID OverrideClassGuid;
  BOOLEAN WarningAsError;
  BOOLEAN AutoDefault;
  BOOLEAN CheckDefault;
} OPTIONS;

typedef enum {
  STATUS_STARTED = 0,
  STATUS_INITIALIZED,
  STATUS_PREPROCESSED,
  STATUS_COMPILEED,
  STATUS_GENBINARY,
  STATUS_FINISHED,
  STATUS_FAILED,
  STATUS_DEAD,
} COMPILER_RUN_STATUS;

class CVfrCompiler {
private:
  COMPILER_RUN_STATUS  mRunStatus;
  OPTIONS              mOptions;
  CHAR8                *mPreProcessCmd;
  CHAR8                *mPreProcessOpt;

  VOID    OptionInitialization (IN INT32 , IN CHAR8 **);
  VOID    AppendIncludePath (IN CHAR8 *);
  VOID    AppendCPreprocessorOptions (IN CHAR8 *);
  INT8    SetBaseFileName (VOID);
  INT8    SetPkgOutputFileName (VOID);
  INT8    SetCOutputFileName(VOID);
  INT8    SetPreprocessorOutputFileName (VOID);
  INT8    SetRecordListFileName (VOID);

  VOID    SET_RUN_STATUS (IN COMPILER_RUN_STATUS);
  BOOLEAN IS_RUN_STATUS (IN COMPILER_RUN_STATUS);

public:
  COMPILER_RUN_STATUS RunStatus (VOID) {
    return mRunStatus;
  }

public:
  CVfrCompiler (IN INT32 , IN CHAR8 **);
  ~CVfrCompiler ();

  VOID                Usage (VOID);
  VOID                Version (VOID);

  VOID                PreProcess (VOID);
  VOID                Compile (VOID);
  VOID                AdjustBin (VOID);
  VOID                GenBinary (VOID);
  VOID                GenCFile (VOID);
  VOID                GenRecordListFile (VOID);
  VOID                DebugError (IN CHAR8*, IN UINT32, IN UINT32, IN CONST CHAR8*, IN CONST CHAR8*, ...);
};

#endif
