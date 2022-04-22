@REM @file
@REM   This stand-alone program is typically called by the toolsetup.bat file,
@REM   however it may be executed directly from the BaseTools project folder
@REM   if the file is not executed within a WORKSPACE\BaseTools folder.
@REM
@REM Copyright (c) 2016-2020, Intel Corporation. All rights reserved.<BR>
@REM
@REM SPDX-License-Identifier: BSD-2-Clause-Patent
@REM

@echo off
pushd .
set SCRIPT_ERROR=0
goto main

:ToolNotInstall
set SCRIPT_ERROR=1
goto :EOF

:main
if /I "%1"=="VS2019" goto SetVS2019
if /I "%1"=="VS2017" goto SetVS2017
if /I "%1"=="VS2015" goto SetVS2015
if /I "%1"=="VS2013" goto SetVS2013
if /I "%1"=="VS2012" goto SetVS2012

if defined VS71COMNTOOLS (
  if not defined VS2003_PREFIX (
    set "VS2003_PREFIX=%VS71COMNTOOLS:~0,-14%"
  )
)

if defined VS80COMNTOOLS (
  if not defined VS2005_PREFIX (
    set "VS2005_PREFIX=%VS80COMNTOOLS:~0,-14%"
  )
)

if defined VS90COMNTOOLS (
  if not defined VS2008_PREFIX (
    set "VS2008_PREFIX=%VS90COMNTOOLS:~0,-14%"
  )
  if not defined WINSDK_PREFIX (
    set "WINSDK_PREFIX=c:\Program Files\Microsoft SDKs\Windows\v6.0A\bin\"
  )
  if not defined WINSDKx86_PREFIX (
    set "WINSDKx86_PREFIX=c:\Program Files (x86)\Microsoft SDKs\Windows\v6.0A\bin\"
  )
)

if defined VS100COMNTOOLS (
  if not defined VS2010_PREFIX (
    set "VS2010_PREFIX=%VS100COMNTOOLS:~0,-14%"
  )
  if not defined WINSDK7_PREFIX (
    set "WINSDK7_PREFIX=c:\Program Files\Microsoft SDKs\Windows\v7.0A\Bin\"
  )
  if not defined WINSDK7x86_PREFIX (
    set "WINSDK7x86_PREFIX=c:\Program Files (x86)\Microsoft SDKs\Windows\v7.0A\Bin\"
  )
)

:SetVS2012
if defined VS110COMNTOOLS (
  if not defined VS2012_PREFIX (
    set "VS2012_PREFIX=%VS110COMNTOOLS:~0,-14%"
  )
  if not defined WINSDK71_PREFIX (
    set "WINSDK71_PREFIX=c:\Program Files\Microsoft SDKs\Windows\v7.1A\Bin\"
  )
  if not defined WINSDK71x86_PREFIX (
    set "WINSDK71x86_PREFIX=c:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Bin\"
  )
) else (
  if /I "%1"=="VS2012" goto ToolNotInstall
)
if /I "%1"=="VS2012" goto SetWinDDK

:SetVS2013
if defined VS120COMNTOOLS (
  if not defined VS2013_PREFIX (
    set "VS2013_PREFIX=%VS120COMNTOOLS:~0,-14%"
  )
  if not defined WINSDK8_PREFIX (
    set "WINSDK8_PREFIX=c:\Program Files\Windows Kits\8.0\bin\"
  )
  if not defined WINSDK8x86_PREFIX (
    set "WINSDK8x86_PREFIX=c:\Program Files (x86)\Windows Kits\8.0\bin\"
  )
) else (
  if /I "%1"=="VS2013" goto ToolNotInstall
)
if /I "%1"=="VS2013" goto SetWinDDK

:SetVS2015
if defined VS140COMNTOOLS (
  if not defined VS2015_PREFIX (
    set "VS2015_PREFIX=%VS140COMNTOOLS:~0,-14%"
  )
  if not defined WINSDK81_PREFIX (
    set "WINSDK81_PREFIX=c:\Program Files\Windows Kits\8.1\bin\"
  )
  if not defined WINSDK81x86_PREFIX (
    set "WINSDK81x86_PREFIX=c:\Program Files (x86)\Windows Kits\8.1\bin\"
  )
) else (
  if /I "%1"=="VS2015" goto ToolNotInstall
)
if /I "%1"=="VS2015" goto SetWinDDK

:SetVS2017
if not defined VS150COMNTOOLS (
  @REM clear two envs so that vcvars32.bat can run successfully.
  set VSINSTALLDIR=
  set VCToolsVersion=
  if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" (
    if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2017\BuildTools" (
      call "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -products Microsoft.VisualStudio.Product.BuildTools -version 15,16 > vswhereInfo
      for /f "usebackq tokens=1* delims=: " %%i in (vswhereInfo) do (
        if /i "%%i"=="installationPath" call "%%j\VC\Auxiliary\Build\vcvars32.bat"
      )
      del vswhereInfo
    ) else (
      call "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -version 15,16 > vswhereInfo
      for /f "usebackq tokens=1* delims=: " %%i in (vswhereInfo) do (
        if /i "%%i"=="installationPath" call "%%j\VC\Auxiliary\Build\vcvars32.bat"
      )
      del vswhereInfo
    )
  ) else if exist "%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe" (
    if exist "%ProgramFiles%\Microsoft Visual Studio\2017\BuildTools" (
      call "%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe" -products Microsoft.VisualStudio.Product.BuildTools -version 15,16 > vswhereInfo
      for /f "usebackq tokens=1* delims=: " %%i in (vswhereInfo) do (
        if /i "%%i"=="installationPath" call "%%j\VC\Auxiliary\Build\vcvars32.bat"
      )
      del vswhereInfo
    ) else (
      call "%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe" -version 15,16 > vswhereInfo
      for /f "usebackq tokens=1* delims=: " %%i in (vswhereInfo) do (
        if /i "%%i"=="installationPath" call "%%j\VC\Auxiliary\Build\vcvars32.bat"
      )
      del vswhereInfo
    )
  ) else (
    if /I "%1"=="VS2017" goto ToolNotInstall
    goto SetWinDDK
  )
)

if defined VCToolsInstallDir (
  if not defined VS2017_PREFIX (
    set "VS2017_PREFIX=%VCToolsInstallDir%"
  )
  if not defined WINSDK10_PREFIX (
    if defined WindowsSdkVerBinPath (
      set "WINSDK10_PREFIX=%WindowsSdkVerBinPath%"
    ) else if exist "%ProgramFiles(x86)%\Windows Kits\10\bin" (
      set "WINSDK10_PREFIX=%ProgramFiles(x86)%\Windows Kits\10\bin\"
    ) else if exist "%ProgramFiles%\Windows Kits\10\bin" (
      set "WINSDK10_PREFIX=%ProgramFiles%\Windows Kits\10\bin\"
    )
  )
)
if not defined WINSDK_PATH_FOR_RC_EXE (
  if defined WINSDK10_PREFIX (
    set "WINSDK_PATH_FOR_RC_EXE=%WINSDK10_PREFIX%x86"
  )
)

if /I "%1"=="VS2017" goto SetWinDDK

:SetVS2019
if not defined VS160COMNTOOLS (
  @REM clear two envs so that vcvars32.bat can run successfully.
  set VSINSTALLDIR=
  set VCToolsVersion=
  if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" (
    if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\BuildTools" (
      call "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -products Microsoft.VisualStudio.Product.BuildTools -version 16,17 > vswhereInfo
      for /f "usebackq tokens=1* delims=: " %%i in (vswhereInfo) do (
        if /i "%%i"=="installationPath" call "%%j\VC\Auxiliary\Build\vcvars32.bat"
      )
      del vswhereInfo
    ) else (
      call "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -version 16,17 > vswhereInfo
      for /f "usebackq tokens=1* delims=: " %%i in (vswhereInfo) do (
        if /i "%%i"=="installationPath" call "%%j\VC\Auxiliary\Build\vcvars32.bat"
      )
      del vswhereInfo
    )
  ) else if exist "%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe" (
    if exist "%ProgramFiles%\Microsoft Visual Studio\2019\BuildTools" (
      call "%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe" -products Microsoft.VisualStudio.Product.BuildTools -version 16,17 > vswhereInfo
      for /f "usebackq tokens=1* delims=: " %%i in (vswhereInfo) do (
        if /i "%%i"=="installationPath" call "%%j\VC\Auxiliary\Build\vcvars32.bat"
      )
      del vswhereInfo
    ) else (
      call "%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe" -version 16,17 > vswhereInfo
      for /f "usebackq tokens=1* delims=: " %%i in (vswhereInfo) do (
        if /i "%%i"=="installationPath" call "%%j\VC\Auxiliary\Build\vcvars32.bat"
      )
      del vswhereInfo
    )
  ) else (
    if /I "%1"=="VS2019" goto ToolNotInstall
    goto SetWinDDK
  )
)

if defined VCToolsInstallDir (
  if not defined VS2019_PREFIX (
    set "VS2019_PREFIX=%VCToolsInstallDir%"
  )
  if not defined WINSDK10_PREFIX (
    if defined WindowsSdkVerBinPath (
      set "WINSDK10_PREFIX=%WindowsSdkVerBinPath%"
    ) else if exist "%ProgramFiles(x86)%\Windows Kits\10\bin" (
      set "WINSDK10_PREFIX=%ProgramFiles(x86)%\Windows Kits\10\bin\"
    ) else if exist "%ProgramFiles%\Windows Kits\10\bin" (
      set "WINSDK10_PREFIX=%ProgramFiles%\Windows Kits\10\bin\"
    )
  )
)
if not defined WINSDK_PATH_FOR_RC_EXE (
  if defined WINSDK10_PREFIX (
    set "WINSDK_PATH_FOR_RC_EXE=%WINSDK10_PREFIX%x86"
  )
)

if /I "%1"=="VS2019" goto SetWinDDK

:SetWinDDK
if not defined WINDDK3790_PREFIX (
  set WINDDK3790_PREFIX=C:\WINDDK\3790.1830\bin\
)

if not defined IASL_PREFIX (
  set IASL_PREFIX=C:\ASL\
)

popd
