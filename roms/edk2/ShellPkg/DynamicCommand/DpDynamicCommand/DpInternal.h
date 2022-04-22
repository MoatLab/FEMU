/** @file
  Declarations of objects defined internally to the Dp Application.

  Declarations of data and functions which are private to the Dp application.
  This file should never be referenced by anything other than components of the
  Dp application.  In addition to global data, function declarations for
  DpUtilities.c, DpTrace.c, and DpProfile.c are included here.

  Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.
  (C) Copyright 2015-2016 Hewlett Packard Enterprise Development LP<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef _DP_INTELNAL_H_
#define _DP_INTELNAL_H_

#define DP_GAUGE_STRING_LENGTH  36

//
/// Module-Global Variables
///@{
extern EFI_HII_HANDLE      mDpHiiHandle;
extern CHAR16              mGaugeString[DP_GAUGE_STRING_LENGTH + 1];
extern CHAR16              mUnicodeToken[DXE_PERFORMANCE_STRING_SIZE];
extern UINT64              mInterestThreshold;
extern BOOLEAN             mShowId;
extern UINT8               *mBootPerformanceTable;
extern UINTN               mBootPerformanceTableLength;
extern MEASUREMENT_RECORD  *mMeasurementList;
extern UINTN               mMeasurementNum;

extern PERF_SUMMARY_DATA  SummaryData;    ///< Create the SummaryData structure and init. to ZERO.

/// Items for which to gather cumulative statistics.
extern PERF_CUM_DATA  CumData[];

/// Number of items for which we are gathering cumulative statistics.
extern UINT32 const  NumCum;

///@}

/**
  Calculate an event's duration in timer ticks.

  Given the count direction and the event's start and end timer values,
  calculate the duration of the event in timer ticks.  Information for
  the current measurement is pointed to by the parameter.

  If the measurement's start time is 1, it indicates that the developer
  is indicating that the measurement began at the release of reset.
  The start time is adjusted to the timer's starting count before performing
  the elapsed time calculation.

  The calculated duration, in ticks, is the absolute difference between
  the measurement's ending and starting counts.

  @param Measurement   Pointer to a MEASUREMENT_RECORD structure containing
                       data for the current measurement.

  @return              The 64-bit duration of the event.
**/
UINT64
GetDuration (
  IN OUT MEASUREMENT_RECORD  *Measurement
  );

/**
  Determine whether the Measurement record is for an EFI Phase.

  The Token and Module members of the measurement record are checked.
  Module must be empty and Token must be one of SEC, PEI, DXE, BDS, or SHELL.

  @param[in]  Measurement A pointer to the Measurement record to test.

  @retval     TRUE        The measurement record is for an EFI Phase.
  @retval     FALSE       The measurement record is NOT for an EFI Phase.
**/
BOOLEAN
IsPhase (
  IN MEASUREMENT_RECORD  *Measurement
  );

/**
  Determine whether the Measurement record is for core code.

  @param[in] Measurement  A pointer to the Measurement record to test.

  @retval     TRUE        The measurement record is used for core.
  @retval     FALSE       The measurement record is NOT used for core.

**/
BOOLEAN
IsCorePerf (
  IN MEASUREMENT_RECORD  *Measurement
  );

/**
  Get the file name portion of the Pdb File Name.

  The portion of the Pdb File Name between the last backslash and
  either a following period or the end of the string is converted
  to Unicode and copied into UnicodeBuffer.  The name is truncated,
  if necessary, to ensure that UnicodeBuffer is not overrun.

  @param[in]  PdbFileName     Pdb file name.
  @param[out] UnicodeBuffer   The resultant Unicode File Name.

**/
VOID
DpGetShortPdbFileName (
  IN  CHAR8   *PdbFileName,
  OUT CHAR16  *UnicodeBuffer
  );

/**
  Get a human readable name for an image handle.
  The following methods will be tried orderly:
    1. Image PDB
    2. ComponentName2 protocol
    3. FFS UI section
    4. Image GUID
    5. Image DevicePath
    6. Unknown Driver Name

  @param[in]    Handle

  @post   The resulting Unicode name string is stored in the
          mGaugeString global array.

**/
VOID
DpGetNameFromHandle (
  IN EFI_HANDLE  Handle
  );

/**
  Calculate the Duration in microseconds.

  Duration is multiplied by 1000, instead of Frequency being divided by 1000 or
  multiplying the result by 1000, in order to maintain precision.  Since Duration is
  a 64-bit value, multiplying it by 1000 is unlikely to produce an overflow.

  The time is calculated as (Duration * 1000) / Timer_Frequency.

  @param[in]  Duration   The event duration in timer ticks.

  @return     A 64-bit value which is the Elapsed time in microseconds.
**/
UINT64
DurationInMicroSeconds (
  IN UINT64  Duration
  );

/**
  Get index of Measurement Record's match in the CumData array.

  If the Measurement's Token value matches a Token in one of the CumData
  records, the index of the matching record is returned.  The returned
  index is a signed value so that negative values can indicate that
  the Measurement didn't match any entry in the CumData array.

  @param[in]  Measurement A pointer to a Measurement Record to match against the CumData array.

  @retval     <0    Token is not in the CumData array.
  @retval     >=0   Return value is the index into CumData where Token is found.
**/
INTN
GetCumulativeItem (
  IN MEASUREMENT_RECORD  *Measurement
  );

/**
  Collect verbose statistics about the logged performance measurements.

  General Summary information for all Trace measurements is gathered and
  stored within the SummaryData structure.  This information is both
  used internally by subsequent reporting functions, and displayed
  at the end of verbose reports.

  @pre  The SummaryData and CumData structures must be initialized
        prior to calling this function.

  @post The SummaryData and CumData structures contain statistics for the
        current performance logs.

  @param[in, out] CustomCumulativeData  The pointer to the custom cumulative data.

**/
VOID
GatherStatistics (
  IN OUT PERF_CUM_DATA  *CustomCumulativeData OPTIONAL
  );

/**
  Gather and print ALL Trace Records.

  Displays all "interesting" Trace measurements in order.<BR>
  The number of records displayed is controlled by:
     - records with a duration less than mInterestThreshold microseconds are not displayed.
     - No more than Limit records are displayed.  A Limit of zero will not limit the output.
     - If the ExcludeFlag is TRUE, records matching entries in the CumData array are not
       displayed.

  @pre    The mInterestThreshold global variable is set to the shortest duration to be printed.
           The mGaugeString and mUnicodeToken global arrays are used for temporary string storage.
           They must not be in use by a calling function.

  @param[in]    Limit       The number of records to print.  Zero is ALL.
  @param[in]    ExcludeFlag TRUE to exclude individual Cumulative items from display.

  @retval EFI_SUCCESS           The operation was successful.
  @retval EFI_ABORTED           The user aborts the operation.
  @return Others                from a call to gBS->LocateHandleBuffer().
**/
EFI_STATUS
DumpAllTrace (
  IN UINTN    Limit,
  IN BOOLEAN  ExcludeFlag
  );

/**
  Gather and print Raw Trace Records.

  All Trace measurements with a duration greater than or equal to
  mInterestThreshold are printed without interpretation.

  The number of records displayed is controlled by:
     - records with a duration less than mInterestThreshold microseconds are not displayed.
     - No more than Limit records are displayed.  A Limit of zero will not limit the output.
     - If the ExcludeFlag is TRUE, records matching entries in the CumData array are not
       displayed.

  @pre    The mInterestThreshold global variable is set to the shortest duration to be printed.

  @param[in]    Limit       The number of records to print.  Zero is ALL.
  @param[in]    ExcludeFlag TRUE to exclude individual Cumulative items from display.
  @retval EFI_SUCCESS           The operation was successful.
  @retval EFI_ABORTED           The user aborts the operation.
**/
EFI_STATUS
DumpRawTrace (
  IN UINTN    Limit,
  IN BOOLEAN  ExcludeFlag
  );

/**
  Gather and print Major Phase metrics.

**/
VOID
ProcessPhases (
  VOID
  );

/**
  Gather and print Handle data.

  @param[in]    ExcludeFlag   TRUE to exclude individual Cumulative items from display.

  @retval EFI_SUCCESS             The operation was successful.
  @retval EFI_ABORTED             The user aborts the operation.
  @return Others                  from a call to gBS->LocateHandleBuffer().
**/
EFI_STATUS
ProcessHandles (
  IN BOOLEAN  ExcludeFlag
  );

/**
  Gather and print PEIM data.

  Only prints complete PEIM records

  @retval EFI_SUCCESS           The operation was successful.
  @retval EFI_ABORTED           The user aborts the operation.
**/
EFI_STATUS
ProcessPeims (
  VOID
  );

/**
  Gather and print global data.

  Strips out incomplete or "Execution Phase" records
  Only prints records where Handle is NULL
  Increment TIndex for every record, even skipped ones, so that we have an
  indication of every measurement record taken.

  @retval EFI_SUCCESS           The operation was successful.
  @retval EFI_ABORTED           The user aborts the operation.
**/
EFI_STATUS
ProcessGlobal (
  VOID
  );

/**
  Gather and print cumulative data.

  Traverse the measurement records and:<BR>
  For each record with a Token listed in the CumData array:<BR>
     - Update the instance count and the total, minimum, and maximum durations.
  Finally, print the gathered cumulative statistics.

  @param[in]    CustomCumulativeData  The pointer to the custom cumulative data.

**/
VOID
ProcessCumulative (
  IN PERF_CUM_DATA  *CustomCumulativeData OPTIONAL
  );

#endif
