/** @file
  RTC Architectural Protocol GUID as defined in DxeCis 0.96.

Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2017, AMD Inc. All rights reserved.<BR>
Copyright (c) 2018 - 2020, ARM Limited. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "PcRtc.h"

extern UINTN  mRtcIndexRegister;
extern UINTN  mRtcTargetRegister;

//
// Days of month.
//
UINTN  mDayOfMonth[] = { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

//
// The name of NV variable to store the timezone and daylight saving information.
//
CHAR16  mTimeZoneVariableName[] = L"RTC";

/**
  Compare the Hour, Minute and Second of the From time and the To time.

  Only compare H/M/S in EFI_TIME and ignore other fields here.

  @param From   the first time
  @param To     the second time

  @return  >0   The H/M/S of the From time is later than those of To time
  @return  ==0  The H/M/S of the From time is same as those of To time
  @return  <0   The H/M/S of the From time is earlier than those of To time
**/
INTN
CompareHMS (
  IN EFI_TIME  *From,
  IN EFI_TIME  *To
  );

/**
  To check if second date is later than first date within 24 hours.

  @param  From   the first date
  @param  To     the second date

  @retval TRUE   From is previous to To within 24 hours.
  @retval FALSE  From is later, or it is previous to To more than 24 hours.
**/
BOOLEAN
IsWithinOneDay (
  IN EFI_TIME  *From,
  IN EFI_TIME  *To
  );

/**
  Read RTC content through its registers using IO access.

  @param  Address   Address offset of RTC. It is recommended to use
                    macros such as RTC_ADDRESS_SECONDS.

  @return The data of UINT8 type read from RTC.
**/
STATIC
UINT8
IoRtcRead (
  IN  UINTN  Address
  )
{
  IoWrite8 (
    PcdGet8 (PcdRtcIndexRegister),
    (UINT8)(Address | (UINT8)(IoRead8 (PcdGet8 (PcdRtcIndexRegister)) & 0x80))
    );
  return IoRead8 (PcdGet8 (PcdRtcTargetRegister));
}

/**
  Write RTC through its registers  using IO access.

  @param  Address   Address offset of RTC. It is recommended to use
                    macros such as RTC_ADDRESS_SECONDS.
  @param  Data      The content you want to write into RTC.

**/
STATIC
VOID
IoRtcWrite (
  IN  UINTN  Address,
  IN  UINT8  Data
  )
{
  IoWrite8 (
    PcdGet8 (PcdRtcIndexRegister),
    (UINT8)(Address | (UINT8)(IoRead8 (PcdGet8 (PcdRtcIndexRegister)) & 0x80))
    );
  IoWrite8 (PcdGet8 (PcdRtcTargetRegister), Data);
}

/**
  Read RTC content through its registers using MMIO access.

  @param  Address   Address offset of RTC. It is recommended to use
                    macros such as RTC_ADDRESS_SECONDS.

  @return The data of UINT8 type read from RTC.
**/
STATIC
UINT8
MmioRtcRead (
  IN  UINTN  Address
  )
{
  MmioWrite8 (
    mRtcIndexRegister,
    (UINT8)(Address | (UINT8)(MmioRead8 (mRtcIndexRegister) & 0x80))
    );
  return MmioRead8 (mRtcTargetRegister);
}

/**
  Write RTC through its registers using MMIO access.

  @param  Address   Address offset of RTC. It is recommended to use
                    macros such as RTC_ADDRESS_SECONDS.
  @param  Data      The content you want to write into RTC.

**/
STATIC
VOID
MmioRtcWrite (
  IN  UINTN  Address,
  IN  UINT8  Data
  )
{
  MmioWrite8 (
    mRtcIndexRegister,
    (UINT8)(Address | (UINT8)(MmioRead8 (mRtcIndexRegister) & 0x80))
    );
  MmioWrite8 (mRtcTargetRegister, Data);
}

/**
  Read RTC content through its registers.

  @param  Address   Address offset of RTC. It is recommended to use
                    macros such as RTC_ADDRESS_SECONDS.

  @return The data of UINT8 type read from RTC.
**/
STATIC
UINT8
RtcRead (
  IN  UINTN  Address
  )
{
  if (FeaturePcdGet (PcdRtcUseMmio)) {
    return MmioRtcRead (Address);
  }

  return IoRtcRead (Address);
}

/**
  Write RTC through its registers.

  @param  Address   Address offset of RTC. It is recommended to use
                    macros such as RTC_ADDRESS_SECONDS.
  @param  Data      The content you want to write into RTC.

**/
STATIC
VOID
RtcWrite (
  IN  UINTN  Address,
  IN  UINT8  Data
  )
{
  if (FeaturePcdGet (PcdRtcUseMmio)) {
    MmioRtcWrite (Address, Data);
  } else {
    IoRtcWrite (Address, Data);
  }
}

/**
  Initialize RTC.

  @param  Global            For global use inside this module.

  @retval EFI_DEVICE_ERROR  Initialization failed due to device error.
  @retval EFI_SUCCESS       Initialization successful.

**/
EFI_STATUS
PcRtcInit (
  IN PC_RTC_MODULE_GLOBALS  *Global
  )
{
  EFI_STATUS      Status;
  RTC_REGISTER_A  RegisterA;
  RTC_REGISTER_B  RegisterB;
  RTC_REGISTER_D  RegisterD;
  EFI_TIME        Time;
  UINTN           DataSize;
  UINT32          TimerVar;
  BOOLEAN         Enabled;
  BOOLEAN         Pending;

  //
  // Acquire RTC Lock to make access to RTC atomic
  //
  if (!EfiAtRuntime ()) {
    EfiAcquireLock (&Global->RtcLock);
  }

  //
  // Initialize RTC Register
  //
  // Make sure Division Chain is properly configured,
  // or RTC clock won't "tick" -- time won't increment
  //
  RegisterA.Data = FixedPcdGet8 (PcdInitialValueRtcRegisterA);
  RtcWrite (RTC_ADDRESS_REGISTER_A, RegisterA.Data);

  //
  // Read Register B
  //
  RegisterB.Data = RtcRead (RTC_ADDRESS_REGISTER_B);

  //
  // Clear RTC flag register
  //
  RtcRead (RTC_ADDRESS_REGISTER_C);

  //
  // Clear RTC register D
  //
  RegisterD.Data = FixedPcdGet8 (PcdInitialValueRtcRegisterD);
  RtcWrite (RTC_ADDRESS_REGISTER_D, RegisterD.Data);

  //
  // Wait for up to 0.1 seconds for the RTC to be updated
  //
  Status = RtcWaitToUpdate (PcdGet32 (PcdRealTimeClockUpdateTimeout));
  if (EFI_ERROR (Status)) {
    //
    // Set the variable with default value if the RTC is functioning incorrectly.
    //
    Global->SavedTimeZone = EFI_UNSPECIFIED_TIMEZONE;
    Global->Daylight      = 0;
    if (!EfiAtRuntime ()) {
      EfiReleaseLock (&Global->RtcLock);
    }

    return EFI_DEVICE_ERROR;
  }

  //
  // Get the Time/Date/Daylight Savings values.
  //
  Time.Second = RtcRead (RTC_ADDRESS_SECONDS);
  Time.Minute = RtcRead (RTC_ADDRESS_MINUTES);
  Time.Hour   = RtcRead (RTC_ADDRESS_HOURS);
  Time.Day    = RtcRead (RTC_ADDRESS_DAY_OF_THE_MONTH);
  Time.Month  = RtcRead (RTC_ADDRESS_MONTH);
  Time.Year   = RtcRead (RTC_ADDRESS_YEAR);

  //
  // Set RTC configuration after get original time
  // The value of bit AIE should be reserved.
  //
  RegisterB.Data = FixedPcdGet8 (PcdInitialValueRtcRegisterB) | (RegisterB.Data & BIT5);
  RtcWrite (RTC_ADDRESS_REGISTER_B, RegisterB.Data);

  //
  // Release RTC Lock.
  //
  if (!EfiAtRuntime ()) {
    EfiReleaseLock (&Global->RtcLock);
  }

  //
  // Get the data of Daylight saving and time zone, if they have been
  // stored in NV variable during previous boot.
  //
  DataSize = sizeof (UINT32);
  Status   = EfiGetVariable (
               mTimeZoneVariableName,
               &gEfiCallerIdGuid,
               NULL,
               &DataSize,
               &TimerVar
               );
  if (!EFI_ERROR (Status)) {
    Time.TimeZone = (INT16)TimerVar;
    Time.Daylight = (UINT8)(TimerVar >> 16);
  } else {
    Time.TimeZone = EFI_UNSPECIFIED_TIMEZONE;
    Time.Daylight = 0;
  }

  //
  // Validate time fields
  //
  Status = ConvertRtcTimeToEfiTime (&Time, RegisterB);
  if (!EFI_ERROR (Status)) {
    Status = RtcTimeFieldsValid (&Time);
  }

  if (EFI_ERROR (Status)) {
    //
    // Report Status Code to indicate that the RTC has bad date and time
    //
    REPORT_STATUS_CODE (
      EFI_ERROR_CODE | EFI_ERROR_MINOR,
      (EFI_SOFTWARE_DXE_RT_DRIVER | EFI_SW_EC_BAD_DATE_TIME)
      );
    Time.Second     = RTC_INIT_SECOND;
    Time.Minute     = RTC_INIT_MINUTE;
    Time.Hour       = RTC_INIT_HOUR;
    Time.Day        = RTC_INIT_DAY;
    Time.Month      = RTC_INIT_MONTH;
    Time.Year       = PcdGet16 (PcdMinimalValidYear);
    Time.Nanosecond = 0;
    Time.TimeZone   = EFI_UNSPECIFIED_TIMEZONE;
    Time.Daylight   = 0;
  }

  //
  // Reset time value according to new RTC configuration
  //
  Status = PcRtcSetTime (&Time, Global);
  if (EFI_ERROR (Status)) {
    return EFI_DEVICE_ERROR;
  }

  //
  // Reset wakeup time value to valid state when wakeup alarm is disabled and wakeup time is invalid.
  // Global variable has already had valid SavedTimeZone and Daylight,
  // so we can use them to get and set wakeup time.
  //
  Status = PcRtcGetWakeupTime (&Enabled, &Pending, &Time, Global);
  if ((Enabled) || (!EFI_ERROR (Status))) {
    return EFI_SUCCESS;
  }

  //
  // When wakeup time is disabled and invalid, reset wakeup time register to valid state
  // but keep wakeup alarm disabled.
  //
  Time.Second     = RTC_INIT_SECOND;
  Time.Minute     = RTC_INIT_MINUTE;
  Time.Hour       = RTC_INIT_HOUR;
  Time.Day        = RTC_INIT_DAY;
  Time.Month      = RTC_INIT_MONTH;
  Time.Year       = PcdGet16 (PcdMinimalValidYear);
  Time.Nanosecond = 0;
  Time.TimeZone   = Global->SavedTimeZone;
  Time.Daylight   = Global->Daylight;

  //
  // Acquire RTC Lock to make access to RTC atomic
  //
  if (!EfiAtRuntime ()) {
    EfiAcquireLock (&Global->RtcLock);
  }

  //
  // Wait for up to 0.1 seconds for the RTC to be updated
  //
  Status = RtcWaitToUpdate (PcdGet32 (PcdRealTimeClockUpdateTimeout));
  if (EFI_ERROR (Status)) {
    if (!EfiAtRuntime ()) {
      EfiReleaseLock (&Global->RtcLock);
    }

    return EFI_DEVICE_ERROR;
  }

  ConvertEfiTimeToRtcTime (&Time, RegisterB);

  //
  // Set the Y/M/D info to variable as it has no corresponding hw registers.
  //
  Status =  EfiSetVariable (
              L"RTCALARM",
              &gEfiCallerIdGuid,
              EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE,
              sizeof (Time),
              &Time
              );
  if (EFI_ERROR (Status)) {
    if (!EfiAtRuntime ()) {
      EfiReleaseLock (&Global->RtcLock);
    }

    return EFI_DEVICE_ERROR;
  }

  //
  // Inhibit updates of the RTC
  //
  RegisterB.Bits.Set = 1;
  RtcWrite (RTC_ADDRESS_REGISTER_B, RegisterB.Data);

  //
  // Set RTC alarm time registers
  //
  RtcWrite (RTC_ADDRESS_SECONDS_ALARM, Time.Second);
  RtcWrite (RTC_ADDRESS_MINUTES_ALARM, Time.Minute);
  RtcWrite (RTC_ADDRESS_HOURS_ALARM, Time.Hour);

  //
  // Allow updates of the RTC registers
  //
  RegisterB.Bits.Set = 0;
  RtcWrite (RTC_ADDRESS_REGISTER_B, RegisterB.Data);

  //
  // Release RTC Lock.
  //
  if (!EfiAtRuntime ()) {
    EfiReleaseLock (&Global->RtcLock);
  }

  return EFI_SUCCESS;
}

/**
  Returns the current time and date information, and the time-keeping capabilities
  of the hardware platform.

  @param  Time          A pointer to storage to receive a snapshot of the current time.
  @param  Capabilities  An optional pointer to a buffer to receive the real time clock
                        device's capabilities.
  @param  Global        For global use inside this module.

  @retval EFI_SUCCESS            The operation completed successfully.
  @retval EFI_INVALID_PARAMETER  Time is NULL.
  @retval EFI_DEVICE_ERROR       The time could not be retrieved due to hardware error.

**/
EFI_STATUS
PcRtcGetTime (
  OUT  EFI_TIME               *Time,
  OUT  EFI_TIME_CAPABILITIES  *Capabilities   OPTIONAL,
  IN   PC_RTC_MODULE_GLOBALS  *Global
  )
{
  EFI_STATUS      Status;
  RTC_REGISTER_B  RegisterB;

  //
  // Check parameters for null pointer
  //
  if (Time == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Acquire RTC Lock to make access to RTC atomic
  //
  if (!EfiAtRuntime ()) {
    EfiAcquireLock (&Global->RtcLock);
  }

  //
  // Wait for up to 0.1 seconds for the RTC to be updated
  //
  Status = RtcWaitToUpdate (PcdGet32 (PcdRealTimeClockUpdateTimeout));
  if (EFI_ERROR (Status)) {
    if (!EfiAtRuntime ()) {
      EfiReleaseLock (&Global->RtcLock);
    }

    return Status;
  }

  //
  // Read Register B
  //
  RegisterB.Data = RtcRead (RTC_ADDRESS_REGISTER_B);

  //
  // Get the Time/Date/Daylight Savings values.
  //
  Time->Second = RtcRead (RTC_ADDRESS_SECONDS);
  Time->Minute = RtcRead (RTC_ADDRESS_MINUTES);
  Time->Hour   = RtcRead (RTC_ADDRESS_HOURS);
  Time->Day    = RtcRead (RTC_ADDRESS_DAY_OF_THE_MONTH);
  Time->Month  = RtcRead (RTC_ADDRESS_MONTH);
  Time->Year   = RtcRead (RTC_ADDRESS_YEAR);

  //
  // Release RTC Lock.
  //
  if (!EfiAtRuntime ()) {
    EfiReleaseLock (&Global->RtcLock);
  }

  //
  // Get the variable that contains the TimeZone and Daylight fields
  //
  Time->TimeZone = Global->SavedTimeZone;
  Time->Daylight = Global->Daylight;

  //
  // Make sure all field values are in correct range
  //
  Status = ConvertRtcTimeToEfiTime (Time, RegisterB);
  if (!EFI_ERROR (Status)) {
    Status = RtcTimeFieldsValid (Time);
  }

  if (EFI_ERROR (Status)) {
    return EFI_DEVICE_ERROR;
  }

  //
  //  Fill in Capabilities if it was passed in
  //
  if (Capabilities != NULL) {
    Capabilities->Resolution = 1;
    //
    // 1 hertz
    //
    Capabilities->Accuracy = 50000000;
    //
    // 50 ppm
    //
    Capabilities->SetsToZero = FALSE;
  }

  return EFI_SUCCESS;
}

/**
  Sets the current local time and date information.

  @param  Time                  A pointer to the current time.
  @param  Global                For global use inside this module.

  @retval EFI_SUCCESS           The operation completed successfully.
  @retval EFI_INVALID_PARAMETER A time field is out of range.
  @retval EFI_DEVICE_ERROR      The time could not be set due due to hardware error.

**/
EFI_STATUS
PcRtcSetTime (
  IN EFI_TIME               *Time,
  IN PC_RTC_MODULE_GLOBALS  *Global
  )
{
  EFI_STATUS      Status;
  EFI_TIME        RtcTime;
  RTC_REGISTER_B  RegisterB;
  UINT32          TimerVar;

  if (Time == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Make sure that the time fields are valid
  //
  Status = RtcTimeFieldsValid (Time);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  CopyMem (&RtcTime, Time, sizeof (EFI_TIME));

  //
  // Acquire RTC Lock to make access to RTC atomic
  //
  if (!EfiAtRuntime ()) {
    EfiAcquireLock (&Global->RtcLock);
  }

  //
  // Wait for up to 0.1 seconds for the RTC to be updated
  //
  Status = RtcWaitToUpdate (PcdGet32 (PcdRealTimeClockUpdateTimeout));
  if (EFI_ERROR (Status)) {
    if (!EfiAtRuntime ()) {
      EfiReleaseLock (&Global->RtcLock);
    }

    return Status;
  }

  //
  // Write timezone and daylight to RTC variable
  //
  if ((Time->TimeZone == EFI_UNSPECIFIED_TIMEZONE) && (Time->Daylight == 0)) {
    Status = EfiSetVariable (
               mTimeZoneVariableName,
               &gEfiCallerIdGuid,
               0,
               0,
               NULL
               );
    if (Status == EFI_NOT_FOUND) {
      Status = EFI_SUCCESS;
    }
  } else {
    TimerVar = Time->Daylight;
    TimerVar = (UINT32)((TimerVar << 16) | (UINT16)(Time->TimeZone));
    Status   = EfiSetVariable (
                 mTimeZoneVariableName,
                 &gEfiCallerIdGuid,
                 EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE,
                 sizeof (TimerVar),
                 &TimerVar
                 );
  }

  if (EFI_ERROR (Status)) {
    if (!EfiAtRuntime ()) {
      EfiReleaseLock (&Global->RtcLock);
    }

    return EFI_DEVICE_ERROR;
  }

  //
  // Read Register B, and inhibit updates of the RTC
  //
  RegisterB.Data     = RtcRead (RTC_ADDRESS_REGISTER_B);
  RegisterB.Bits.Set = 1;
  RtcWrite (RTC_ADDRESS_REGISTER_B, RegisterB.Data);

  //
  // Store the century value to RTC before converting to BCD format.
  //
  if (Global->CenturyRtcAddress != 0) {
    RtcWrite (Global->CenturyRtcAddress, DecimalToBcd8 ((UINT8)(RtcTime.Year / 100)));
  }

  ConvertEfiTimeToRtcTime (&RtcTime, RegisterB);

  RtcWrite (RTC_ADDRESS_SECONDS, RtcTime.Second);
  RtcWrite (RTC_ADDRESS_MINUTES, RtcTime.Minute);
  RtcWrite (RTC_ADDRESS_HOURS, RtcTime.Hour);
  RtcWrite (RTC_ADDRESS_DAY_OF_THE_MONTH, RtcTime.Day);
  RtcWrite (RTC_ADDRESS_MONTH, RtcTime.Month);
  RtcWrite (RTC_ADDRESS_YEAR, (UINT8)RtcTime.Year);

  //
  // Allow updates of the RTC registers
  //
  RegisterB.Bits.Set = 0;
  RtcWrite (RTC_ADDRESS_REGISTER_B, RegisterB.Data);

  //
  // Release RTC Lock.
  //
  if (!EfiAtRuntime ()) {
    EfiReleaseLock (&Global->RtcLock);
  }

  //
  // Set the variable that contains the TimeZone and Daylight fields
  //
  Global->SavedTimeZone = Time->TimeZone;
  Global->Daylight      = Time->Daylight;

  return EFI_SUCCESS;
}

/**
  Returns the current wakeup alarm clock setting.

  @param  Enabled  Indicates if the alarm is currently enabled or disabled.
  @param  Pending  Indicates if the alarm signal is pending and requires acknowledgment.
  @param  Time     The current alarm setting.
  @param  Global   For global use inside this module.

  @retval EFI_SUCCESS           The alarm settings were returned.
  @retval EFI_INVALID_PARAMETER Enabled is NULL.
  @retval EFI_INVALID_PARAMETER Pending is NULL.
  @retval EFI_INVALID_PARAMETER Time is NULL.
  @retval EFI_DEVICE_ERROR      The wakeup time could not be retrieved due to a hardware error.
  @retval EFI_UNSUPPORTED       A wakeup timer is not supported on this platform.

**/
EFI_STATUS
PcRtcGetWakeupTime (
  OUT BOOLEAN                *Enabled,
  OUT BOOLEAN                *Pending,
  OUT EFI_TIME               *Time,
  IN  PC_RTC_MODULE_GLOBALS  *Global
  )
{
  EFI_STATUS      Status;
  RTC_REGISTER_B  RegisterB;
  RTC_REGISTER_C  RegisterC;
  EFI_TIME        RtcTime;
  UINTN           DataSize;

  //
  // Check parameters for null pointers
  //
  if ((Enabled == NULL) || (Pending == NULL) || (Time == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Acquire RTC Lock to make access to RTC atomic
  //
  if (!EfiAtRuntime ()) {
    EfiAcquireLock (&Global->RtcLock);
  }

  //
  // Wait for up to 0.1 seconds for the RTC to be updated
  //
  Status = RtcWaitToUpdate (PcdGet32 (PcdRealTimeClockUpdateTimeout));
  if (EFI_ERROR (Status)) {
    if (!EfiAtRuntime ()) {
      EfiReleaseLock (&Global->RtcLock);
    }

    return EFI_DEVICE_ERROR;
  }

  //
  // Read Register B and Register C
  //
  RegisterB.Data = RtcRead (RTC_ADDRESS_REGISTER_B);
  RegisterC.Data = RtcRead (RTC_ADDRESS_REGISTER_C);

  //
  // Get the Time/Date/Daylight Savings values.
  //
  *Enabled = RegisterB.Bits.Aie;
  *Pending = RegisterC.Bits.Af;

  Time->Second   = RtcRead (RTC_ADDRESS_SECONDS_ALARM);
  Time->Minute   = RtcRead (RTC_ADDRESS_MINUTES_ALARM);
  Time->Hour     = RtcRead (RTC_ADDRESS_HOURS_ALARM);
  Time->Day      = RtcRead (RTC_ADDRESS_DAY_OF_THE_MONTH);
  Time->Month    = RtcRead (RTC_ADDRESS_MONTH);
  Time->Year     = RtcRead (RTC_ADDRESS_YEAR);
  Time->TimeZone = Global->SavedTimeZone;
  Time->Daylight = Global->Daylight;

  //
  // Get the alarm info from variable
  //
  DataSize = sizeof (EFI_TIME);
  Status   = EfiGetVariable (
               L"RTCALARM",
               &gEfiCallerIdGuid,
               NULL,
               &DataSize,
               &RtcTime
               );
  if (!EFI_ERROR (Status)) {
    //
    // The alarm variable exists. In this case, we read variable to get info.
    //
    Time->Day   = RtcTime.Day;
    Time->Month = RtcTime.Month;
    Time->Year  = RtcTime.Year;
  }

  //
  // Release RTC Lock.
  //
  if (!EfiAtRuntime ()) {
    EfiReleaseLock (&Global->RtcLock);
  }

  //
  // Make sure all field values are in correct range
  //
  Status = ConvertRtcTimeToEfiTime (Time, RegisterB);
  if (!EFI_ERROR (Status)) {
    Status = RtcTimeFieldsValid (Time);
  }

  if (EFI_ERROR (Status)) {
    return EFI_DEVICE_ERROR;
  }

  return EFI_SUCCESS;
}

/**
  Sets the system wakeup alarm clock time.

  @param  Enabled  Enable or disable the wakeup alarm.
  @param  Time     If Enable is TRUE, the time to set the wakeup alarm for.
                   If Enable is FALSE, then this parameter is optional, and may be NULL.
  @param  Global   For global use inside this module.

  @retval EFI_SUCCESS           If Enable is TRUE, then the wakeup alarm was enabled.
                                If Enable is FALSE, then the wakeup alarm was disabled.
  @retval EFI_INVALID_PARAMETER A time field is out of range.
  @retval EFI_DEVICE_ERROR      The wakeup time could not be set due to a hardware error.
  @retval EFI_UNSUPPORTED       A wakeup timer is not supported on this platform.

**/
EFI_STATUS
PcRtcSetWakeupTime (
  IN BOOLEAN                Enable,
  IN EFI_TIME               *Time    OPTIONAL,
  IN PC_RTC_MODULE_GLOBALS  *Global
  )
{
  EFI_STATUS             Status;
  EFI_TIME               RtcTime;
  RTC_REGISTER_B         RegisterB;
  EFI_TIME_CAPABILITIES  Capabilities;

  ZeroMem (&RtcTime, sizeof (RtcTime));

  if (Enable) {
    if (Time == NULL) {
      return EFI_INVALID_PARAMETER;
    }

    //
    // Make sure that the time fields are valid
    //
    Status = RtcTimeFieldsValid (Time);
    if (EFI_ERROR (Status)) {
      return EFI_INVALID_PARAMETER;
    }

    //
    // Just support set alarm time within 24 hours
    //
    PcRtcGetTime (&RtcTime, &Capabilities, Global);
    Status = RtcTimeFieldsValid (&RtcTime);
    if (EFI_ERROR (Status)) {
      return EFI_DEVICE_ERROR;
    }

    if (!IsWithinOneDay (&RtcTime, Time)) {
      return EFI_UNSUPPORTED;
    }

    //
    // Make a local copy of the time and date
    //
    CopyMem (&RtcTime, Time, sizeof (EFI_TIME));
  }

  //
  // Acquire RTC Lock to make access to RTC atomic
  //
  if (!EfiAtRuntime ()) {
    EfiAcquireLock (&Global->RtcLock);
  }

  //
  // Wait for up to 0.1 seconds for the RTC to be updated
  //
  Status = RtcWaitToUpdate (PcdGet32 (PcdRealTimeClockUpdateTimeout));
  if (EFI_ERROR (Status)) {
    if (!EfiAtRuntime ()) {
      EfiReleaseLock (&Global->RtcLock);
    }

    return EFI_DEVICE_ERROR;
  }

  //
  // Read Register B
  //
  RegisterB.Data = RtcRead (RTC_ADDRESS_REGISTER_B);

  if (Enable) {
    ConvertEfiTimeToRtcTime (&RtcTime, RegisterB);
  } else {
    //
    // if the alarm is disable, record the current setting.
    //
    RtcTime.Second   = RtcRead (RTC_ADDRESS_SECONDS_ALARM);
    RtcTime.Minute   = RtcRead (RTC_ADDRESS_MINUTES_ALARM);
    RtcTime.Hour     = RtcRead (RTC_ADDRESS_HOURS_ALARM);
    RtcTime.Day      = RtcRead (RTC_ADDRESS_DAY_OF_THE_MONTH);
    RtcTime.Month    = RtcRead (RTC_ADDRESS_MONTH);
    RtcTime.Year     = RtcRead (RTC_ADDRESS_YEAR);
    RtcTime.TimeZone = Global->SavedTimeZone;
    RtcTime.Daylight = Global->Daylight;
  }

  //
  // Set the Y/M/D info to variable as it has no corresponding hw registers.
  //
  Status =  EfiSetVariable (
              L"RTCALARM",
              &gEfiCallerIdGuid,
              EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE,
              sizeof (RtcTime),
              &RtcTime
              );
  if (EFI_ERROR (Status)) {
    if (!EfiAtRuntime ()) {
      EfiReleaseLock (&Global->RtcLock);
    }

    return EFI_DEVICE_ERROR;
  }

  //
  // Inhibit updates of the RTC
  //
  RegisterB.Bits.Set = 1;
  RtcWrite (RTC_ADDRESS_REGISTER_B, RegisterB.Data);

  if (Enable) {
    //
    // Set RTC alarm time
    //
    RtcWrite (RTC_ADDRESS_SECONDS_ALARM, RtcTime.Second);
    RtcWrite (RTC_ADDRESS_MINUTES_ALARM, RtcTime.Minute);
    RtcWrite (RTC_ADDRESS_HOURS_ALARM, RtcTime.Hour);

    RegisterB.Bits.Aie = 1;
  } else {
    RegisterB.Bits.Aie = 0;
  }

  //
  // Allow updates of the RTC registers
  //
  RegisterB.Bits.Set = 0;
  RtcWrite (RTC_ADDRESS_REGISTER_B, RegisterB.Data);

  //
  // Release RTC Lock.
  //
  if (!EfiAtRuntime ()) {
    EfiReleaseLock (&Global->RtcLock);
  }

  return EFI_SUCCESS;
}

/**
  Checks an 8-bit BCD value, and converts to an 8-bit value if valid.

  This function checks the 8-bit BCD value specified by Value.
  If valid, the function converts it to an 8-bit value and returns it.
  Otherwise, return 0xff.

  @param   Value The 8-bit BCD value to check and convert

  @return  The 8-bit value converted. Or 0xff if Value is invalid.

**/
UINT8
CheckAndConvertBcd8ToDecimal8 (
  IN  UINT8  Value
  )
{
  if ((Value < 0xa0) && ((Value & 0xf) < 0xa)) {
    return BcdToDecimal8 (Value);
  }

  return 0xff;
}

/**
  Converts time read from RTC to EFI_TIME format defined by UEFI spec.

  This function converts raw time data read from RTC to the EFI_TIME format
  defined by UEFI spec.
  If data mode of RTC is BCD, then converts it to decimal,
  If RTC is in 12-hour format, then converts it to 24-hour format.

  @param   Time       On input, the time data read from RTC to convert
                      On output, the time converted to UEFI format
  @param   RegisterB  Value of Register B of RTC, indicating data mode
                      and hour format.

  @retval  EFI_INVALID_PARAMETER  Parameters passed in are invalid.
  @retval  EFI_SUCCESS            Convert RTC time to EFI time successfully.

**/
EFI_STATUS
ConvertRtcTimeToEfiTime (
  IN OUT EFI_TIME        *Time,
  IN     RTC_REGISTER_B  RegisterB
  )
{
  BOOLEAN  IsPM;
  UINT8    Century;

  if ((Time->Hour & 0x80) != 0) {
    IsPM = TRUE;
  } else {
    IsPM = FALSE;
  }

  Time->Hour = (UINT8)(Time->Hour & 0x7f);

  if (RegisterB.Bits.Dm == 0) {
    Time->Year   = CheckAndConvertBcd8ToDecimal8 ((UINT8)Time->Year);
    Time->Month  = CheckAndConvertBcd8ToDecimal8 (Time->Month);
    Time->Day    = CheckAndConvertBcd8ToDecimal8 (Time->Day);
    Time->Hour   = CheckAndConvertBcd8ToDecimal8 (Time->Hour);
    Time->Minute = CheckAndConvertBcd8ToDecimal8 (Time->Minute);
    Time->Second = CheckAndConvertBcd8ToDecimal8 (Time->Second);
  }

  if ((Time->Year == 0xff) || (Time->Month == 0xff) || (Time->Day == 0xff) ||
      (Time->Hour == 0xff) || (Time->Minute == 0xff) || (Time->Second == 0xff))
  {
    return EFI_INVALID_PARAMETER;
  }

  //
  // For minimal/maximum year range [1970, 2069],
  //   Century is 19 if RTC year >= 70,
  //   Century is 20 otherwise.
  //
  Century = (UINT8)(PcdGet16 (PcdMinimalValidYear) / 100);
  if (Time->Year < PcdGet16 (PcdMinimalValidYear) % 100) {
    Century++;
  }

  Time->Year = (UINT16)(Century * 100 + Time->Year);

  //
  // If time is in 12 hour format, convert it to 24 hour format
  //
  if (RegisterB.Bits.Mil == 0) {
    if (IsPM && (Time->Hour < 12)) {
      Time->Hour = (UINT8)(Time->Hour + 12);
    }

    if (!IsPM && (Time->Hour == 12)) {
      Time->Hour = 0;
    }
  }

  Time->Nanosecond = 0;

  return EFI_SUCCESS;
}

/**
  Wait for a period for the RTC to be ready.

  @param    Timeout  Tell how long it should take to wait.

  @retval   EFI_DEVICE_ERROR   RTC device error.
  @retval   EFI_SUCCESS        RTC is updated and ready.
**/
EFI_STATUS
RtcWaitToUpdate (
  UINTN  Timeout
  )
{
  RTC_REGISTER_A  RegisterA;
  RTC_REGISTER_D  RegisterD;

  //
  // See if the RTC is functioning correctly
  //
  RegisterD.Data = RtcRead (RTC_ADDRESS_REGISTER_D);

  if (RegisterD.Bits.Vrt == 0) {
    return EFI_DEVICE_ERROR;
  }

  //
  // Wait for up to 0.1 seconds for the RTC to be ready.
  //
  Timeout        = (Timeout / 10) + 1;
  RegisterA.Data = RtcRead (RTC_ADDRESS_REGISTER_A);
  while (RegisterA.Bits.Uip == 1 && Timeout > 0) {
    MicroSecondDelay (10);
    RegisterA.Data = RtcRead (RTC_ADDRESS_REGISTER_A);
    Timeout--;
  }

  RegisterD.Data = RtcRead (RTC_ADDRESS_REGISTER_D);
  if ((Timeout == 0) || (RegisterD.Bits.Vrt == 0)) {
    return EFI_DEVICE_ERROR;
  }

  return EFI_SUCCESS;
}

/**
  See if all fields of a variable of EFI_TIME type is correct.

  @param   Time   The time to be checked.

  @retval  EFI_INVALID_PARAMETER  Some fields of Time are not correct.
  @retval  EFI_SUCCESS            Time is a valid EFI_TIME variable.

**/
EFI_STATUS
RtcTimeFieldsValid (
  IN EFI_TIME  *Time
  )
{
  if ((Time->Year < PcdGet16 (PcdMinimalValidYear)) ||
      (Time->Year > PcdGet16 (PcdMaximalValidYear)) ||
      (Time->Month < 1) ||
      (Time->Month > 12) ||
      (!DayValid (Time)) ||
      (Time->Hour > 23) ||
      (Time->Minute > 59) ||
      (Time->Second > 59) ||
      (Time->Nanosecond > 999999999) ||
      (!((Time->TimeZone == EFI_UNSPECIFIED_TIMEZONE) || ((Time->TimeZone >= -1440) && (Time->TimeZone <= 1440)))) ||
      ((Time->Daylight & (~(EFI_TIME_ADJUST_DAYLIGHT | EFI_TIME_IN_DAYLIGHT))) != 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}

/**
  See if field Day of an EFI_TIME is correct.

  @param    Time   Its Day field is to be checked.

  @retval   TRUE   Day field of Time is correct.
  @retval   FALSE  Day field of Time is NOT correct.
**/
BOOLEAN
DayValid (
  IN  EFI_TIME  *Time
  )
{
  //
  // The validity of Time->Month field should be checked before
  //
  ASSERT (Time->Month >= 1);
  ASSERT (Time->Month <= 12);
  if ((Time->Day < 1) ||
      (Time->Day > mDayOfMonth[Time->Month - 1]) ||
      ((Time->Month == 2) && (!IsLeapYear (Time) && (Time->Day > 28)))
      )
  {
    return FALSE;
  }

  return TRUE;
}

/**
  Check if it is a leap year.

  @param    Time   The time to be checked.

  @retval   TRUE   It is a leap year.
  @retval   FALSE  It is NOT a leap year.
**/
BOOLEAN
IsLeapYear (
  IN EFI_TIME  *Time
  )
{
  if (Time->Year % 4 == 0) {
    if (Time->Year % 100 == 0) {
      if (Time->Year % 400 == 0) {
        return TRUE;
      } else {
        return FALSE;
      }
    } else {
      return TRUE;
    }
  } else {
    return FALSE;
  }
}

/**
  Converts time from EFI_TIME format defined by UEFI spec to RTC format.

  This function converts time from EFI_TIME format defined by UEFI spec to RTC format.
  If data mode of RTC is BCD, then converts EFI_TIME to it.
  If RTC is in 12-hour format, then converts EFI_TIME to it.

  @param   Time       On input, the time data read from UEFI to convert
                      On output, the time converted to RTC format
  @param   RegisterB  Value of Register B of RTC, indicating data mode
**/
VOID
ConvertEfiTimeToRtcTime (
  IN OUT EFI_TIME        *Time,
  IN     RTC_REGISTER_B  RegisterB
  )
{
  BOOLEAN  IsPM;

  IsPM = TRUE;
  //
  // Adjust hour field if RTC is in 12 hour mode
  //
  if (RegisterB.Bits.Mil == 0) {
    if (Time->Hour < 12) {
      IsPM = FALSE;
    }

    if (Time->Hour >= 13) {
      Time->Hour = (UINT8)(Time->Hour - 12);
    } else if (Time->Hour == 0) {
      Time->Hour = 12;
    }
  }

  //
  // Set the Time/Date values.
  //
  Time->Year = (UINT16)(Time->Year % 100);

  if (RegisterB.Bits.Dm == 0) {
    Time->Year   = DecimalToBcd8 ((UINT8)Time->Year);
    Time->Month  = DecimalToBcd8 (Time->Month);
    Time->Day    = DecimalToBcd8 (Time->Day);
    Time->Hour   = DecimalToBcd8 (Time->Hour);
    Time->Minute = DecimalToBcd8 (Time->Minute);
    Time->Second = DecimalToBcd8 (Time->Second);
  }

  //
  // If we are in 12 hour mode and PM is set, then set bit 7 of the Hour field.
  //
  if ((RegisterB.Bits.Mil == 0) && IsPM) {
    Time->Hour = (UINT8)(Time->Hour | 0x80);
  }
}

/**
  Compare the Hour, Minute and Second of the From time and the To time.

  Only compare H/M/S in EFI_TIME and ignore other fields here.

  @param From   the first time
  @param To     the second time

  @return  >0   The H/M/S of the From time is later than those of To time
  @return  ==0  The H/M/S of the From time is same as those of To time
  @return  <0   The H/M/S of the From time is earlier than those of To time
**/
INTN
CompareHMS (
  IN EFI_TIME  *From,
  IN EFI_TIME  *To
  )
{
  if ((From->Hour > To->Hour) ||
      ((From->Hour == To->Hour) && (From->Minute > To->Minute)) ||
      ((From->Hour == To->Hour) && (From->Minute == To->Minute) && (From->Second > To->Second)))
  {
    return 1;
  } else if ((From->Hour == To->Hour) && (From->Minute == To->Minute) && (From->Second == To->Second)) {
    return 0;
  } else {
    return -1;
  }
}

/**
  To check if second date is later than first date within 24 hours.

  @param  From   the first date
  @param  To     the second date

  @retval TRUE   From is previous to To within 24 hours.
  @retval FALSE  From is later, or it is previous to To more than 24 hours.
**/
BOOLEAN
IsWithinOneDay (
  IN EFI_TIME  *From,
  IN EFI_TIME  *To
  )
{
  BOOLEAN  Adjacent;

  Adjacent = FALSE;

  //
  // The validity of From->Month field should be checked before
  //
  ASSERT (From->Month >= 1);
  ASSERT (From->Month <= 12);

  if (From->Year == To->Year) {
    if (From->Month == To->Month) {
      if ((From->Day + 1) == To->Day) {
        if ((CompareHMS (From, To) >= 0)) {
          Adjacent = TRUE;
        }
      } else if (From->Day == To->Day) {
        if ((CompareHMS (From, To) <= 0)) {
          Adjacent = TRUE;
        }
      }
    } else if (((From->Month + 1) == To->Month) && (To->Day == 1)) {
      if ((From->Month == 2) && !IsLeapYear (From)) {
        if (From->Day == 28) {
          if ((CompareHMS (From, To) >= 0)) {
            Adjacent = TRUE;
          }
        }
      } else if (From->Day == mDayOfMonth[From->Month - 1]) {
        if ((CompareHMS (From, To) >= 0)) {
          Adjacent = TRUE;
        }
      }
    }
  } else if (((From->Year + 1) == To->Year) &&
             (From->Month == 12) &&
             (From->Day   == 31) &&
             (To->Month   == 1)  &&
             (To->Day     == 1))
  {
    if ((CompareHMS (From, To) >= 0)) {
      Adjacent = TRUE;
    }
  }

  return Adjacent;
}

/**
  Get the century RTC address from the ACPI FADT table.

  @return  The century RTC address or 0 if not found.
**/
UINT8
GetCenturyRtcAddress (
  VOID
  )
{
  EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE  *Fadt;

  Fadt = (EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE *)EfiLocateFirstAcpiTable (
                                                        EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE
                                                        );

  if ((Fadt != NULL) &&
      (Fadt->Century > RTC_ADDRESS_REGISTER_D) && (Fadt->Century < 0x80)
      )
  {
    return Fadt->Century;
  } else {
    return 0;
  }
}

/**
  Notification function of ACPI Table change.

  This is a notification function registered on ACPI Table change event.
  It saves the Century address stored in ACPI FADT table.

  @param  Event        Event whose notification function is being invoked.
  @param  Context      Pointer to the notification function's context.

**/
VOID
EFIAPI
PcRtcAcpiTableChangeCallback (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS  Status;
  EFI_TIME    Time;
  UINT8       CenturyRtcAddress;
  UINT8       Century;

  CenturyRtcAddress = GetCenturyRtcAddress ();
  if ((CenturyRtcAddress != 0) && (mModuleGlobal.CenturyRtcAddress != CenturyRtcAddress)) {
    mModuleGlobal.CenturyRtcAddress = CenturyRtcAddress;
    Status                          = PcRtcGetTime (&Time, NULL, &mModuleGlobal);
    if (!EFI_ERROR (Status)) {
      Century = (UINT8)(Time.Year / 100);
      Century = DecimalToBcd8 (Century);
      DEBUG ((DEBUG_INFO, "PcRtc: Write 0x%x to CMOS location 0x%x\n", Century, mModuleGlobal.CenturyRtcAddress));
      RtcWrite (mModuleGlobal.CenturyRtcAddress, Century);
    }
  }
}
