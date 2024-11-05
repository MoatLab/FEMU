/** @file
  IA32 specific functions to support Debug Support protocol.

Copyright (c) 2008 - 2010, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "PlDebugSupport.h"

IA32_IDT_GATE_DESCRIPTOR  NullDesc = {
  { 0 }
};

/**
  Get Interrupt Handle from IDT Gate Descriptor.

  @param  IdtGateDescriptor  IDT Gate Descriptor.

  @return Interrupt Handle stored in IDT Gate Descriptor.

**/
UINTN
GetInterruptHandleFromIdt (
  IN IA32_IDT_GATE_DESCRIPTOR  *IdtGateDescriptor
  )
{
  UINTN  InterruptHandle;

  //
  // InterruptHandle  0-15 : OffsetLow
  // InterruptHandle 16-31 : OffsetHigh
  //
  ((UINT16 *)&InterruptHandle)[0] = (UINT16)IdtGateDescriptor->Bits.OffsetLow;
  ((UINT16 *)&InterruptHandle)[1] = (UINT16)IdtGateDescriptor->Bits.OffsetHigh;

  return InterruptHandle;
}

/**
  Allocate pool for a new IDT entry stub.

  Copy the generic stub into the new buffer and fixup the vector number
  and jump target address.

  @param  ExceptionType   This is the exception type that the new stub will be created
                          for.
  @param  Stub            On successful exit, *Stub contains the newly allocated entry stub.

**/
VOID
CreateEntryStub (
  IN EFI_EXCEPTION_TYPE  ExceptionType,
  OUT VOID               **Stub
  )
{
  UINT8  *StubCopy;

  StubCopy = *Stub;

  //
  // Fixup the stub code for this vector
  //

  // The stub code looks like this:
  //
  //    00000000  89 25 00000004 R  mov     AppEsp, esp             ; save stack top
  //    00000006  BC 00008014 R     mov     esp, offset DbgStkBot   ; switch to debugger stack
  //    0000000B  6A 00             push    0                       ; push vector number - will be modified before installed
  //    0000000D  E9                db      0e9h                    ; jump rel32
  //    0000000E  00000000          dd      0                       ; fixed up to relative address of CommonIdtEntry
  //

  //
  // poke in the exception type so the second push pushes the exception type
  //
  StubCopy[0x0c] = (UINT8)ExceptionType;

  //
  // fixup the jump target to point to the common entry
  //
  *(UINT32 *)&StubCopy[0x0e] = (UINT32)CommonIdtEntry - (UINT32)&StubCopy[StubSize];

  return;
}

/**
  This is the main worker function that manages the state of the interrupt
  handlers.  It both installs and uninstalls interrupt handlers based on the
  value of NewCallback.  If NewCallback is NULL, then uninstall is indicated.
  If NewCallback is non-NULL, then install is indicated.

  @param  NewCallback   If non-NULL, NewCallback specifies the new handler to register.
                        If NULL, specifies that the previously registered handler should
                        be uninstalled.
  @param  ExceptionType Indicates which entry to manage.

  @retval EFI_SUCCESS            Installing or Uninstalling operation is ok.
  @retval EFI_INVALID_PARAMETER  Requested uninstalling a handler from a vector that has
                                 no handler registered for it
  @retval EFI_ALREADY_STARTED    Requested install to a vector that already has a handler registered.

**/
EFI_STATUS
ManageIdtEntryTable (
  CALLBACK_FUNC       NewCallback,
  EFI_EXCEPTION_TYPE  ExceptionType
  )
{
  EFI_STATUS  Status;

  Status = EFI_SUCCESS;

  if (CompareMem (&IdtEntryTable[ExceptionType].NewDesc, &NullDesc, sizeof (IA32_IDT_GATE_DESCRIPTOR)) != 0) {
    //
    // we've already installed to this vector
    //
    if (NewCallback != NULL) {
      //
      // if the input handler is non-null, error
      //
      Status = EFI_ALREADY_STARTED;
    } else {
      UnhookEntry (ExceptionType);
    }
  } else {
    //
    // no user handler installed on this vector
    //
    if (NewCallback == NULL) {
      //
      // if the input handler is null, error
      //
      Status = EFI_INVALID_PARAMETER;
    } else {
      HookEntry (ExceptionType, NewCallback);
    }
  }

  return Status;
}
