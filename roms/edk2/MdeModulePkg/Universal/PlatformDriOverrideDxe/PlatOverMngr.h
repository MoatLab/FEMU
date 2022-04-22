/** @file

  The defintions are required both by Source code and Vfr file.
  The PLAT_OVER_MNGR_DATA structure, form guid and Ifr question ID are defined.

Copyright (c) 2007 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _PLAT_OVER_MNGR_H_
#define _PLAT_OVER_MNGR_H_

#include <Guid/PlatDriOverrideHii.h>

//
// The max number of the supported driver list.
//
#define MAX_CHOICE_NUM    0x00FF
#define UPDATE_DATA_SIZE  0x1000

#define FORM_ID_DEVICE  0x1100
#define FORM_ID_DRIVER  0x1200
#define FORM_ID_ORDER   0x1500

#define KEY_VALUE_DEVICE_OFFSET  0x0100
#define KEY_VALUE_DRIVER_OFFSET  0x0300

#define KEY_VALUE_DEVICE_REFRESH  0x1234
#define KEY_VALUE_DEVICE_FILTER   0x1235
#define KEY_VALUE_DEVICE_CLEAR    0x1236

#define KEY_VALUE_DRIVER_GOTO_PREVIOUS  0x1300
#define KEY_VALUE_DRIVER_GOTO_ORDER     0x1301

#define KEY_VALUE_ORDER_GOTO_PREVIOUS  0x2000
#define KEY_VALUE_ORDER_SAVE_AND_EXIT  0x1800

#define VARSTORE_ID_PLAT_OVER_MNGR  0x1000

#define LABEL_END  0xffff

typedef struct {
  UINT8    DriOrder[MAX_CHOICE_NUM];
  UINT8    PciDeviceFilter;
} PLAT_OVER_MNGR_DATA;

//
// Field offset of structure PLAT_OVER_MNGR_DATA
//
#define VAR_OFFSET(Field)  ((UINTN) &(((PLAT_OVER_MNGR_DATA *) 0)->Field))
#define DRIVER_ORDER_VAR_OFFSET  (VAR_OFFSET (DriOrder))

//
// Tool automatic generated Question Id start from 1
// In order to avoid to conflict them, the Driver Selection and Order QuestionID offset is defined from 0x0500.
//
#define QUESTION_ID_OFFSET        0x0500
#define DRIVER_ORDER_QUESTION_ID  (VAR_OFFSET (DriOrder) + QUESTION_ID_OFFSET)

#endif
