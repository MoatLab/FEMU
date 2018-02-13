/* AUTOMATICALLY GENERATED, DO NOT MODIFY */

/*
 * schema-defined QAPI event functions
 *
 * Copyright (c) 2014 Wenchao Xia
 *
 * Authors:
 *  Wenchao Xia  <wenchaoqemu@gmail.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#ifndef TEST_QAPI_EVENT_H
#define TEST_QAPI_EVENT_H

#include "qapi/error.h"
#include "qapi/qmp/qdict.h"
#include "test-qapi-types.h"


void qapi_event_send_event_a(Error **errp);

void qapi_event_send_event_b(Error **errp);

void qapi_event_send_event_c(bool has_a, int64_t a, bool has_b, UserDefOne *b, const char *c, Error **errp);

void qapi_event_send_event_d(EventStructOne *a, const char *b, bool has_c, const char *c, bool has_enum3, EnumOne enum3, Error **errp);

void qapi_event_send_event_e(UserDefZero *arg, Error **errp);

void qapi_event_send_event_f(UserDefAlternate *arg, Error **errp);

void qapi_event_send___org_qemu_x_event(__org_qemu_x_Enum __org_qemu_x_member1, const char *__org_qemu_x_member2, bool has_q_wchar_t, int64_t q_wchar_t, Error **errp);

typedef enum test_QAPIEvent {
    TEST_QAPI_EVENT_EVENT_A = 0,
    TEST_QAPI_EVENT_EVENT_B = 1,
    TEST_QAPI_EVENT_EVENT_C = 2,
    TEST_QAPI_EVENT_EVENT_D = 3,
    TEST_QAPI_EVENT_EVENT_E = 4,
    TEST_QAPI_EVENT_EVENT_F = 5,
    TEST_QAPI_EVENT___ORG_QEMU_X_EVENT = 6,
    TEST_QAPI_EVENT__MAX = 7,
} test_QAPIEvent;

extern const char *const test_QAPIEvent_lookup[];

#endif
