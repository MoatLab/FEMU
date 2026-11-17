/*
 * QEMU Object Model
 *
 * Copyright IBM, Corp. 2011
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QEMU_COMPAT_PROPERTIES_H
#define QEMU_COMPAT_PROPERTIES_H

/**
 * typedef GlobalProperty - a global property type
 *
 * @used: Set to true if property was used when initializing a device.
 * @optional: If set to true, GlobalProperty will be skipped without errors
 *            if the property doesn't exist.
 *
 * An error is fatal for non-hotplugged devices, when the global is applied.
 */
typedef struct GlobalProperty {
    const char *driver;
    const char *property;
    const char *value;
    bool used;
    bool optional;
} GlobalProperty;

void object_set_machine_compat_props(GPtrArray *compat_props);
void object_set_accelerator_compat_props(GPtrArray *compat_props);
void object_register_sugar_prop(const char *driver, const char *prop,
                                const char *value, bool optional);
void object_apply_compat_props(Object *obj);
bool object_apply_global_props(Object *obj, const GPtrArray *props,
                               Error **errp);

#endif
