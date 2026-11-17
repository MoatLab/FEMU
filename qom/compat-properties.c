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

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qom/compat-properties.h"
#include "qom/qom-qobject.h"
#include "hw/core/qdev.h"

/*
 * Global property defaults
 * Slot 0: accelerator's global property defaults
 * Slot 1: machine's global property defaults
 * Slot 2: global properties from legacy command line option
 * Each is a GPtrArray of GlobalProperty.
 * Applied in order, later entries override earlier ones.
 */
static GPtrArray *object_compat_props[3];

/*
 * Retrieve @GPtrArray for global property defined with options
 * other than "-global".  These are generally used for syntactic
 * sugar and legacy command line options.
 */
void object_register_sugar_prop(const char *driver, const char *prop,
                                const char *value, bool optional)
{
    GlobalProperty *g;
    if (!object_compat_props[2]) {
        object_compat_props[2] = g_ptr_array_new();
    }
    g = g_new0(GlobalProperty, 1);
    g->driver = g_strdup(driver);
    g->property = g_strdup(prop);
    g->value = g_strdup(value);
    g->optional = optional;
    g_ptr_array_add(object_compat_props[2], g);
}

/*
 * Set machine's global property defaults to @compat_props.
 * May be called at most once.
 */
void object_set_machine_compat_props(GPtrArray *compat_props)
{
    assert(!object_compat_props[1]);
    object_compat_props[1] = compat_props;
}

/*
 * Set accelerator's global property defaults to @compat_props.
 * May be called at most once.
 */
void object_set_accelerator_compat_props(GPtrArray *compat_props)
{
    assert(!object_compat_props[0]);
    object_compat_props[0] = compat_props;
}

void object_apply_compat_props(Object *obj)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(object_compat_props); i++) {
        object_apply_global_props(obj, object_compat_props[i],
                                  i == 2 ? &error_fatal : &error_abort);
    }
}
