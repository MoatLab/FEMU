/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_PROPS_H
#define FEMU_PROPS_H

#include "qom/object.h"

/*
 * Help text for device properties. `-device <type>,help` prints it, and
 * hw/femu/scripts/gen-property-docs.py builds the property reference from it,
 * so every user-settable property needs an entry here.
 */
typedef struct FemuPropDesc {
    const char *name;
    const char *desc;
} FemuPropDesc;

void femu_describe_class(ObjectClass *oc, const FemuPropDesc *descs);
void femu_describe_object(Object *obj, const FemuPropDesc *descs);

void femu_ctrl_describe_props(ObjectClass *oc);
void femu_ctrl_describe_runtime(Object *obj);
void femu_subsys_describe_props(ObjectClass *oc);
void femu_cxl_describe_props(ObjectClass *oc);
void femu_cxl_describe_runtime(Object *obj);

#endif
