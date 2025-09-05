/*
 * QEMU CPU model
 *
 * Copyright (c) 2012-2014 SUSE LINUX Products GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <http://www.gnu.org/licenses/gpl-2.0.html>
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/core/cpu.h"
#include "system/hw_accel.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "qemu/lockcnt.h"
#include "qemu/error-report.h"
#include "qemu/qemu-print.h"
#include "qemu/target-info.h"
#include "exec/log.h"
#include "exec/gdbstub.h"
#include "system/tcg.h"
#include "hw/boards.h"
#include "hw/qdev-properties.h"
#include "trace.h"
#ifdef CONFIG_PLUGIN
#include "qemu/plugin.h"
#endif

CPUState *cpu_by_arch_id(int64_t id)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        if (cpu->cc->get_arch_id(cpu) == id) {
            return cpu;
        }
    }
    return NULL;
}

bool cpu_exists(int64_t id)
{
    return !!cpu_by_arch_id(id);
}

CPUState *cpu_create(const char *typename)
{
    Error *err = NULL;
    CPUState *cpu = CPU(object_new(typename));
    if (!qdev_realize(DEVICE(cpu), NULL, &err)) {
        error_report_err(err);
        object_unref(OBJECT(cpu));
        exit(EXIT_FAILURE);
    }
    return cpu;
}

/* Resetting the IRQ comes from across the code base so we take the
 * BQL here if we need to.  cpu_interrupt assumes it is held.*/
void cpu_reset_interrupt(CPUState *cpu, int mask)
{
    bool need_lock = !bql_locked();

    if (need_lock) {
        bql_lock();
    }
    cpu->interrupt_request &= ~mask;
    if (need_lock) {
        bql_unlock();
    }
}

void cpu_exit(CPUState *cpu)
{
    qatomic_set(&cpu->exit_request, 1);
    /* Ensure cpu_exec will see the exit request after TCG has exited.  */
    smp_wmb();
    qatomic_set(&cpu->neg.icount_decr.u16.high, -1);
}

static int cpu_common_gdb_read_register(CPUState *cpu, GByteArray *buf, int reg)
{
    return 0;
}

static int cpu_common_gdb_write_register(CPUState *cpu, uint8_t *buf, int reg)
{
    return 0;
}

void cpu_dump_state(CPUState *cpu, FILE *f, int flags)
{
    if (cpu->cc->dump_state) {
        cpu_synchronize_state(cpu);
        cpu->cc->dump_state(cpu, f, flags);
    }
}

void cpu_reset(CPUState *cpu)
{
    device_cold_reset(DEVICE(cpu));

    trace_cpu_reset(cpu->cpu_index);
}

static void cpu_common_reset_hold(Object *obj, ResetType type)
{
    CPUState *cpu = CPU(obj);

    if (qemu_loglevel_mask(CPU_LOG_RESET)) {
        qemu_log("CPU Reset (CPU %d)\n", cpu->cpu_index);
        log_cpu_state(cpu, cpu->cc->reset_dump_flags);
    }

    cpu->interrupt_request = 0;
    cpu->halted = cpu->start_powered_off;
    cpu->mem_io_pc = 0;
    cpu->icount_extra = 0;
    qatomic_set(&cpu->neg.icount_decr.u32, 0);
    cpu->neg.can_do_io = true;
    cpu->exception_index = -1;
    cpu->crash_occurred = false;
    cpu->cflags_next_tb = -1;

    cpu_exec_reset_hold(cpu);
}

ObjectClass *cpu_class_by_name(const char *typename, const char *cpu_model)
{
    ObjectClass *oc;
    CPUClass *cc;

    oc = object_class_by_name(typename);
    cc = CPU_CLASS(oc);
    assert(cc->class_by_name);
    assert(cpu_model);
    oc = cc->class_by_name(cpu_model);
    if (object_class_dynamic_cast(oc, typename) &&
        !object_class_is_abstract(oc)) {
        return oc;
    }

    return NULL;
}

char *cpu_model_from_type(const char *typename)
{
    g_autofree char *suffix = g_strdup_printf("-%s", target_cpu_type());

    if (!object_class_by_name(typename)) {
        return NULL;
    }

    if (g_str_has_suffix(typename, suffix)) {
        return g_strndup(typename, strlen(typename) - strlen(suffix));
    }

    return g_strdup(typename);
}

static void cpu_common_parse_features(const char *typename, char *features,
                                      Error **errp)
{
    char *val;
    static bool cpu_globals_initialized;
    /* Single "key=value" string being parsed */
    char *featurestr = features ? strtok(features, ",") : NULL;

    /* should be called only once, catch invalid users */
    assert(!cpu_globals_initialized);
    cpu_globals_initialized = true;

    while (featurestr) {
        val = strchr(featurestr, '=');
        if (val) {
            GlobalProperty *prop = g_new0(typeof(*prop), 1);
            *val = 0;
            val++;
            prop->driver = typename;
            prop->property = g_strdup(featurestr);
            prop->value = g_strdup(val);
            qdev_prop_register_global(prop);
        } else {
            error_setg(errp, "Expected key=value format, found %s.",
                       featurestr);
            return;
        }
        featurestr = strtok(NULL, ",");
    }
}

const char *parse_cpu_option(const char *cpu_option)
{
    ObjectClass *oc;
    CPUClass *cc;
    gchar **model_pieces;
    const char *cpu_type;

    model_pieces = g_strsplit(cpu_option, ",", 2);
    if (!model_pieces[0]) {
        error_report("-cpu option cannot be empty");
        exit(1);
    }

    oc = cpu_class_by_name(target_cpu_type(), model_pieces[0]);
    if (oc == NULL) {
        error_report("unable to find CPU model '%s'", model_pieces[0]);
        g_strfreev(model_pieces);
        exit(EXIT_FAILURE);
    }

    cpu_type = object_class_get_name(oc);
    cc = CPU_CLASS(oc);
    cc->parse_features(cpu_type, model_pieces[1], &error_fatal);
    g_strfreev(model_pieces);
    return cpu_type;
}

bool cpu_exec_realizefn(CPUState *cpu, Error **errp)
{
    if (!accel_cpu_common_realize(cpu, errp)) {
        return false;
    }

    gdb_init_cpu(cpu);

    /* Wait until cpu initialization complete before exposing cpu. */
    cpu_list_add(cpu);

    cpu_vmstate_register(cpu);

    return true;
}

static void cpu_common_realizefn(DeviceState *dev, Error **errp)
{
    CPUState *cpu = CPU(dev);
    Object *machine = qdev_get_machine();

    /* qdev_get_machine() can return something that's not TYPE_MACHINE
     * if this is one of the user-only emulators; in that case there's
     * no need to check the ignore_memory_transaction_failures board flag.
     */
    if (object_dynamic_cast(machine, TYPE_MACHINE)) {
        MachineClass *mc = MACHINE_GET_CLASS(machine);

        if (mc) {
            cpu->ignore_memory_transaction_failures =
                mc->ignore_memory_transaction_failures;
        }
    }

    if (dev->hotplugged) {
        cpu_synchronize_post_init(cpu);
        cpu_resume(cpu);
    }

    /* NOTE: latest generic point where the cpu is fully realized */
}

static void cpu_common_unrealizefn(DeviceState *dev)
{
    CPUState *cpu = CPU(dev);

    /* Call the plugin hook before clearing the cpu is fully unrealized */
#ifdef CONFIG_PLUGIN
    if (tcg_enabled()) {
        qemu_plugin_vcpu_exit_hook(cpu);
    }
#endif

    /* NOTE: latest generic point before the cpu is fully unrealized */
    cpu_exec_unrealizefn(cpu);
}

void cpu_exec_unrealizefn(CPUState *cpu)
{
    cpu_vmstate_unregister(cpu);

    cpu_list_remove(cpu);
    /*
     * Now that the vCPU has been removed from the RCU list, we can call
     * accel_cpu_common_unrealize, which may free fields using call_rcu.
     */
    accel_cpu_common_unrealize(cpu);
}

static void cpu_common_initfn(Object *obj)
{
    CPUState *cpu = CPU(obj);

    cpu_exec_class_post_init(CPU_GET_CLASS(obj));

    /* cache the cpu class for the hotpath */
    cpu->cc = CPU_GET_CLASS(cpu);

    cpu->cpu_index = UNASSIGNED_CPU_INDEX;
    cpu->cluster_index = UNASSIGNED_CLUSTER_INDEX;
    cpu->as = NULL;
    cpu->num_ases = 0;
    /* user-mode doesn't have configurable SMP topology */
    /* the default value is changed by qemu_init_vcpu() for system-mode */
    cpu->nr_threads = 1;

    /* allocate storage for thread info, initialise condition variables */
    cpu->thread = g_new0(QemuThread, 1);
    cpu->halt_cond = g_new0(QemuCond, 1);
    qemu_cond_init(cpu->halt_cond);

    qemu_mutex_init(&cpu->work_mutex);
    qemu_lockcnt_init(&cpu->in_ioctl_lock);
    QSIMPLEQ_INIT(&cpu->work_list);
    QTAILQ_INIT(&cpu->breakpoints);
    QTAILQ_INIT(&cpu->watchpoints);

    cpu_exec_initfn(cpu);

    /*
     * Plugin initialization must wait until the cpu start executing
     * code, but we must queue this work before the threads are
     * created to ensure we don't race.
     */
#ifdef CONFIG_PLUGIN
    if (tcg_enabled()) {
        cpu->plugin_state = qemu_plugin_create_vcpu_state();
        qemu_plugin_vcpu_init_hook(cpu);
    }
#endif
}

static void cpu_common_finalize(Object *obj)
{
    CPUState *cpu = CPU(obj);

#ifdef CONFIG_PLUGIN
    if (tcg_enabled()) {
        g_free(cpu->plugin_state);
    }
#endif
    free_queued_cpu_work(cpu);
    /* If cleanup didn't happen in context to gdb_unregister_coprocessor_all */
    if (cpu->gdb_regs) {
        g_array_free(cpu->gdb_regs, TRUE);
    }
    qemu_lockcnt_destroy(&cpu->in_ioctl_lock);
    qemu_mutex_destroy(&cpu->work_mutex);
    qemu_cond_destroy(cpu->halt_cond);
    g_free(cpu->halt_cond);
    g_free(cpu->thread);
}

static int64_t cpu_common_get_arch_id(CPUState *cpu)
{
    return cpu->cpu_index;
}

static void cpu_common_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);
    CPUClass *k = CPU_CLASS(klass);

    k->parse_features = cpu_common_parse_features;
    k->get_arch_id = cpu_common_get_arch_id;
    k->gdb_read_register = cpu_common_gdb_read_register;
    k->gdb_write_register = cpu_common_gdb_write_register;
    set_bit(DEVICE_CATEGORY_CPU, dc->categories);
    dc->realize = cpu_common_realizefn;
    dc->unrealize = cpu_common_unrealizefn;
    rc->phases.hold = cpu_common_reset_hold;
    cpu_class_init_props(dc);
    /*
     * Reason: CPUs still need special care by board code: wiring up
     * IRQs, adding reset handlers, halting non-first CPUs, ...
     */
    dc->user_creatable = false;
}

static const TypeInfo cpu_type_info = {
    .name = TYPE_CPU,
    .parent = TYPE_DEVICE,
    .instance_size = sizeof(CPUState),
    .instance_init = cpu_common_initfn,
    .instance_finalize = cpu_common_finalize,
    .abstract = true,
    .class_size = sizeof(CPUClass),
    .class_init = cpu_common_class_init,
};

static void cpu_register_types(void)
{
    type_register_static(&cpu_type_info);
}

type_init(cpu_register_types)

static void cpu_list_entry(gpointer data, gpointer user_data)
{
    CPUClass *cc = CPU_CLASS(OBJECT_CLASS(data));
    const char *typename = object_class_get_name(OBJECT_CLASS(data));
    g_autofree char *model = cpu_model_from_type(typename);

    if (cc->deprecation_note) {
        qemu_printf("  %s (deprecated)\n", model);
    } else {
        qemu_printf("  %s\n", model);
    }
}

void list_cpus(void)
{
    CPUClass *cc = CPU_CLASS(object_class_by_name(target_cpu_type()));

    if (cc->list_cpus) {
        cc->list_cpus();
    } else {
        GSList *list;

        list = object_class_get_list_sorted(TYPE_CPU, false);
        qemu_printf("Available CPUs:\n");
        g_slist_foreach(list, cpu_list_entry, NULL);
        g_slist_free(list);
    }
}
