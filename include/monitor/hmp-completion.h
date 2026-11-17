/*
 * Human Monitor Completion handlers
 *
 * Copyright IBM, Corp. 2011
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HMP_COMPLETION_H
#define HMP_COMPLETION_H

#include "qemu/readline.h"

void object_add_completion(ReadLineState *rs, int nb_args, const char *str);
void object_del_completion(ReadLineState *rs, int nb_args, const char *str);
void device_add_completion(ReadLineState *rs, int nb_args, const char *str);
void device_del_completion(ReadLineState *rs, int nb_args, const char *str);
void sendkey_completion(ReadLineState *rs, int nb_args, const char *str);
void chardev_remove_completion(ReadLineState *rs, int nb_args, const char *str);
void chardev_add_completion(ReadLineState *rs, int nb_args, const char *str);
void set_link_completion(ReadLineState *rs, int nb_args, const char *str);
void netdev_add_completion(ReadLineState *rs, int nb_args, const char *str);
void netdev_del_completion(ReadLineState *rs, int nb_args, const char *str);
void ringbuf_write_completion(ReadLineState *rs, int nb_args, const char *str);
void info_trace_events_completion(ReadLineState *rs, int nb_args,
                                  const char *str);
void trace_event_completion(ReadLineState *rs, int nb_args, const char *str);
void watchdog_action_completion(ReadLineState *rs, int nb_args,
                                const char *str);
void migrate_set_capability_completion(ReadLineState *rs, int nb_args,
                                       const char *str);
void migrate_set_parameter_completion(ReadLineState *rs, int nb_args,
                                      const char *str);
void delvm_completion(ReadLineState *rs, int nb_args, const char *str);
void loadvm_completion(ReadLineState *rs, int nb_args, const char *str);

#endif
