/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef _LIBMCTP_SERIAL_H
#define _LIBMCTP_SERIAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libmctp.h>

struct mctp_binding_serial;

struct mctp_binding_serial *mctp_serial_init(void);
void mctp_serial_destroy(struct mctp_binding_serial *serial);

struct mctp_binding *mctp_binding_serial_core(struct mctp_binding_serial *b);

/* file-based IO */
struct pollfd;
int mctp_serial_init_pollfd(struct mctp_binding_serial *serial,
			    struct pollfd *pollfd);

int mctp_serial_read(struct mctp_binding_serial *serial);
int mctp_serial_open_path(struct mctp_binding_serial *serial, const char *path);
void mctp_serial_open_fd(struct mctp_binding_serial *serial, int fd);

/* direct function call IO */
typedef int (*mctp_serial_tx_fn)(void *data, void *buf, size_t len)
	__attribute__((warn_unused_result));
void mctp_serial_set_tx_fn(struct mctp_binding_serial *serial,
			   mctp_serial_tx_fn fn, void *data);
int mctp_serial_rx(struct mctp_binding_serial *serial, const void *buf,
		   size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_SERIAL_H */
