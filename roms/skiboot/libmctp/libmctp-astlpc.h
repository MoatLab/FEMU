/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef _LIBMCTP_ASTLPCL_H
#define _LIBMCTP_ASTLPCL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libmctp.h>

#include <stdint.h>

struct mctp_binding_astlpc;

/* todo: Remove enum from public interfaces */
enum mctp_binding_astlpc_kcs_reg {
	MCTP_ASTLPC_KCS_REG_DATA = 0,
	MCTP_ASTLPC_KCS_REG_STATUS = 1,
};

struct mctp_binding_astlpc_ops {
	int (*kcs_read)(void *data, enum mctp_binding_astlpc_kcs_reg reg,
			uint8_t *val);
	int (*kcs_write)(void *data, enum mctp_binding_astlpc_kcs_reg reg,
			 uint8_t val);
	int (*lpc_read)(void *data, void *buf, long offset, size_t len);
	int (*lpc_write)(void *data, const void *buf, long offset, size_t len);
};

#define MCTP_BINDING_ASTLPC_MODE_BMC  0
#define MCTP_BINDING_ASTLPC_MODE_HOST 1
struct mctp_binding_astlpc *
mctp_astlpc_init(uint8_t mode, uint32_t mtu, void *lpc_map,
		 const struct mctp_binding_astlpc_ops *ops, void *ops_data);

struct mctp_binding_astlpc *
mctp_astlpc_init_ops(const struct mctp_binding_astlpc_ops *ops, void *ops_data,
		     void *lpc_map);
void mctp_astlpc_destroy(struct mctp_binding_astlpc *astlpc);

struct mctp_binding *mctp_binding_astlpc_core(struct mctp_binding_astlpc *b);

bool mctp_astlpc_tx_done(struct mctp_binding_astlpc *astlpc);
int mctp_astlpc_poll(struct mctp_binding_astlpc *astlpc);

/* fileio-based interface */
struct mctp_binding_astlpc *mctp_astlpc_init_fileio(void);

struct pollfd;
int mctp_astlpc_init_pollfd(struct mctp_binding_astlpc *astlpc,
			    struct pollfd *pollfd);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_ASTLPC_H */
