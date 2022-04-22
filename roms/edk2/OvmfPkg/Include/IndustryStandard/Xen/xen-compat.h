/******************************************************************************
 * xen-compat.h
 *
 * Guest OS interface to Xen.  Compatibility layer.
 *
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2006, Christian Limpach
 */

#ifndef __XEN_PUBLIC_XEN_COMPAT_H__
#define __XEN_PUBLIC_XEN_COMPAT_H__

#define __XEN_LATEST_INTERFACE_VERSION__  0x00040400

#if defined (__XEN__) || defined (__XEN_TOOLS__)
/* Xen is built with matching headers and implements the latest interface. */
#define __XEN_INTERFACE_VERSION__  __XEN_LATEST_INTERFACE_VERSION__
#elif !defined (__XEN_INTERFACE_VERSION__)
/* Guests which do not specify a version get the legacy interface. */
#define __XEN_INTERFACE_VERSION__  0x00000000
#endif

#if __XEN_INTERFACE_VERSION__ > __XEN_LATEST_INTERFACE_VERSION__
  #error "These header files do not support the requested interface version."
#endif

#endif /* __XEN_PUBLIC_XEN_COMPAT_H__ */
