#ifndef __FEMU_BBSSD_FTL_INTERNAL_H
#define __FEMU_BBSSD_FTL_INTERNAL_H

#include "ftl.h"

/* geometry setup (hw/femu/bbssd/ftl-geom.c) */
void ssd_init_params(struct ssdparams *spp, FemuCtrl *n);
void ssd_init_ch(struct ssd_channel *ch, struct ssdparams *spp);

#endif /* __FEMU_BBSSD_FTL_INTERNAL_H */
