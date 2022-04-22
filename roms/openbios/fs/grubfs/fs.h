/*
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 *	@(#)fs.h	7.7 (Berkeley) 5/9/89
 */

/*
 * Each disk drive contains some number of file systems.
 * A file system consists of a number of cylinder groups.
 * Each cylinder group has inodes and data.
 *
 * A file system is described by its super-block, which in turn
 * describes the cylinder groups.  The super-block is critical
 * data and is replicated in each cylinder group to protect against
 * catastrophic loss.  This is done at `newfs' time and the critical
 * super-block data does not change, so the copies need not be
 * referenced further unless disaster strikes.
 *
 * For file system fs, the offsets of the various blocks of interest
 * are given in the super block as:
 *	[fs->fs_sblkno]		Super-block
 *	[fs->fs_cblkno]		Cylinder group block
 *	[fs->fs_iblkno]		Inode blocks
 *	[fs->fs_dblkno]		Data blocks
 * The beginning of cylinder group cg in fs, is given by
 * the ``cgbase(fs, cg)'' macro.
 *
 * The first boot and super blocks are given in absolute disk addresses.
 * The byte-offset forms are preferred, as they don't imply a sector size.
 */
#define BBSIZE		8192
#define SBSIZE		8192
#define	BBOFF		((mach_off_t)(0))
#define	SBOFF		((mach_off_t)(BBOFF + BBSIZE))
#define	BBLOCK		((mach_daddr_t)(0))
#define	SBLOCK		((mach_daddr_t)(BBLOCK + BBSIZE / DEV_BSIZE))

/*
 * Addresses stored in inodes are capable of addressing fragments
 * of `blocks'. File system blocks of at most size MAXBSIZE can
 * be optionally broken into 2, 4, or 8 pieces, each of which is
 * addressible; these pieces may be DEV_BSIZE, or some multiple of
 * a DEV_BSIZE unit.
 *
 * Large files consist of exclusively large data blocks.  To avoid
 * undue wasted disk space, the last data block of a small file may be
 * allocated as only as many fragments of a large block as are
 * necessary.  The file system format retains only a single pointer
 * to such a fragment, which is a piece of a single large block that
 * has been divided.  The size of such a fragment is determinable from
 * information in the inode, using the ``blksize(fs, ip, lbn)'' macro.
 *
 * The file system records space availability at the fragment level;
 * to determine block availability, aligned fragments are examined.
 *
 * The root inode is the root of the file system.
 * Inode 0 can't be used for normal purposes and
 * historically bad blocks were linked to inode 1,
 * thus the root inode is 2. (inode 1 is no longer used for
 * this purpose, however numerous dump tapes make this
 * assumption, so we are stuck with it)
 */
#define	ROOTINO		((mach_ino_t)2)	/* i number of all roots */

/*
 * MINBSIZE is the smallest allowable block size.
 * In order to insure that it is possible to create files of size
 * 2^32 with only two levels of indirection, MINBSIZE is set to 4096.
 * MINBSIZE must be big enough to hold a cylinder group block,
 * thus changes to (struct cg) must keep its size within MINBSIZE.
 * Note that super blocks are always of size SBSIZE,
 * and that both SBSIZE and MAXBSIZE must be >= MINBSIZE.
 */
#define MINBSIZE	4096

/*
 * The path name on which the file system is mounted is maintained
 * in fs_fsmnt. MAXMNTLEN defines the amount of space allocated in
 * the super block for this name.
 * The limit on the amount of summary information per file system
 * is defined by MAXCSBUFS. It is currently parameterized for a
 * maximum of two million cylinders.
 */
#define MAXMNTLEN 512
#define MAXCSBUFS 32

/*
 * Per cylinder group information; summarized in blocks allocated
 * from first cylinder group data blocks.  These blocks have to be
 * read in from fs_csaddr (size fs_cssize) in addition to the
 * super block.
 *
 * N.B. sizeof(struct csum) must be a power of two in order for
 * the ``fs_cs'' macro to work (see below).
 */
struct csum
  {
    int cs_ndir;		/* number of directories */
    int cs_nbfree;		/* number of free blocks */
    int cs_nifree;		/* number of free inodes */
    int cs_nffree;		/* number of free frags */
  };

/*
 * Super block for a file system.
 */
#define	FS_MAGIC	0x011954
struct fs
  {
    int xxx1;			/* struct       fs *fs_link; */
    int xxx2;			/* struct       fs *fs_rlink; */
    mach_daddr_t fs_sblkno;	/* addr of super-block in filesys */
    mach_daddr_t fs_cblkno;	/* offset of cyl-block in filesys */
    mach_daddr_t fs_iblkno;	/* offset of inode-blocks in filesys */
    mach_daddr_t fs_dblkno;	/* offset of first data after cg */
    int fs_cgoffset;		/* cylinder group offset in cylinder */
    int fs_cgmask;		/* used to calc mod fs_ntrak */
    mach_time_t fs_time;	/* last time written */
    int fs_size;		/* number of blocks in fs */
    int fs_dsize;		/* number of data blocks in fs */
    int fs_ncg;			/* number of cylinder groups */
    int fs_bsize;		/* size of basic blocks in fs */
    int fs_fsize;		/* size of frag blocks in fs */
    int fs_frag;		/* number of frags in a block in fs */
/* these are configuration parameters */
    int fs_minfree;		/* minimum percentage of free blocks */
    int fs_rotdelay;		/* num of ms for optimal next block */
    int fs_rps;			/* disk revolutions per second */
/* these fields can be computed from the others */
    int fs_bmask;		/* ``blkoff'' calc of blk offsets */
    int fs_fmask;		/* ``fragoff'' calc of frag offsets */
    int fs_bshift;		/* ``lblkno'' calc of logical blkno */
    int fs_fshift;		/* ``numfrags'' calc number of frags */
/* these are configuration parameters */
    int fs_maxcontig;		/* max number of contiguous blks */
    int fs_maxbpg;		/* max number of blks per cyl group */
/* these fields can be computed from the others */
    int fs_fragshift;		/* block to frag shift */
    int fs_fsbtodb;		/* fsbtodb and dbtofsb shift constant */
    int fs_sbsize;		/* actual size of super block */
    int fs_csmask;		/* csum block offset */
    int fs_csshift;		/* csum block number */
    int fs_nindir;		/* value of NINDIR */
    int fs_inopb;		/* value of INOPB */
    int fs_nspf;		/* value of NSPF */
/* yet another configuration parameter */
    int fs_optim;		/* optimization preference, see below */
/* these fields are derived from the hardware */
    int fs_npsect;		/* # sectors/track including spares */
    int fs_interleave;		/* hardware sector interleave */
    int fs_trackskew;		/* sector 0 skew, per track */
    int fs_headswitch;		/* head switch time, usec */
    int fs_trkseek;		/* track-to-track seek, usec */
/* sizes determined by number of cylinder groups and their sizes */
    mach_daddr_t fs_csaddr;	/* blk addr of cyl grp summary area */
    int fs_cssize;		/* size of cyl grp summary area */
    int fs_cgsize;		/* cylinder group size */
/* these fields are derived from the hardware */
    int fs_ntrak;		/* tracks per cylinder */
    int fs_nsect;		/* sectors per track */
    int fs_spc;			/* sectors per cylinder */
/* this comes from the disk driver partitioning */
    int fs_ncyl;		/* cylinders in file system */
/* these fields can be computed from the others */
    int fs_cpg;			/* cylinders per group */
    int fs_ipg;			/* inodes per group */
    int fs_fpg;			/* blocks per group * fs_frag */
/* this data must be re-computed after crashes */
    struct csum fs_cstotal;	/* cylinder summary information */
/* these fields are cleared at mount time */
    char fs_fmod;		/* super block modified flag */
    char fs_clean;		/* file system is clean flag */
    char fs_ronly;		/* mounted read-only flag */
    char fs_flags;		/* currently unused flag */
    char fs_fsmnt[MAXMNTLEN];	/* name mounted on */
/* these fields retain the current block allocation info */
    int fs_cgrotor;		/* last cg searched */
#if 1
    int was_fs_csp[MAXCSBUFS];
#else
    struct csum *fs_csp[MAXCSBUFS];	/* list of fs_cs info buffers */
#endif
    int fs_cpc;			/* cyl per cycle in postbl */
    short fs_opostbl[16][8];	/* old rotation block list head */
    long fs_sparecon[50];	/* reserved for future constants */
    long fs_contigsumsize;	/* size of cluster summary array */
    long fs_maxsymlinklen;	/* max length of an internal symlink */
    long fs_inodefmt;		/* format of on-disk inodes */
    quad fs_maxfilesize;	/* maximum representable file size */
    quad fs_qbmask;		/* ~fs_bmask - for use with quad size */
    quad fs_qfmask;		/* ~fs_fmask - for use with quad size */
    long fs_state;		/* validate fs_clean field */
    int fs_postblformat;	/* format of positional layout tables */
    int fs_nrpos;		/* number of rotaional positions */
    int fs_postbloff;		/* (short) rotation block list head */
    int fs_rotbloff;		/* (char) blocks for each rotation */
    int fs_magic;		/* magic number */
    unsigned char fs_space[1];	/* list of blocks for each rotation */
/* actually longer */
  };
/*
 * Preference for optimization.
 */
#define FS_OPTTIME	0	/* minimize allocation time */
#define FS_OPTSPACE	1	/* minimize disk fragmentation */

/*
 * Rotational layout table format types
 */
#define FS_42POSTBLFMT		-1	/* 4.2BSD rotational table format */
#define FS_DYNAMICPOSTBLFMT	1	/* dynamic rotational table format */
/*
 * Macros for access to superblock array structures
 */
#define fs_postbl(fs, cylno) \
    (((fs)->fs_postblformat == FS_42POSTBLFMT) \
    ? ((fs)->fs_opostbl[cylno]) \
    : ((short *)((char *)(fs) + (fs)->fs_postbloff) + (cylno) * (fs)->fs_nrpos))
#define fs_rotbl(fs) \
    (((fs)->fs_postblformat == FS_42POSTBLFMT) \
    ? ((fs)->fs_space) \
    : ((unsigned char *)((char *)(fs) + (fs)->fs_rotbloff)))

/*
 * Convert cylinder group to base address of its global summary info.
 *
 * N.B. This macro assumes that sizeof(struct csum) is a power of two.
 */
#define fs_cs(fs, indx) \
	fs_csp[(indx) >> (fs)->fs_csshift][(indx) & ~(fs)->fs_csmask]

/*
 * Cylinder group block for a file system.
 */
#define	CG_MAGIC	0x090255
struct cg
  {
    int xxx1;			/* struct       cg *cg_link; */
    int cg_magic;		/* magic number */
    mach_time_t cg_time;		/* time last written */
    int cg_cgx;			/* we are the cgx'th cylinder group */
    short cg_ncyl;		/* number of cyl's this cg */
    short cg_niblk;		/* number of inode blocks this cg */
    int cg_ndblk;		/* number of data blocks this cg */
    struct csum cg_cs;		/* cylinder summary information */
    int cg_rotor;		/* position of last used block */
    int cg_frotor;		/* position of last used frag */
    int cg_irotor;		/* position of last used inode */
    int cg_frsum[MAXFRAG];	/* counts of available frags */
    int cg_btotoff;		/* (long) block totals per cylinder */
    int cg_boff;		/* (short) free block positions */
    int cg_iusedoff;		/* (char) used inode map */
    int cg_freeoff;		/* (char) free block map */
    int cg_nextfreeoff;		/* (char) next available space */
    int cg_sparecon[16];	/* reserved for future use */
    unsigned char cg_space[1];	       /* space for cylinder group maps */
/* actually longer */
  };
/*
 * Macros for access to cylinder group array structures
 */
#define cg_blktot(cgp) \
    (((cgp)->cg_magic != CG_MAGIC) \
    ? (((struct ocg *)(cgp))->cg_btot) \
    : ((int *)((char *)(cgp) + (cgp)->cg_btotoff)))
#define cg_blks(fs, cgp, cylno) \
    (((cgp)->cg_magic != CG_MAGIC) \
    ? (((struct ocg *)(cgp))->cg_b[cylno]) \
    : ((short *)((char *)(cgp) + (cgp)->cg_boff) + (cylno) * (fs)->fs_nrpos))
#define cg_inosused(cgp) \
    (((cgp)->cg_magic != CG_MAGIC) \
    ? (((struct ocg *)(cgp))->cg_iused) \
    : ((char *)((char *)(cgp) + (cgp)->cg_iusedoff)))
#define cg_blksfree(cgp) \
    (((cgp)->cg_magic != CG_MAGIC) \
    ? (((struct ocg *)(cgp))->cg_free) \
    : ((unsigned char *)((char *)(cgp) + (cgp)->cg_freeoff)))
#define cg_chkmagic(cgp) \
    ((cgp)->cg_magic == CG_MAGIC || ((struct ocg *)(cgp))->cg_magic == CG_MAGIC)

/*
 * The following structure is defined
 * for compatibility with old file systems.
 */
struct ocg
  {
    int xxx1;			/* struct       ocg *cg_link; */
    int xxx2;			/* struct       ocg *cg_rlink; */
    mach_time_t cg_time;	/* time last written */
    int cg_cgx;			/* we are the cgx'th cylinder group */
    short cg_ncyl;		/* number of cyl's this cg */
    short cg_niblk;		/* number of inode blocks this cg */
    int cg_ndblk;		/* number of data blocks this cg */
    struct csum cg_cs;		/* cylinder summary information */
    int cg_rotor;		/* position of last used block */
    int cg_frotor;		/* position of last used frag */
    int cg_irotor;		/* position of last used inode */
    int cg_frsum[8];		/* counts of available frags */
    int cg_btot[32];		/* block totals per cylinder */
    short cg_b[32][8];		/* positions of free blocks */
    char cg_iused[256];		/* used inode map */
    int cg_magic;		/* magic number */
    unsigned char cg_free[1];	/* free block map */
/* actually longer */
  };

/*
 * Turn file system block numbers into disk block addresses.
 * This maps file system blocks to device size blocks.
 */
#define fsbtodb(fs, b)	((b) << (fs)->fs_fsbtodb)
#define	dbtofsb(fs, b)	((b) >> (fs)->fs_fsbtodb)

/*
 * Cylinder group macros to locate things in cylinder groups.
 * They calc file system addresses of cylinder group data structures.
 */
#define	cgbase(fs, c)	((mach_daddr_t)((fs)->fs_fpg * (c)))
#define cgstart(fs, c) \
	(cgbase(fs, c) + (fs)->fs_cgoffset * ((c) & ~((fs)->fs_cgmask)))
#define	cgsblock(fs, c)	(cgstart(fs, c) + (fs)->fs_sblkno)	/* super blk */
#define	cgtod(fs, c)	(cgstart(fs, c) + (fs)->fs_cblkno)	/* cg block */
#define	cgimin(fs, c)	(cgstart(fs, c) + (fs)->fs_iblkno)	/* inode blk */
#define	cgdmin(fs, c)	(cgstart(fs, c) + (fs)->fs_dblkno)	/* 1st data */

/*
 * Macros for handling inode numbers:
 *     inode number to file system block offset.
 *     inode number to cylinder group number.
 *     inode number to file system block address.
 */
#define	itoo(fs, x)	((x) % INOPB(fs))
#define	itog(fs, x)	((x) / (fs)->fs_ipg)
#define	itod(fs, x) \
	((mach_daddr_t)(cgimin(fs, itog(fs, x)) + \
	(blkstofrags((fs), (((x) % (fs)->fs_ipg) / INOPB(fs))))))

/*
 * Give cylinder group number for a file system block.
 * Give cylinder group block number for a file system block.
 */
#define	dtog(fs, d)	((d) / (fs)->fs_fpg)
#define	dtogd(fs, d)	((d) % (fs)->fs_fpg)

/*
 * Extract the bits for a block from a map.
 * Compute the cylinder and rotational position of a cyl block addr.
 */
#define blkmap(fs, map, loc) \
    (((map)[(loc) / NBBY] >> ((loc) % NBBY)) & (0xff >> (NBBY - (fs)->fs_frag)))
#define cbtocylno(fs, bno) \
    ((bno) * NSPF(fs) / (fs)->fs_spc)
#define cbtorpos(fs, bno) \
    (((bno) * NSPF(fs) % (fs)->fs_spc / (fs)->fs_nsect * (fs)->fs_trackskew + \
     (bno) * NSPF(fs) % (fs)->fs_spc % (fs)->fs_nsect * (fs)->fs_interleave) % \
     (fs)->fs_nsect * (fs)->fs_nrpos / (fs)->fs_npsect)

/*
 * The following macros optimize certain frequently calculated
 * quantities by using shifts and masks in place of divisions
 * modulos and multiplications.
 */
#define blkoff(fs, loc)		/* calculates (loc % fs->fs_bsize) */ \
	((loc) & ~(fs)->fs_bmask)
#define fragoff(fs, loc)	/* calculates (loc % fs->fs_fsize) */ \
	((loc) & ~(fs)->fs_fmask)
#define lblkno(fs, loc)		/* calculates (loc / fs->fs_bsize) */ \
	((loc) >> (fs)->fs_bshift)
#define numfrags(fs, loc)	/* calculates (loc / fs->fs_fsize) */ \
	((loc) >> (fs)->fs_fshift)
#define blkroundup(fs, size)	/* calculates roundup(size, fs->fs_bsize) */ \
	(((size) + (fs)->fs_bsize - 1) & (fs)->fs_bmask)
#define fragroundup(fs, size)	/* calculates roundup(size, fs->fs_fsize) */ \
	(((size) + (fs)->fs_fsize - 1) & (fs)->fs_fmask)
#define fragstoblks(fs, frags)	/* calculates (frags / fs->fs_frag) */ \
	((frags) >> (fs)->fs_fragshift)
#define blkstofrags(fs, blks)	/* calculates (blks * fs->fs_frag) */ \
	((blks) << (fs)->fs_fragshift)
#define fragnum(fs, fsb)	/* calculates (fsb % fs->fs_frag) */ \
	((fsb) & ((fs)->fs_frag - 1))
#define blknum(fs, fsb)		/* calculates rounddown(fsb, fs->fs_frag) */ \
	((fsb) &~ ((fs)->fs_frag - 1))

/*
 * Determine the number of available frags given a
 * percentage to hold in reserve
 */
#define freespace(fs, percentreserved) \
	(blkstofrags((fs), (fs)->fs_cstotal.cs_nbfree) + \
	(fs)->fs_cstotal.cs_nffree - ((fs)->fs_dsize * (percentreserved) / 100))

/*
 * Determining the size of a file block in the file system.
 */
#define blksize(fs, ip, lbn) \
	(((lbn) >= NDADDR || (ip)->i_size >= ((lbn) + 1) << (fs)->fs_bshift) \
	    ? (fs)->fs_bsize \
	    : (fragroundup(fs, blkoff(fs, (ip)->i_size))))
#define dblksize(fs, dip, lbn) \
	(((lbn) >= NDADDR || (dip)->di_size >= ((lbn) + 1) << (fs)->fs_bshift) \
	    ? (fs)->fs_bsize \
	    : (fragroundup(fs, blkoff(fs, (dip)->di_size))))

/*
 * Number of disk sectors per block; assumes DEV_BSIZE byte sector size.
 */
#define	NSPB(fs)	((fs)->fs_nspf << (fs)->fs_fragshift)
#define	NSPF(fs)	((fs)->fs_nspf)

/*
 * INOPB is the number of inodes in a secondary storage block.
 */
#define	INOPB(fs)	((fs)->fs_inopb)
#define	INOPF(fs)	((fs)->fs_inopb >> (fs)->fs_fragshift)

/*
 * NINDIR is the number of indirects in a file system block.
 */
#define	NINDIR(fs)	((fs)->fs_nindir)
