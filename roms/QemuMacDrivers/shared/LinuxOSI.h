/* 
 *	<LinuxOSI.h>
 *
 *   Copyright (C) 1999, 2002, 2003 Samuel Rydh (samuel@ibrium.se)
 *   
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *   
 */

#ifndef _LINUX_OSI_H
#define _LINUX_OSI_H

#include <Types.h>

#define		MOL_GESTALT_SELECTOR	'MOL-'
//#define	MOL_GESTALT_VALUE	'-MOL'	/* old value, osi_interrupts used */
#define		MOL_GESTALT_VALUE	'1MOL'

extern int	OSI_IRQTest( int cmd, int param );

/* Misc */
extern int	MOLIsRunning( void );
extern void 	OSI_Debugger( int debugnum );

extern UInt32 	OSI_GetTime( void );
extern void	OSI_PutC( char ch );
extern void	OSI_CMountDrvVol( void );

/* Mouse Driver */
struct osi_mouse;
extern int	OSI_GetMouse( struct osi_mouse *pb );
extern int	OSI_MouseCntrl( int cmd );
extern int	OSI_MouseCntrl1( int cmd, int param );
extern int	OSI_MouseAckIRQ( void );

/* Video Driver */
extern int 	OSI_SetVMode_( int modeID, int depthMode );
extern int 	OSI_GetVModeInfo_( int modeID, int depthMode, void *ret );
extern int 	OSI_SetVPowerState( int powerState );

extern int	OSI_GetColor( int index );
extern int	OSI_SetColor( int index, int col );
extern int	OSI_VideoAckIRQ( int *events );
extern int	OSI_VideoCntrl( int cmd );
extern int	OSI_VideoCntrl1( int cmd, int param );

/* Ethernet Driver */
extern int	OSI_EnetOpen( UInt32 osi_id );
extern void	OSI_EnetClose( UInt32 id );
extern UInt32 	OSI_EnetGetEthAddress( UInt32 id, UInt32 eth_address_phys_ptr );
extern UInt32 	OSI_EnetGetStatus( UInt32 id );
extern UInt32 	OSI_EnetControl( UInt32 id, UInt32 command );
extern UInt32 	OSI_EnetControl1( UInt32 id, UInt32 command, UInt32 param );
extern int 	OSI_EnetGetPacket( UInt32 id, UInt32 packet );
extern int 	OSI_EnetSendPacket( UInt32 id, UInt32 packet, UInt32 size );
extern UInt32 	OSI_EnetAddMulticast( UInt32 id, UInt32 eth_address_phys_ptr );
extern UInt32 	OSI_EnetDelMulticast( UInt32 id, UInt32 eth_address_phys_ptr );

/* Sound Driver */
extern int	OSI_SoundWrite( UInt32 phys_buf, int count, int resume );
extern long	OSI_SoundSetVolume( long hwVol, long speakerVol, int hwMute );
extern int 	OSI_SoundIrqAck( void );
extern int	OSI_SoundCntl2( int cmd, int parm, int param2 );
extern int	OSI_SoundCntl1( int cmd, int parm );
extern int	OSI_SoundCntl( int cmd );

/* Interrupt management */
extern UInt32	OSI_RegisterIRQ( UInt32 reg_word, UInt32 appl_int );
extern void	OSI_UnregisterIRQ( UInt32 irq_cookie );
extern int	OSI_PollIRQ( UInt32 irq_cookie );
extern int	OSI_AckIRQ( UInt32 irq_cookie );
extern int	OSI_EnableIRQ( UInt32 irq_cookie, int enable );

/* ABlk driver */
struct ablk_disk_info;
extern int	OSI_ABlkRingSetup( int channel, UInt32 mphys, int nel );
extern int	OSI_ABlkDiskInfo( int channel, int index, struct ablk_disk_info *info );
extern int	OSI_ABlkIRQAck( int channel, int *req_cnt, int *active, int *events );
extern int	OSI_ABlkCntrl( int channel, int cmd );
extern int	OSI_ABlkCntrl1( int channel, int cmd, int arg );
extern int	OSI_ABlkKick( int channel );
extern int	OSI_ABlkSyncRead( int channel, int unit, int blk, UInt32 physbuf, int size );
extern int	OSI_ABlkSyncWrite( int channel, int unit, int blk, UInt32 physbuf, int size );

/* SCSI */
extern int	OSI_SCSISubmit( int req_mphys );
extern int	OSI_SCSIAck( void );
extern int	OSI_SCSIControl( int cmd, int param );

#endif
