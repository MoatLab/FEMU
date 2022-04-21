;#######################################################
;#
;# 	Linux Interace Stub
;#
;#######################################################

	INCLUDE 'MakeFunction.s'
	INCLUDE 'LinuxOSIDefs.s'


;#######################################################
; int OSI_IRQTest( int cmd, int param )
;#######################################################

 MakeFunction OSI_IRQTest
	mr	r6,r3
	mr	r7,r4
	osi_call OSI_IRQTEST
	blr


;#######################################################
; void OSI_PutC( char ch )
;#######################################################

 MakeFunction OSI_PutC
 	mr	r6,r3 
	OSI_CALL( OSI_LOG_PUTC )
	blr

;#######################################################
; void OSI_Debugger( int debugnum )
;#######################################################

 MakeFunction OSI_Debugger
	mr	r6,r3
	osi_call OSI_DEBUGGER
	blr

;#######################################################
; ulong OSI_GetTime( void )
;#######################################################

 MakeFunction OSI_GetTime
	osi_call OSI_GET_DATE
	blr

;#######################################################
; void OSI_CMountDrvVol( void )
;#######################################################

 MakeFunction OSI_CMountDrvVol
	osi_call OSI_CMOUNT_DRV_VOL
	blr


;#######################################################
; int OSI_ABlkDiskInfo( int channel, int unit, ablk_disk_info_t *ret )
; int OSI_ABlkRingSetup( int channel, ulong mphys, int num_el )
; int OSI_ABlkCntrl( int channel, int cmd )
; int OSI_ABlkCntrl( int channel, int cmd, int param )
; int OSI_ABlkKick( int channel )
; int OSI_ABlkIRQAck( int channel, int *req_count, int *active, int *event )
; int OSI_ABlkSyncRead( int channel, int unit, int blk, ulong mphys, int size )
; int OSI_ABlkSyncWrite( int channel, int unit, int blk, ulong mphys, int size )
;#######################################################

 MakeFunction OSI_ABlkDiskInfo
	mr	r6,r3
	mr	r7,r4
	mr	r10,r5			; save pointer in r10
	osi_call OSI_ABLK_DISK_INFO
	stw	r4,0(r10)		; 16 byte return info
	stw	r5,4(r10)
	stw	r6,8(r10)
	stw	r7,12(r10)
	blr

 MakeFunction OSI_ABlkRingSetup
	mr	r6,r3
	mr	r7,r4
	mr	r8,r5
	osi_call OSI_ABLK_RING_SETUP
	blr

 MakeFunction OSI_ABlkCntrl
	mr	r6,r3
	mr	r7,r4
	osi_call OSI_ABLK_CNTRL
	blr

 MakeFunction OSI_ABlkCntrl1
	mr	r6,r3
	mr	r7,r4
	mr	r8,r5
	osi_call OSI_ABLK_CNTRL
	blr

 MakeFunction OSI_ABlkKick

	mr	r6,r3
	osi_call OSI_ABLK_KICK
	blr

 MakeFunction OSI_ABlkIRQAck
	mr	r8,r4			; save r4 in r8
	mr	r9,r5			; save r5 in r9
	mr	r10,r6			; save r6 in r10
	mr	r6,r3
	osi_call OSI_ABLK_IRQ_ACK
	stw	r4,0(r8)		; return req_count
	stw	r5,0(r9)		; return active
	stw	r6,0(r10)		; return event
	blr

 MakeFunction OSI_ABlkSyncRead
	mr	r10,r7
	mr	r9,r6
	mr	r8,r5
	mr	r7,r4
	mr	r6,r3
	osi_call OSI_ABLK_SYNC_READ
	blr

 MakeFunction OSI_ABlkSyncWrite
	mr	r10,r7
	mr	r9,r6
	mr	r8,r5
	mr	r7,r4
	mr	r6,r3
	osi_call OSI_ABLK_SYNC_WRITE
	blr
	

;#######################################################
; int OSI_MouseAckIRQ( void )
; int OSI_GetMouse( osi_mouse_t *pb )
; int OSI_MouseCntrl( int cmd )
; int OSI_MouseCntrl1( int cmd, int param )
;#######################################################

 MakeFunction OSI_MouseAckIRQ
	osi_call OSI_MOUSE_ACK_IRQ
	blr

 MakeFunction OSI_GetMouse
	mr	r10,r3
	osi_call OSI_GET_MOUSE
	stw	r4,0(r10)
	stw	r5,4(r10)
	stw	r6,8(r10)
	stw	r7,12(r10)
	stw	r8,16(r10)
	blr

 MakeFunction OSI_MouseCntrl
	mr	r6,r3
	osi_call OSI_MOUSE_CNTRL
	blr

 MakeFunction OSI_MouseCntrl1
	mr	r6,r3
	mr	r7,r4
	osi_call OSI_MOUSE_CNTRL
	blr


;#######################################################
; int OSI_SetVMode_( int modeID, int depthMode )
; int OSI_GetVModeInfo_( int modeID, int depthMode, osi_get_vmode_info_t *ret )
; int OSI_SetVPowerState( int powerState )
; int OSI_GetColor( int index )
; int OSI_SetColor( int index, int color )
; int OSI_VideoAckIRQ( int *events )
; int OSI_VideoCntrl( int cmd )
; int OSI_VideoCntrl1( int cmd, int param )
;#######################################################

 MakeFunction OSI_SetVMode_
	mr r6,r3
	mr r7,r4
	osi_call OSI_SET_VMODE
	blr

 MakeFunction OSI_GetVModeInfo_ 
	mr r6,r3
	mr r7,r4
	mr r10,r5
	osi_call OSI_GET_VMODE_INFO
	stw r4,0(r10)
	stw r5,4(r10)
	stw r6,8(r10)
	stw r7,12(r10)
	stw r8,16(r10)
	stw r9,20(r10)
	blr

 MakeFunction OSI_SetVPowerState
	mr r6,r3
	osi_call OSI_SET_VIDEO_POWER
	blr

 MakeFunction OSI_GetColor
	mr r6,r3
	osi_call OSI_GET_COLOR
	blr

 MakeFunction OSI_SetColor
	mr r6,r3
	mr r7,r4
	osi_call OSI_SET_COLOR
	blr

 MakeFunction OSI_VideoAckIRQ
	mr	r10,r3			; save pointer in r10
	osi_call OSI_VIDEO_ACK_IRQ
	stw	r4,0(r10)		; events return in r4
	blr

 MakeFunction OSI_VideoCntrl
	mr r6,r3
	osi_call OSI_VIDEO_CNTRL
	blr

 MakeFunction OSI_VideoCntrl1
	mr r6,r3
	mr r7,r4
	osi_call OSI_VIDEO_CNTRL
	blr


;#######################################################
; void OSI_EnetClose( UInt32 id )
; UInt32 OSI_EnetOpen( UInt32 interruptNumber )
; UInt32 OSI_EnetGetEthAddress( UInt32 id, UInt32 eth_address_phys_ptr )
; UInt32 OSI_EnetGetStatus( UInt32 id )
; UInt32 OSI_EnetControl1( UInt32 id, UInt32 command, int param ) 
; UInt32 OSI_EnetControl( UInt32 id, UInt32 command ) 
; int OSI_EnetGetPacket( UInt32 id, UInt32 packet )
; int OSI_EnetSendPacket( UInt32 id, UInt32 packet, UInt32 size )
; UInt32 OSI_EnetAddMulticast( UInt32 id, UInt32 eth_address_phys_ptr )
; UInt32 OSI_EnetDelMulticast( UInt32 id, UInt32 eth_address_phys_ptr )
;#######################################################

 MakeFunction OSI_EnetOpen
	mr r6,r3
	osi_call OSI_ENET_OPEN
	blr

 MakeFunction OSI_EnetClose
	mr r6,r3
	osi_call OSI_ENET_CLOSE 
	blr

 MakeFunction OSI_EnetGetEthAddress
	mr r6,r3
	mr r7,r4
	osi_call OSI_ENET_GET_ADDR 
	blr

 MakeFunction OSI_EnetGetStatus
	mr r6,r3
	osi_call OSI_ENET_GET_STATUS 
	blr

 MakeFunction OSI_EnetControl
	mr r6,r3
	mr r7,r4
	osi_call OSI_ENET_CONTROL 
	blr

 MakeFunction OSI_EnetControl1
	mr r6,r3
	mr r7,r4
	mr r8,r5
	osi_call OSI_ENET_CONTROL 
	blr

 MakeFunction OSI_EnetGetPacket
	mr r6,r3
	mr r7,r4
	osi_call OSI_ENET_GET_PACKET 
	blr

 MakeFunction OSI_EnetSendPacket
	mr r6,r3
	mr r7,r4
	mr r8,r5
	osi_call OSI_ENET_SEND_PACKET 
	blr

 MakeFunction OSI_EnetAddMulticast
	mr r6,r3
	mr r7,r4
	osi_call OSI_ENET_ADD_MULTI 
	blr

 MakeFunction OSI_EnetDelMulticast
	mr r6,r3
	mr r7,r4
	osi_call OSI_ENET_DEL_MULTI 
	blr


;#######################################################
; int OSI_SoundWrite( UInt32 phys_buf, int size, int restart )
; int OSI_SoundCntl2( int cmd, int param, int param2 )
; int OSI_SoundCntl1( int cmd, int param )
; int OSI_SoundCntl( int cmd )
; int OSI_SoundSetVolume( int hwVol, int speakerVol, int hwMute )
; int OSI_SoundIrqAck( void )
;#######################################################

 MakeFunction OSI_SoundWrite
	mr	r6,r3
	mr	r7,r4	
	mr	r8,r5
	OSI_CALL( OSI_SOUND_WRITE )
	blr

 MakeFunction OSI_SoundCntl2
	mr	r8,r5
	mr	r7,r4
	mr	r6,r3
	OSI_CALL( OSI_SOUND_CNTL )
	blr

 MakeFunction OSI_SoundCntl1
	mr	r7,r4
	mr	r6,r3
	OSI_CALL( OSI_SOUND_CNTL )
	blr

 MakeFunction OSI_SoundCntl
	mr	r6,r3
	OSI_CALL( OSI_SOUND_CNTL )
	blr

 MakeFunction OSI_SoundSetVolume
	mr	r6,r3
	mr	r7,r4
	mr	r8,r5
	OSI_CALL( OSI_SOUND_SET_VOLUME )
	blr
	
 MakeFunction OSI_SoundIrqAck
	OSI_CALL( OSI_SOUND_IRQ_ACK )
	blr


;#######################################################
; int OSI_SCSIControl( int sel, int param )
; int OSI_SCSISubmit( int req_mphys )
; int OSI_SCSIAck( void )
;#######################################################

 MakeFunction OSI_SCSIControl
	mr	r7,r4
	mr	r6,r3
	OSI_CALL( OSI_SCSI_CNTRL )
	blr
	
 MakeFunction OSI_SCSISubmit
	mr	r6,r3
	OSI_CALL( OSI_SCSI_SUBMIT )
	blr

 MakeFunction OSI_SCSIAck
	OSI_CALL( OSI_SCSI_ACK )
	blr
