;
; Linux interface magic
;

OSI_SC_MAGIC_R3:	set	0x113724FA
OSI_SC_MAGIC_R4:	set	0x77810F9B

	MACRO
	osi_call &selector
		li	r3,0x24FA
		addis	r3,r3,0x1137
		li	r4,0x0F9B
		addis	r4,r4,0x7781
		li	r5,&selector
		sc
	ENDM

;
; Selectors
;

OSI_DEBUGGER			set 	1
OSI_CMOUNT_DRV_VOL		set	4
	
OSI_MOUSE_CNTRL			set	8
OSI_GET_DATE			set	9

OSI_ENET_OPEN			set	10
OSI_ENET_CLOSE			set	11
OSI_ENET_GET_ADDR		set	12
OSI_ENET_GET_STATUS		set	13
OSI_ENET_CONTROL		set	14
OSI_ENET_ADD_MULTI		set	16
OSI_ENET_DEL_MULTI		set	17
OSI_ENET_GET_PACKET		set	18
OSI_ENET_SEND_PACKET		set	19

OSI_SCSI_CNTRL			set	23
OSI_SCSI_SUBMIT			set	24
OSI_SCSI_ACK			set	25

OSI_GET_MOUSE			set	26	; void -- r4-r7 mouse data, r3 status
OSI_MOUSE_ACK_IRQ		set	27

OSI_SET_VMODE			set	28	; vmode, depthmode -- err
OSI_GET_VMODE_INFO		set	29	; int modeID -- r3-status, r4-r7 osi_get_next_vmode_t
OSI_GET_MOUSE_DPI		set	30	; -- mouse dpi

OSI_SET_VIDEO_POWER		set	31	; set VESA DPMS (Energy Star) state on console-video

OSI_SOUND_WRITE			set	33 
OSI_SOUND_SET_VOLUME		set	35
OSI_SOUND_CNTL			set	36

OSI_VIDEO_ACK_IRQ		set	38
OSI_VIDEO_CNTRL			set	39

OSI_SOUND_IRQ_ACK		set	40
OSI_SOUND_START_STOP		set	41

OSI_REGISTER_IRQ		set	42	; first_word_of_reg_property -- irq_cookie

OSI_LOG_PUTC			set	47

OSI_SET_COLOR			set	59
OSI_GET_COLOR			set	64

OSI_IRQTEST			set	65
	
OSI_ABLK_RING_SETUP		set	79
OSI_ABLK_CNTRL			set	80
OSI_ABLK_DISK_INFO		set	81
OSI_ABLK_KICK			set	82
OSI_ABLK_IRQ_ACK		set	83
OSI_ABLK_SYNC_READ		set	84
OSI_ABLK_SYNC_WRITE		set	85
