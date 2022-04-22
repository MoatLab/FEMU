// Code for handling XHCI "Super speed" USB controllers.
//
// Copyright (C) 2013  Gerd Hoffmann <kraxel@redhat.com>
// Copyright (C) 2014  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "config.h" // CONFIG_*
#include "malloc.h" // memalign_low
#include "memmap.h" // PAGE_SIZE
#include "output.h" // dprintf
#include "pcidevice.h" // foreachpci
#include "pci_ids.h" // PCI_CLASS_SERIAL_USB_XHCI
#include "pci_regs.h" // PCI_BASE_ADDRESS_0
#include "string.h" // memcpy
#include "usb.h" // struct usb_s
#include "usb-xhci.h" // struct ehci_qh
#include "util.h" // timer_calc
#include "x86.h" // readl

// --------------------------------------------------------------
// configuration

#define XHCI_RING_ITEMS          16
#define XHCI_RING_SIZE           (XHCI_RING_ITEMS*sizeof(struct xhci_trb))

/*
 *  xhci_ring structs are allocated with XHCI_RING_SIZE alignment,
 *  then we can get it from a trb pointer (provided by evt ring).
 */
#define XHCI_RING(_trb)          \
    ((struct xhci_ring*)((u32)(_trb) & ~(XHCI_RING_SIZE-1)))

// --------------------------------------------------------------
// bit definitions

#define XHCI_CMD_RS              (1<<0)
#define XHCI_CMD_HCRST           (1<<1)
#define XHCI_CMD_INTE            (1<<2)
#define XHCI_CMD_HSEE            (1<<3)
#define XHCI_CMD_LHCRST          (1<<7)
#define XHCI_CMD_CSS             (1<<8)
#define XHCI_CMD_CRS             (1<<9)
#define XHCI_CMD_EWE             (1<<10)
#define XHCI_CMD_EU3S            (1<<11)

#define XHCI_STS_HCH             (1<<0)
#define XHCI_STS_HSE             (1<<2)
#define XHCI_STS_EINT            (1<<3)
#define XHCI_STS_PCD             (1<<4)
#define XHCI_STS_SSS             (1<<8)
#define XHCI_STS_RSS             (1<<9)
#define XHCI_STS_SRE             (1<<10)
#define XHCI_STS_CNR             (1<<11)
#define XHCI_STS_HCE             (1<<12)

#define XHCI_PORTSC_CCS          (1<<0)
#define XHCI_PORTSC_PED          (1<<1)
#define XHCI_PORTSC_OCA          (1<<3)
#define XHCI_PORTSC_PR           (1<<4)
#define XHCI_PORTSC_PLS_SHIFT        5
#define XHCI_PORTSC_PLS_MASK     0xf
#define XHCI_PORTSC_PP           (1<<9)
#define XHCI_PORTSC_SPEED_SHIFT      10
#define XHCI_PORTSC_SPEED_MASK   0xf
#define XHCI_PORTSC_SPEED_FULL   (1<<10)
#define XHCI_PORTSC_SPEED_LOW    (2<<10)
#define XHCI_PORTSC_SPEED_HIGH   (3<<10)
#define XHCI_PORTSC_SPEED_SUPER  (4<<10)
#define XHCI_PORTSC_PIC_SHIFT        14
#define XHCI_PORTSC_PIC_MASK     0x3
#define XHCI_PORTSC_LWS          (1<<16)
#define XHCI_PORTSC_CSC          (1<<17)
#define XHCI_PORTSC_PEC          (1<<18)
#define XHCI_PORTSC_WRC          (1<<19)
#define XHCI_PORTSC_OCC          (1<<20)
#define XHCI_PORTSC_PRC          (1<<21)
#define XHCI_PORTSC_PLC          (1<<22)
#define XHCI_PORTSC_CEC          (1<<23)
#define XHCI_PORTSC_CAS          (1<<24)
#define XHCI_PORTSC_WCE          (1<<25)
#define XHCI_PORTSC_WDE          (1<<26)
#define XHCI_PORTSC_WOE          (1<<27)
#define XHCI_PORTSC_DR           (1<<30)
#define XHCI_PORTSC_WPR          (1<<31)

#define TRB_C               (1<<0)
#define TRB_TYPE_SHIFT          10
#define TRB_TYPE_MASK       0x3f
#define TRB_TYPE(t)         (((t) >> TRB_TYPE_SHIFT) & TRB_TYPE_MASK)

#define TRB_EV_ED           (1<<2)

#define TRB_TR_ENT          (1<<1)
#define TRB_TR_ISP          (1<<2)
#define TRB_TR_NS           (1<<3)
#define TRB_TR_CH           (1<<4)
#define TRB_TR_IOC          (1<<5)
#define TRB_TR_IDT          (1<<6)
#define TRB_TR_TBC_SHIFT        7
#define TRB_TR_TBC_MASK     0x3
#define TRB_TR_BEI          (1<<9)
#define TRB_TR_TLBPC_SHIFT      16
#define TRB_TR_TLBPC_MASK   0xf
#define TRB_TR_FRAMEID_SHIFT    20
#define TRB_TR_FRAMEID_MASK 0x7ff
#define TRB_TR_SIA          (1<<31)

#define TRB_TR_DIR          (1<<16)

#define TRB_CR_SLOTID_SHIFT     24
#define TRB_CR_SLOTID_MASK  0xff
#define TRB_CR_EPID_SHIFT       16
#define TRB_CR_EPID_MASK    0x1f

#define TRB_CR_BSR          (1<<9)
#define TRB_CR_DC           (1<<9)

#define TRB_LK_TC           (1<<1)

#define TRB_INTR_SHIFT          22
#define TRB_INTR_MASK       0x3ff
#define TRB_INTR(t)         (((t).status >> TRB_INTR_SHIFT) & TRB_INTR_MASK)

typedef enum TRBType {
    TRB_RESERVED = 0,
    TR_NORMAL,
    TR_SETUP,
    TR_DATA,
    TR_STATUS,
    TR_ISOCH,
    TR_LINK,
    TR_EVDATA,
    TR_NOOP,
    CR_ENABLE_SLOT,
    CR_DISABLE_SLOT,
    CR_ADDRESS_DEVICE,
    CR_CONFIGURE_ENDPOINT,
    CR_EVALUATE_CONTEXT,
    CR_RESET_ENDPOINT,
    CR_STOP_ENDPOINT,
    CR_SET_TR_DEQUEUE,
    CR_RESET_DEVICE,
    CR_FORCE_EVENT,
    CR_NEGOTIATE_BW,
    CR_SET_LATENCY_TOLERANCE,
    CR_GET_PORT_BANDWIDTH,
    CR_FORCE_HEADER,
    CR_NOOP,
    ER_TRANSFER = 32,
    ER_COMMAND_COMPLETE,
    ER_PORT_STATUS_CHANGE,
    ER_BANDWIDTH_REQUEST,
    ER_DOORBELL,
    ER_HOST_CONTROLLER,
    ER_DEVICE_NOTIFICATION,
    ER_MFINDEX_WRAP,
} TRBType;

typedef enum TRBCCode {
    CC_INVALID = 0,
    CC_SUCCESS,
    CC_DATA_BUFFER_ERROR,
    CC_BABBLE_DETECTED,
    CC_USB_TRANSACTION_ERROR,
    CC_TRB_ERROR,
    CC_STALL_ERROR,
    CC_RESOURCE_ERROR,
    CC_BANDWIDTH_ERROR,
    CC_NO_SLOTS_ERROR,
    CC_INVALID_STREAM_TYPE_ERROR,
    CC_SLOT_NOT_ENABLED_ERROR,
    CC_EP_NOT_ENABLED_ERROR,
    CC_SHORT_PACKET,
    CC_RING_UNDERRUN,
    CC_RING_OVERRUN,
    CC_VF_ER_FULL,
    CC_PARAMETER_ERROR,
    CC_BANDWIDTH_OVERRUN,
    CC_CONTEXT_STATE_ERROR,
    CC_NO_PING_RESPONSE_ERROR,
    CC_EVENT_RING_FULL_ERROR,
    CC_INCOMPATIBLE_DEVICE_ERROR,
    CC_MISSED_SERVICE_ERROR,
    CC_COMMAND_RING_STOPPED,
    CC_COMMAND_ABORTED,
    CC_STOPPED,
    CC_STOPPED_LENGTH_INVALID,
    CC_MAX_EXIT_LATENCY_TOO_LARGE_ERROR = 29,
    CC_ISOCH_BUFFER_OVERRUN = 31,
    CC_EVENT_LOST_ERROR,
    CC_UNDEFINED_ERROR,
    CC_INVALID_STREAM_ID_ERROR,
    CC_SECONDARY_BANDWIDTH_ERROR,
    CC_SPLIT_TRANSACTION_ERROR
} TRBCCode;

enum {
    PLS_U0              =  0,
    PLS_U1              =  1,
    PLS_U2              =  2,
    PLS_U3              =  3,
    PLS_DISABLED        =  4,
    PLS_RX_DETECT       =  5,
    PLS_INACTIVE        =  6,
    PLS_POLLING         =  7,
    PLS_RECOVERY        =  8,
    PLS_HOT_RESET       =  9,
    PLS_COMPILANCE_MODE = 10,
    PLS_TEST_MODE       = 11,
    PLS_RESUME          = 15,
};

#define xhci_get_field(data, field)             \
    (((data) >> field##_SHIFT) & field##_MASK)

// --------------------------------------------------------------
// state structs

struct xhci_ring {
    struct xhci_trb      ring[XHCI_RING_ITEMS];
    struct xhci_trb      evt;
    u32                  eidx;
    u32                  nidx;
    u32                  cs;
    struct mutex_s       lock;
};

struct xhci_portmap {
    u8 start;
    u8 count;
};

struct usb_xhci_s {
    struct usb_s         usb;

    /* devinfo */
    u32                  xcap;
    u32                  ports;
    u32                  slots;
    u8                   context64;
    struct xhci_portmap  usb2;
    struct xhci_portmap  usb3;

    /* xhci registers */
    struct xhci_caps     *caps;
    struct xhci_op       *op;
    struct xhci_pr       *pr;
    struct xhci_ir       *ir;
    struct xhci_db       *db;

    /* xhci data structures */
    struct xhci_devlist  *devs;
    struct xhci_ring     *cmds;
    struct xhci_ring     *evts;
    struct xhci_er_seg   *eseg;
};

struct xhci_pipe {
    struct xhci_ring     reqs;

    struct usb_pipe      pipe;
    u32                  slotid;
    u32                  epid;
    void                 *buf;
    int                  bufused;
};

// --------------------------------------------------------------
// tables

static const char *speed_name[16] = {
    [ 0 ] = " - ",
    [ 1 ] = "Full",
    [ 2 ] = "Low",
    [ 3 ] = "High",
    [ 4 ] = "Super",
};

static const int speed_from_xhci[16] = {
    [ 0 ] = -1,
    [ 1 ] = USB_FULLSPEED,
    [ 2 ] = USB_LOWSPEED,
    [ 3 ] = USB_HIGHSPEED,
    [ 4 ] = USB_SUPERSPEED,
    [ 5 ... 15 ] = -1,
};

static const int speed_to_xhci[] = {
    [ USB_FULLSPEED  ] = 1,
    [ USB_LOWSPEED   ] = 2,
    [ USB_HIGHSPEED  ] = 3,
    [ USB_SUPERSPEED ] = 4,
};

static int wait_bit(u32 *reg, u32 mask, int value, u32 timeout)
{
    u32 end = timer_calc(timeout);

    while ((readl(reg) & mask) != value) {
        if (timer_check(end)) {
            warn_timeout();
            return -1;
        }
        yield();
    }
    return 0;
}


/****************************************************************
 * Root hub
 ****************************************************************/

#define XHCI_TIME_POSTPOWER 20

// Check if device attached to port
static void
xhci_print_port_state(int loglevel, const char *prefix, u32 port, u32 portsc)
{
    u32 pls = xhci_get_field(portsc, XHCI_PORTSC_PLS);
    u32 speed = xhci_get_field(portsc, XHCI_PORTSC_SPEED);

    dprintf(loglevel, "%s port #%d: 0x%08x,%s%s pls %d, speed %d [%s]\n",
            prefix, port + 1, portsc,
            (portsc & XHCI_PORTSC_PP)  ? " powered," : "",
            (portsc & XHCI_PORTSC_PED) ? " enabled," : "",
            pls, speed, speed_name[speed]);
}

static int
xhci_hub_detect(struct usbhub_s *hub, u32 port)
{
    struct usb_xhci_s *xhci = container_of(hub->cntl, struct usb_xhci_s, usb);
    u32 portsc = readl(&xhci->pr[port].portsc);
    return (portsc & XHCI_PORTSC_CCS) ? 1 : 0;
}

// Reset device on port
static int
xhci_hub_reset(struct usbhub_s *hub, u32 port)
{
    struct usb_xhci_s *xhci = container_of(hub->cntl, struct usb_xhci_s, usb);
    u32 portsc = readl(&xhci->pr[port].portsc);
    if (!(portsc & XHCI_PORTSC_CCS))
        // Device no longer connected?!
        return -1;

    switch (xhci_get_field(portsc, XHCI_PORTSC_PLS)) {
    case PLS_U0:
        // A USB3 port - controller automatically performs reset
        break;
    case PLS_POLLING:
        // A USB2 port - perform device reset
        xhci_print_port_state(3, __func__, port, portsc);
        writel(&xhci->pr[port].portsc, portsc | XHCI_PORTSC_PR);
        break;
    default:
        return -1;
    }

    // Wait for device to complete reset and be enabled
    u32 end = timer_calc(100);
    for (;;) {
        portsc = readl(&xhci->pr[port].portsc);
        if (!(portsc & XHCI_PORTSC_CCS))
            // Device disconnected during reset
            return -1;
        if (portsc & XHCI_PORTSC_PED)
            // Reset complete
            break;
        if (timer_check(end)) {
            warn_timeout();
            return -1;
        }
        yield();
    }

    int rc = speed_from_xhci[xhci_get_field(portsc, XHCI_PORTSC_SPEED)];
    xhci_print_port_state(1, "XHCI", port, portsc);
    return rc;
}

static int
xhci_hub_portmap(struct usbhub_s *hub, u32 vport)
{
    struct usb_xhci_s *xhci = container_of(hub->cntl, struct usb_xhci_s, usb);
    u32 pport = vport + 1;

    if (vport + 1 >= xhci->usb3.start &&
        vport + 1 < xhci->usb3.start + xhci->usb3.count)
        pport = vport + 2 - xhci->usb3.start;

    if (vport + 1 >= xhci->usb2.start &&
        vport + 1 < xhci->usb2.start + xhci->usb2.count)
        pport = vport + 2 - xhci->usb2.start;

    return pport;
}

static void
xhci_hub_disconnect(struct usbhub_s *hub, u32 port)
{
    // XXX - should turn the port power off.
}

static struct usbhub_op_s xhci_hub_ops = {
    .detect = xhci_hub_detect,
    .reset = xhci_hub_reset,
    .portmap = xhci_hub_portmap,
    .disconnect = xhci_hub_disconnect,
};

// Find any devices connected to the root hub.
static int
xhci_check_ports(struct usb_xhci_s *xhci)
{
    // Wait for port power to stabilize.
    msleep(XHCI_TIME_POSTPOWER);

    struct usbhub_s hub;
    memset(&hub, 0, sizeof(hub));
    hub.cntl = &xhci->usb;
    hub.portcount = xhci->ports;
    hub.op = &xhci_hub_ops;
    usb_enumerate(&hub);
    return hub.devcount;
}


/****************************************************************
 * Setup
 ****************************************************************/

static void
xhci_free_pipes(struct usb_xhci_s *xhci)
{
    // XXX - should walk list of pipes and free unused pipes.
}

static void
configure_xhci(void *data)
{
    struct usb_xhci_s *xhci = data;
    u32 reg;

    xhci->devs = memalign_high(64, sizeof(*xhci->devs) * (xhci->slots + 1));
    xhci->eseg = memalign_high(64, sizeof(*xhci->eseg));
    xhci->cmds = memalign_high(XHCI_RING_SIZE, sizeof(*xhci->cmds));
    xhci->evts = memalign_high(XHCI_RING_SIZE, sizeof(*xhci->evts));
    if (!xhci->devs || !xhci->cmds || !xhci->evts || !xhci->eseg) {
        warn_noalloc();
        goto fail;
    }
    memset(xhci->devs, 0, sizeof(*xhci->devs) * (xhci->slots + 1));
    memset(xhci->cmds, 0, sizeof(*xhci->cmds));
    memset(xhci->evts, 0, sizeof(*xhci->evts));
    memset(xhci->eseg, 0, sizeof(*xhci->eseg));

    reg = readl(&xhci->op->usbcmd);
    if (reg & XHCI_CMD_RS) {
        reg &= ~XHCI_CMD_RS;
        writel(&xhci->op->usbcmd, reg);
        if (wait_bit(&xhci->op->usbsts, XHCI_STS_HCH, XHCI_STS_HCH, 32) != 0)
            goto fail;
    }

    dprintf(3, "%s: resetting\n", __func__);
    writel(&xhci->op->usbcmd, XHCI_CMD_HCRST);
    if (wait_bit(&xhci->op->usbcmd, XHCI_CMD_HCRST, 0, 1000) != 0)
        goto fail;
    if (wait_bit(&xhci->op->usbsts, XHCI_STS_CNR, 0, 1000) != 0)
        goto fail;

    writel(&xhci->op->config, xhci->slots);
    writel(&xhci->op->dcbaap_low, (u32)xhci->devs);
    writel(&xhci->op->dcbaap_high, 0);
    writel(&xhci->op->crcr_low, (u32)xhci->cmds | 1);
    writel(&xhci->op->crcr_high, 0);
    xhci->cmds->cs = 1;

    xhci->eseg->ptr_low = (u32)xhci->evts;
    xhci->eseg->ptr_high = 0;
    xhci->eseg->size = XHCI_RING_ITEMS;
    writel(&xhci->ir->erstsz, 1);
    writel(&xhci->ir->erdp_low, (u32)xhci->evts);
    writel(&xhci->ir->erdp_high, 0);
    writel(&xhci->ir->erstba_low, (u32)xhci->eseg);
    writel(&xhci->ir->erstba_high, 0);
    xhci->evts->cs = 1;

    reg = readl(&xhci->caps->hcsparams2);
    u32 spb = (reg >> 21 & 0x1f) << 5 | reg >> 27;
    if (spb) {
        dprintf(3, "%s: setup %d scratch pad buffers\n", __func__, spb);
        u64 *spba = memalign_high(64, sizeof(*spba) * spb);
        void *pad = memalign_high(PAGE_SIZE, PAGE_SIZE * spb);
        if (!spba || !pad) {
            warn_noalloc();
            free(spba);
            free(pad);
            goto fail;
        }
        int i;
        for (i = 0; i < spb; i++)
            spba[i] = (u32)pad + (i * PAGE_SIZE);
        xhci->devs[0].ptr_low = (u32)spba;
        xhci->devs[0].ptr_high = 0;
    }

    reg = readl(&xhci->op->usbcmd);
    reg |= XHCI_CMD_RS;
    writel(&xhci->op->usbcmd, reg);

    // Find devices
    int count = xhci_check_ports(xhci);
    xhci_free_pipes(xhci);
    if (count)
        // Success
        return;

    // No devices found - shutdown and free controller.
    dprintf(1, "XHCI no devices found\n");
    reg = readl(&xhci->op->usbcmd);
    reg &= ~XHCI_CMD_RS;
    writel(&xhci->op->usbcmd, reg);
    wait_bit(&xhci->op->usbsts, XHCI_STS_HCH, XHCI_STS_HCH, 32);

fail:
    free(xhci->eseg);
    free(xhci->evts);
    free(xhci->cmds);
    free(xhci->devs);
    free(xhci);
}

static struct usb_xhci_s*
xhci_controller_setup(void *baseaddr)
{
    struct usb_xhci_s *xhci = malloc_high(sizeof(*xhci));
    if (!xhci) {
        warn_noalloc();
        return NULL;
    }
    memset(xhci, 0, sizeof(*xhci));
    xhci->caps  = baseaddr;
    xhci->op    = baseaddr + readb(&xhci->caps->caplength);
    xhci->pr    = baseaddr + readb(&xhci->caps->caplength) + 0x400;
    xhci->db    = baseaddr + readl(&xhci->caps->dboff);
    xhci->ir    = baseaddr + readl(&xhci->caps->rtsoff) + 0x20;

    u32 hcs1 = readl(&xhci->caps->hcsparams1);
    u32 hcc  = readl(&xhci->caps->hccparams);
    xhci->ports = (hcs1 >> 24) & 0xff;
    xhci->slots = hcs1         & 0xff;
    xhci->xcap  = ((hcc >> 16) & 0xffff) << 2;
    xhci->context64 = (hcc & 0x04) ? 1 : 0;
    xhci->usb.type = USB_TYPE_XHCI;

    dprintf(1, "XHCI init: regs @ %p, %d ports, %d slots"
            ", %d byte contexts\n"
            , xhci->caps, xhci->ports, xhci->slots
            , xhci->context64 ? 64 : 32);

    if (xhci->xcap) {
        u32 off;
        void *addr = baseaddr + xhci->xcap;
        do {
            struct xhci_xcap *xcap = addr;
            u32 ports, name, cap = readl(&xcap->cap);
            switch (cap & 0xff) {
            case 0x02:
                name  = readl(&xcap->data[0]);
                ports = readl(&xcap->data[1]);
                u8 major = (cap >> 24) & 0xff;
                u8 minor = (cap >> 16) & 0xff;
                u8 count = (ports >> 8) & 0xff;
                u8 start = (ports >> 0) & 0xff;
                dprintf(1, "XHCI    protocol %c%c%c%c %x.%02x"
                        ", %d ports (offset %d), def %x\n"
                        , (name >>  0) & 0xff
                        , (name >>  8) & 0xff
                        , (name >> 16) & 0xff
                        , (name >> 24) & 0xff
                        , major, minor
                        , count, start
                        , ports >> 16);
                if (name == 0x20425355 /* "USB " */) {
                    if (major == 2) {
                        xhci->usb2.start = start;
                        xhci->usb2.count = count;
                    }
                    if (major == 3) {
                        xhci->usb3.start = start;
                        xhci->usb3.count = count;
                    }
                }
                break;
            default:
                dprintf(1, "XHCI    extcap 0x%x @ %p\n", cap & 0xff, addr);
                break;
            }
            off = (cap >> 8) & 0xff;
            addr += off << 2;
        } while (off > 0);
    }

    u32 pagesize = readl(&xhci->op->pagesize);
    if (PAGE_SIZE != (pagesize<<12)) {
        dprintf(1, "XHCI driver does not support page size code %d\n"
                , pagesize<<12);
        free(xhci);
        return NULL;
    }

    return xhci;
}

static void
xhci_controller_setup_pci(struct pci_device *pci)
{
    struct usb_xhci_s *xhci;
    void *baseaddr;

    baseaddr = pci_enable_membar(pci, PCI_BASE_ADDRESS_0);
    if (!baseaddr)
        return;

    dprintf(1, "PCI: XHCI at %pP (mmio %p)\n", pci, baseaddr);
    pci_enable_busmaster(pci);

    xhci = xhci_controller_setup(baseaddr);
    if (!xhci)
        return;

    xhci->usb.pci = pci;
    run_thread(configure_xhci, xhci);
}

static void
xhci_controller_setup_acpi(struct acpi_device *dev)
{
    struct usb_xhci_s *xhci;
    u64 mem, unused;
    void *baseaddr;

    if (acpi_dsdt_find_mem(dev, &mem, &unused) < 0)
        return;
    if (mem >= 0x100000000ll)
        return;

    baseaddr = (void*)(u32)mem;
    dprintf(1, "ACPI: XHCI at mmio %p\n", baseaddr);

    xhci = xhci_controller_setup(baseaddr);
    if (!xhci)
        return;

    xhci->usb.mmio = baseaddr;
    run_thread(configure_xhci, xhci);
}

void
xhci_setup(void)
{
    if (! CONFIG_USB_XHCI)
        return;

    struct pci_device *pci;
    foreachpci(pci) {
        if (pci_classprog(pci) == PCI_CLASS_SERIAL_USB_XHCI)
            xhci_controller_setup_pci(pci);
    }

    u16 xhci_eisaid = 0x0d10;
    struct acpi_device *dev;
    for (dev = acpi_dsdt_find_eisaid(NULL, xhci_eisaid);
         dev != NULL;
         dev = acpi_dsdt_find_eisaid(dev, xhci_eisaid)) {
        xhci_controller_setup_acpi(dev);
    }
}


/****************************************************************
 * End point communication
 ****************************************************************/

// Signal the hardware to process events on a TRB ring
static void xhci_doorbell(struct usb_xhci_s *xhci, u32 slotid, u32 value)
{
    dprintf(5, "%s: slotid %d, epid %d\n", __func__, slotid, value);
    struct xhci_db *db = xhci->db;
    void *addr = &db[slotid].doorbell;
    writel(addr, value);
}

// Dequeue events on the XHCI command ring generated by the hardware
static void xhci_process_events(struct usb_xhci_s *xhci)
{
    struct xhci_ring *evts = xhci->evts;

    for (;;) {
        /* check for event */
        u32 nidx = evts->nidx;
        u32 cs = evts->cs;
        struct xhci_trb *etrb = evts->ring + nidx;
        u32 control = etrb->control;
        if ((control & TRB_C) != (cs ? 1 : 0))
            return;

        /* process event */
        u32 evt_type = TRB_TYPE(control);
        u32 evt_cc = (etrb->status >> 24) & 0xff;
        switch (evt_type) {
        case ER_TRANSFER:
        case ER_COMMAND_COMPLETE:
        {
            struct xhci_trb  *rtrb = (void*)etrb->ptr_low;
            struct xhci_ring *ring = XHCI_RING(rtrb);
            struct xhci_trb  *evt = &ring->evt;
            u32 eidx = rtrb - ring->ring + 1;
            dprintf(5, "%s: ring %p [trb %p, evt %p, type %d, eidx %d, cc %d]\n",
                    __func__, ring, rtrb, evt, evt_type, eidx, evt_cc);
            memcpy(evt, etrb, sizeof(*etrb));
            ring->eidx = eidx;
            break;
        }
        case ER_PORT_STATUS_CHANGE:
        {
            u32 port = ((etrb->ptr_low >> 24) & 0xff) - 1;
            // Read status, and clear port status change bits
            u32 portsc = readl(&xhci->pr[port].portsc);
            u32 pclear = (((portsc & ~(XHCI_PORTSC_PED|XHCI_PORTSC_PR))
                           & ~(XHCI_PORTSC_PLS_MASK<<XHCI_PORTSC_PLS_SHIFT))
                          | (1<<XHCI_PORTSC_PLS_SHIFT));
            writel(&xhci->pr[port].portsc, pclear);

            xhci_print_port_state(3, __func__, port, portsc);
            break;
        }
        default:
            dprintf(1, "%s: unknown event, type %d, cc %d\n",
                    __func__, evt_type, evt_cc);
            break;
        }

        /* move ring index, notify xhci */
        nidx++;
        if (nidx == XHCI_RING_ITEMS) {
            nidx = 0;
            cs = cs ? 0 : 1;
            evts->cs = cs;
        }
        evts->nidx = nidx;
        struct xhci_ir *ir = xhci->ir;
        u32 erdp = (u32)(evts->ring + nidx);
        writel(&ir->erdp_low, erdp);
        writel(&ir->erdp_high, 0);
    }
}

// Check if a ring has any pending TRBs
static int xhci_ring_busy(struct xhci_ring *ring)
{
    u32 eidx = ring->eidx;
    u32 nidx = ring->nidx;
    return (eidx != nidx);
}

// Wait for a ring to empty (all TRBs processed by hardware)
static int xhci_event_wait(struct usb_xhci_s *xhci,
                           struct xhci_ring *ring,
                           u32 timeout)
{
    u32 end = timer_calc(timeout);

    for (;;) {
        xhci_process_events(xhci);
        if (!xhci_ring_busy(ring)) {
            u32 status = ring->evt.status;
            return (status >> 24) & 0xff;
        }
        if (timer_check(end)) {
            warn_timeout();
            return -1;
        }
        yield();
    }
}

// Add a TRB to the given ring
static void xhci_trb_fill(struct xhci_ring *ring
                          , void *data, u32 xferlen, u32 flags)
{
    struct xhci_trb *dst = &ring->ring[ring->nidx];
    if (flags & TRB_TR_IDT) {
        memcpy(&dst->ptr_low, data, xferlen);
    } else {
        dst->ptr_low = (u32)data;
        dst->ptr_high = 0;
    }
    dst->status = xferlen;
    dst->control = flags | (ring->cs ? TRB_C : 0);
}

// Queue a TRB onto a ring, wrapping ring as needed
static void xhci_trb_queue(struct xhci_ring *ring,
                           void *data, u32 xferlen, u32 flags)
{
    if (ring->nidx >= ARRAY_SIZE(ring->ring) - 1) {
        xhci_trb_fill(ring, ring->ring, 0, (TR_LINK << 10) | TRB_LK_TC);
        ring->nidx = 0;
        ring->cs ^= 1;
        dprintf(5, "%s: ring %p [linked]\n", __func__, ring);
    }

    xhci_trb_fill(ring, data, xferlen, flags);
    ring->nidx++;
    dprintf(5, "%s: ring %p [nidx %d, len %d]\n",
            __func__, ring, ring->nidx, xferlen);
}

// Submit a command to the xhci controller ring
static int xhci_cmd_submit(struct usb_xhci_s *xhci, struct xhci_inctx *inctx
                           , u32 flags)
{
    if (inctx) {
        struct xhci_slotctx *slot = (void*)&inctx[1 << xhci->context64];
        u32 port = ((slot->ctx[1] >> 16) & 0xff) - 1;
        u32 portsc = readl(&xhci->pr[port].portsc);
        if (!(portsc & XHCI_PORTSC_CCS)) {
            // Device no longer connected?!
            xhci_print_port_state(1, __func__, port, portsc);
            return -1;
        }
    }

    mutex_lock(&xhci->cmds->lock);
    xhci_trb_queue(xhci->cmds, inctx, 0, flags);
    xhci_doorbell(xhci, 0, 0);
    int rc = xhci_event_wait(xhci, xhci->cmds, 1000);
    mutex_unlock(&xhci->cmds->lock);
    return rc;
}

static int xhci_cmd_enable_slot(struct usb_xhci_s *xhci)
{
    dprintf(3, "%s:\n", __func__);
    int cc = xhci_cmd_submit(xhci, NULL, CR_ENABLE_SLOT << 10);
    if (cc != CC_SUCCESS)
        return -1;
    return (xhci->cmds->evt.control >> 24) & 0xff;
}

static int xhci_cmd_disable_slot(struct usb_xhci_s *xhci, u32 slotid)
{
    dprintf(3, "%s: slotid %d\n", __func__, slotid);
    return xhci_cmd_submit(xhci, NULL, (CR_DISABLE_SLOT << 10) | (slotid << 24));
}

static int xhci_cmd_address_device(struct usb_xhci_s *xhci, u32 slotid
                                   , struct xhci_inctx *inctx)
{
    dprintf(3, "%s: slotid %d\n", __func__, slotid);
    return xhci_cmd_submit(xhci, inctx
                           , (CR_ADDRESS_DEVICE << 10) | (slotid << 24));
}

static int xhci_cmd_configure_endpoint(struct usb_xhci_s *xhci, u32 slotid
                                       , struct xhci_inctx *inctx)
{
    dprintf(3, "%s: slotid %d, add 0x%x, del 0x%x\n", __func__,
            slotid, inctx->add, inctx->del);
    return xhci_cmd_submit(xhci, inctx
                           , (CR_CONFIGURE_ENDPOINT << 10) | (slotid << 24));
}

static int xhci_cmd_evaluate_context(struct usb_xhci_s *xhci, u32 slotid
                                     , struct xhci_inctx *inctx)
{
    dprintf(3, "%s: slotid %d, add 0x%x, del 0x%x\n", __func__,
            slotid, inctx->add, inctx->del);
    return xhci_cmd_submit(xhci, inctx
                           , (CR_EVALUATE_CONTEXT << 10) | (slotid << 24));
}

static struct xhci_inctx *
xhci_alloc_inctx(struct usbdevice_s *usbdev, int maxepid)
{
    struct usb_xhci_s *xhci = container_of(
        usbdev->hub->cntl, struct usb_xhci_s, usb);
    int size = (sizeof(struct xhci_inctx) * 33) << xhci->context64;
    struct xhci_inctx *in = memalign_tmphigh(2048 << xhci->context64, size);
    if (!in) {
        warn_noalloc();
        return NULL;
    }
    memset(in, 0, size);

    struct xhci_slotctx *slot = (void*)&in[1 << xhci->context64];
    slot->ctx[0]    |= maxepid << 27; // context entries
    slot->ctx[0]    |= speed_to_xhci[usbdev->speed] << 20;

    // Set high-speed hub flags.
    struct usbdevice_s *hubdev = usbdev->hub->usbdev;
    if (hubdev) {
        if (usbdev->speed == USB_LOWSPEED || usbdev->speed == USB_FULLSPEED) {
            struct xhci_pipe *hpipe = container_of(
                hubdev->defpipe, struct xhci_pipe, pipe);
            if (hubdev->speed == USB_HIGHSPEED) {
                slot->ctx[2] |= hpipe->slotid;
                slot->ctx[2] |= (usbdev->port+1) << 8;
            } else {
                struct xhci_slotctx *hslot = (void*)xhci->devs[hpipe->slotid].ptr_low;
                slot->ctx[2] = hslot->ctx[2];
            }
        }
        u32 route = 0;
        while (usbdev->hub->usbdev) {
            route <<= 4;
            route |= (usbdev->port+1) & 0xf;
            usbdev = usbdev->hub->usbdev;
        }
        slot->ctx[0]    |= route;
    }

    slot->ctx[1]    |= (usbdev->port+1) << 16;

    return in;
}

static int xhci_config_hub(struct usbhub_s *hub)
{
    struct usb_xhci_s *xhci = container_of(
        hub->cntl, struct usb_xhci_s, usb);
    struct xhci_pipe *pipe = container_of(
        hub->usbdev->defpipe, struct xhci_pipe, pipe);
    struct xhci_slotctx *hdslot = (void*)xhci->devs[pipe->slotid].ptr_low;
    if ((hdslot->ctx[3] >> 27) == 3)
        // Already configured
        return 0;
    struct xhci_inctx *in = xhci_alloc_inctx(hub->usbdev, 1);
    if (!in)
        return -1;
    in->add = 0x01;
    struct xhci_slotctx *slot = (void*)&in[1 << xhci->context64];
    slot->ctx[0] |= 1 << 26;
    slot->ctx[1] |= hub->portcount << 24;

    int cc = xhci_cmd_configure_endpoint(xhci, pipe->slotid, in);
    free(in);
    if (cc != CC_SUCCESS) {
        dprintf(1, "%s: configure hub: failed (cc %d)\n", __func__, cc);
        return -1;
    }
    return 0;
}

static struct usb_pipe *
xhci_alloc_pipe(struct usbdevice_s *usbdev
                , struct usb_endpoint_descriptor *epdesc)
{
    u8 eptype = epdesc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;
    struct usb_xhci_s *xhci = container_of(
        usbdev->hub->cntl, struct usb_xhci_s, usb);
    struct xhci_pipe *pipe;
    u32 epid;

    if (epdesc->bEndpointAddress == 0) {
        epid = 1;
    } else {
        epid = (epdesc->bEndpointAddress & 0x0f) * 2;
        epid += (epdesc->bEndpointAddress & USB_DIR_IN) ? 1 : 0;
    }

    if (eptype == USB_ENDPOINT_XFER_CONTROL)
        pipe = memalign_high(XHCI_RING_SIZE, sizeof(*pipe));
    else
        pipe = memalign_low(XHCI_RING_SIZE, sizeof(*pipe));
    if (!pipe) {
        warn_noalloc();
        return NULL;
    }
    memset(pipe, 0, sizeof(*pipe));

    usb_desc2pipe(&pipe->pipe, usbdev, epdesc);
    pipe->epid = epid;
    pipe->reqs.cs = 1;
    if (eptype == USB_ENDPOINT_XFER_INT) {
        pipe->buf = malloc_high(pipe->pipe.maxpacket);
        if (!pipe->buf) {
            warn_noalloc();
            free(pipe);
            return NULL;
        }
    }

    // Allocate input context and initialize endpoint info.
    struct xhci_inctx *in = xhci_alloc_inctx(usbdev, epid);
    if (!in)
        goto fail;
    in->add = 0x01 | (1 << epid);
    struct xhci_epctx *ep = (void*)&in[(pipe->epid+1) << xhci->context64];
    if (eptype == USB_ENDPOINT_XFER_INT)
        ep->ctx[0] = (usb_get_period(usbdev, epdesc) + 3) << 16;
    ep->ctx[1]   |= eptype << 3;
    if (epdesc->bEndpointAddress & USB_DIR_IN
        || eptype == USB_ENDPOINT_XFER_CONTROL)
        ep->ctx[1] |= 1 << 5;
    ep->ctx[1]   |= pipe->pipe.maxpacket << 16;
    ep->deq_low  = (u32)&pipe->reqs.ring[0];
    ep->deq_low  |= 1;         // dcs
    ep->length   = pipe->pipe.maxpacket;

    dprintf(3, "%s: usbdev %p, ring %p, slotid %d, epid %d\n", __func__,
            usbdev, &pipe->reqs, pipe->slotid, pipe->epid);
    if (pipe->epid == 1) {
        if (usbdev->hub->usbdev) {
            // Make sure parent hub is configured.
            int ret = xhci_config_hub(usbdev->hub);
            if (ret)
                goto fail;
        }
        // Enable slot.
        u32 size = (sizeof(struct xhci_slotctx) * 32) << xhci->context64;
        struct xhci_slotctx *dev = memalign_high(1024 << xhci->context64, size);
        if (!dev) {
            warn_noalloc();
            goto fail;
        }
        int slotid = xhci_cmd_enable_slot(xhci);
        if (slotid < 0) {
            dprintf(1, "%s: enable slot: failed\n", __func__);
            free(dev);
            goto fail;
        }
        dprintf(3, "%s: enable slot: got slotid %d\n", __func__, slotid);
        memset(dev, 0, size);
        xhci->devs[slotid].ptr_low = (u32)dev;
        xhci->devs[slotid].ptr_high = 0;

        // Send set_address command.
        int cc = xhci_cmd_address_device(xhci, slotid, in);
        if (cc != CC_SUCCESS) {
            dprintf(1, "%s: address device: failed (cc %d)\n", __func__, cc);
            cc = xhci_cmd_disable_slot(xhci, slotid);
            if (cc != CC_SUCCESS) {
                dprintf(1, "%s: disable failed (cc %d)\n", __func__, cc);
                goto fail;
            }
            xhci->devs[slotid].ptr_low = 0;
            free(dev);
            goto fail;
        }
        pipe->slotid = slotid;
    } else {
        struct xhci_pipe *defpipe = container_of(
            usbdev->defpipe, struct xhci_pipe, pipe);
        pipe->slotid = defpipe->slotid;
        // Send configure command.
        int cc = xhci_cmd_configure_endpoint(xhci, pipe->slotid, in);
        if (cc != CC_SUCCESS) {
            dprintf(1, "%s: configure endpoint: failed (cc %d)\n", __func__, cc);
            goto fail;
        }
    }
    free(in);
    return &pipe->pipe;

fail:
    free(pipe->buf);
    free(pipe);
    free(in);
    return NULL;
}

struct usb_pipe *
xhci_realloc_pipe(struct usbdevice_s *usbdev, struct usb_pipe *upipe
                  , struct usb_endpoint_descriptor *epdesc)
{
    if (!CONFIG_USB_XHCI)
        return NULL;
    if (!epdesc) {
        usb_add_freelist(upipe);
        return NULL;
    }
    if (!upipe)
        return xhci_alloc_pipe(usbdev, epdesc);
    u8 eptype = epdesc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;
    int oldmaxpacket = upipe->maxpacket;
    usb_desc2pipe(upipe, usbdev, epdesc);
    struct xhci_pipe *pipe = container_of(upipe, struct xhci_pipe, pipe);
    struct usb_xhci_s *xhci = container_of(
        pipe->pipe.cntl, struct usb_xhci_s, usb);
    dprintf(3, "%s: usbdev %p, ring %p, slotid %d, epid %d\n", __func__,
            usbdev, &pipe->reqs, pipe->slotid, pipe->epid);
    if (eptype != USB_ENDPOINT_XFER_CONTROL || upipe->maxpacket == oldmaxpacket)
        return upipe;

    // maxpacket has changed on control endpoint - update controller.
    dprintf(1, "%s: reconf ctl endpoint pkt size: %d -> %d\n",
            __func__, oldmaxpacket, pipe->pipe.maxpacket);
    struct xhci_inctx *in = xhci_alloc_inctx(usbdev, 1);
    if (!in)
        return upipe;
    in->add = (1 << 1);
    struct xhci_epctx *ep = (void*)&in[2 << xhci->context64];
    ep->ctx[1] |= (pipe->pipe.maxpacket << 16);
    int cc = xhci_cmd_evaluate_context(xhci, pipe->slotid, in);
    if (cc != CC_SUCCESS) {
        dprintf(1, "%s: reconf ctl endpoint: failed (cc %d)\n",
                __func__, cc);
    }
    free(in);

    return upipe;
}

// Submit a USB "setup" message request to the pipe's ring
static void xhci_xfer_setup(struct xhci_pipe *pipe, int dir, void *cmd
                            , void *data, int datalen)
{
    struct usb_xhci_s *xhci = container_of(
        pipe->pipe.cntl, struct usb_xhci_s, usb);
    xhci_trb_queue(&pipe->reqs, cmd, USB_CONTROL_SETUP_SIZE
                   , (TR_SETUP << 10) | TRB_TR_IDT
                   | ((datalen ? (dir ? 3 : 2) : 0) << 16));
    if (datalen)
        xhci_trb_queue(&pipe->reqs, data, datalen, (TR_DATA << 10)
                       | ((dir ? 1 : 0) << 16));
    xhci_trb_queue(&pipe->reqs, NULL, 0, (TR_STATUS << 10) | TRB_TR_IOC
                   | ((dir ? 0 : 1) << 16));
    xhci_doorbell(xhci, pipe->slotid, pipe->epid);
}

// Submit a USB transfer request to the pipe's ring
static void xhci_xfer_normal(struct xhci_pipe *pipe,
                             void *data, int datalen)
{
    struct usb_xhci_s *xhci = container_of(
        pipe->pipe.cntl, struct usb_xhci_s, usb);
    xhci_trb_queue(&pipe->reqs, data, datalen, (TR_NORMAL << 10) | TRB_TR_IOC);
    xhci_doorbell(xhci, pipe->slotid, pipe->epid);
}

int
xhci_send_pipe(struct usb_pipe *p, int dir, const void *cmd
               , void *data, int datalen)
{
    if (!CONFIG_USB_XHCI)
        return -1;
    struct xhci_pipe *pipe = container_of(p, struct xhci_pipe, pipe);
    struct usb_xhci_s *xhci = container_of(
        pipe->pipe.cntl, struct usb_xhci_s, usb);

    if (cmd) {
        const struct usb_ctrlrequest *req = cmd;
        if (req->bRequest == USB_REQ_SET_ADDRESS)
            // Set address command sent during xhci_alloc_pipe.
            return 0;
        xhci_xfer_setup(pipe, dir, (void*)req, data, datalen);
    } else {
        xhci_xfer_normal(pipe, data, datalen);
    }

    int cc = xhci_event_wait(xhci, &pipe->reqs, usb_xfer_time(p, datalen));
    if (cc != CC_SUCCESS) {
        dprintf(1, "%s: xfer failed (cc %d)\n", __func__, cc);
        return -1;
    }

    return 0;
}

int VISIBLE32FLAT
xhci_poll_intr(struct usb_pipe *p, void *data)
{
    if (!CONFIG_USB_XHCI)
        return -1;

    struct xhci_pipe *pipe = container_of(p, struct xhci_pipe, pipe);
    struct usb_xhci_s *xhci = container_of(
        pipe->pipe.cntl, struct usb_xhci_s, usb);
    u32 len = pipe->pipe.maxpacket;
    void *buf = pipe->buf;
    int bufused = pipe->bufused;

    if (!bufused) {
        xhci_xfer_normal(pipe, buf, len);
        bufused = 1;
        pipe->bufused = bufused;
        return -1;
    }

    xhci_process_events(xhci);
    if (xhci_ring_busy(&pipe->reqs))
        return -1;
    dprintf(5, "%s: st %x ct %x [ %p <= %p / %d ]\n", __func__,
            pipe->reqs.evt.status,
            pipe->reqs.evt.control,
            data, buf, len);
    memcpy(data, buf, len);
    xhci_xfer_normal(pipe, buf, len);
    return 0;
}
