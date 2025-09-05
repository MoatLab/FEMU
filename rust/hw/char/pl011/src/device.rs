// Copyright 2024, Linaro Limited
// Author(s): Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{
    ffi::{c_int, c_void, CStr},
    mem::size_of,
    ptr::NonNull,
};

use qemu_api::{
    bindings::{qdev_prop_bool, qdev_prop_chr},
    chardev::{CharBackend, Chardev, Event},
    impl_vmstate_forward,
    irq::{IRQState, InterruptSource},
    log::Log,
    log_mask_ln,
    memory::{hwaddr, MemoryRegion, MemoryRegionOps, MemoryRegionOpsBuilder},
    prelude::*,
    qdev::{Clock, ClockEvent, DeviceImpl, DeviceState, Property, ResetType, ResettablePhasesImpl},
    qom::{ObjectImpl, Owned, ParentField, ParentInit},
    static_assert,
    sysbus::{SysBusDevice, SysBusDeviceImpl},
    uninit_field_mut,
    vmstate::VMStateDescription,
    vmstate_clock, vmstate_fields, vmstate_of, vmstate_struct, vmstate_subsections, vmstate_unused,
    zeroable::Zeroable,
};

use crate::registers::{self, Interrupt, RegisterOffset};

// TODO: You must disable the UART before any of the control registers are
// reprogrammed. When the UART is disabled in the middle of transmission or
// reception, it completes the current character before stopping

/// Integer Baud Rate Divider, `UARTIBRD`
const IBRD_MASK: u32 = 0xffff;

/// Fractional Baud Rate Divider, `UARTFBRD`
const FBRD_MASK: u32 = 0x3f;

/// QEMU sourced constant.
pub const PL011_FIFO_DEPTH: u32 = 16;

#[derive(Clone, Copy)]
struct DeviceId(&'static [u8; 8]);

impl std::ops::Index<hwaddr> for DeviceId {
    type Output = u8;

    fn index(&self, idx: hwaddr) -> &Self::Output {
        &self.0[idx as usize]
    }
}

// FIFOs use 32-bit indices instead of usize, for compatibility with
// the migration stream produced by the C version of this device.
#[repr(transparent)]
#[derive(Debug, Default)]
pub struct Fifo([registers::Data; PL011_FIFO_DEPTH as usize]);
impl_vmstate_forward!(Fifo);

impl Fifo {
    const fn len(&self) -> u32 {
        self.0.len() as u32
    }
}

impl std::ops::IndexMut<u32> for Fifo {
    fn index_mut(&mut self, idx: u32) -> &mut Self::Output {
        &mut self.0[idx as usize]
    }
}

impl std::ops::Index<u32> for Fifo {
    type Output = registers::Data;

    fn index(&self, idx: u32) -> &Self::Output {
        &self.0[idx as usize]
    }
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct PL011Registers {
    #[doc(alias = "fr")]
    pub flags: registers::Flags,
    #[doc(alias = "lcr")]
    pub line_control: registers::LineControl,
    #[doc(alias = "rsr")]
    pub receive_status_error_clear: registers::ReceiveStatusErrorClear,
    #[doc(alias = "cr")]
    pub control: registers::Control,
    pub dmacr: u32,
    pub int_enabled: Interrupt,
    pub int_level: Interrupt,
    pub read_fifo: Fifo,
    pub ilpr: u32,
    pub ibrd: u32,
    pub fbrd: u32,
    pub ifl: u32,
    pub read_pos: u32,
    pub read_count: u32,
    pub read_trigger: u32,
}

#[repr(C)]
#[derive(qemu_api_macros::Object)]
/// PL011 Device Model in QEMU
pub struct PL011State {
    pub parent_obj: ParentField<SysBusDevice>,
    pub iomem: MemoryRegion,
    #[doc(alias = "chr")]
    pub char_backend: CharBackend,
    pub regs: BqlRefCell<PL011Registers>,
    /// QEMU interrupts
    ///
    /// ```text
    ///  * sysbus MMIO region 0: device registers
    ///  * sysbus IRQ 0: `UARTINTR` (combined interrupt line)
    ///  * sysbus IRQ 1: `UARTRXINTR` (receive FIFO interrupt line)
    ///  * sysbus IRQ 2: `UARTTXINTR` (transmit FIFO interrupt line)
    ///  * sysbus IRQ 3: `UARTRTINTR` (receive timeout interrupt line)
    ///  * sysbus IRQ 4: `UARTMSINTR` (momem status interrupt line)
    ///  * sysbus IRQ 5: `UARTEINTR` (error interrupt line)
    /// ```
    #[doc(alias = "irq")]
    pub interrupts: [InterruptSource; IRQMASK.len()],
    #[doc(alias = "clk")]
    pub clock: Owned<Clock>,
    #[doc(alias = "migrate_clk")]
    pub migrate_clock: bool,
}

// Some C users of this device embed its state struct into their own
// structs, so the size of the Rust version must not be any larger
// than the size of the C one. If this assert triggers you need to
// expand the padding_for_rust[] array in the C PL011State struct.
static_assert!(size_of::<PL011State>() <= size_of::<qemu_api::bindings::PL011State>());

qom_isa!(PL011State : SysBusDevice, DeviceState, Object);

#[repr(C)]
pub struct PL011Class {
    parent_class: <SysBusDevice as ObjectType>::Class,
    /// The byte string that identifies the device.
    device_id: DeviceId,
}

trait PL011Impl: SysBusDeviceImpl + IsA<PL011State> {
    const DEVICE_ID: DeviceId;
}

impl PL011Class {
    fn class_init<T: PL011Impl>(&mut self) {
        self.device_id = T::DEVICE_ID;
        self.parent_class.class_init::<T>();
    }
}

unsafe impl ObjectType for PL011State {
    type Class = PL011Class;
    const TYPE_NAME: &'static CStr = crate::TYPE_PL011;
}

impl PL011Impl for PL011State {
    const DEVICE_ID: DeviceId = DeviceId(&[0x11, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1]);
}

impl ObjectImpl for PL011State {
    type ParentType = SysBusDevice;

    const INSTANCE_INIT: Option<unsafe fn(ParentInit<Self>)> = Some(Self::init);
    const INSTANCE_POST_INIT: Option<fn(&Self)> = Some(Self::post_init);
    const CLASS_INIT: fn(&mut Self::Class) = Self::Class::class_init::<Self>;
}

impl DeviceImpl for PL011State {
    fn properties() -> &'static [Property] {
        &PL011_PROPERTIES
    }
    fn vmsd() -> Option<&'static VMStateDescription> {
        Some(&VMSTATE_PL011)
    }
    const REALIZE: Option<fn(&Self) -> qemu_api::Result<()>> = Some(Self::realize);
}

impl ResettablePhasesImpl for PL011State {
    const HOLD: Option<fn(&Self, ResetType)> = Some(Self::reset_hold);
}

impl SysBusDeviceImpl for PL011State {}

impl PL011Registers {
    pub(self) fn read(&mut self, offset: RegisterOffset) -> (bool, u32) {
        use RegisterOffset::*;

        let mut update = false;
        let result = match offset {
            DR => self.read_data_register(&mut update),
            RSR => u32::from(self.receive_status_error_clear),
            FR => u32::from(self.flags),
            FBRD => self.fbrd,
            ILPR => self.ilpr,
            IBRD => self.ibrd,
            LCR_H => u32::from(self.line_control),
            CR => u32::from(self.control),
            FLS => self.ifl,
            IMSC => u32::from(self.int_enabled),
            RIS => u32::from(self.int_level),
            MIS => u32::from(self.int_level & self.int_enabled),
            ICR => {
                // "The UARTICR Register is the interrupt clear register and is write-only"
                // Source: ARM DDI 0183G 3.3.13 Interrupt Clear Register, UARTICR
                0
            }
            DMACR => self.dmacr,
        };
        (update, result)
    }

    pub(self) fn write(
        &mut self,
        offset: RegisterOffset,
        value: u32,
        char_backend: &CharBackend,
    ) -> bool {
        // eprintln!("write offset {offset} value {value}");
        use RegisterOffset::*;
        match offset {
            DR => return self.write_data_register(value),
            RSR => {
                self.receive_status_error_clear = 0.into();
            }
            FR => {
                // flag writes are ignored
            }
            ILPR => {
                self.ilpr = value;
            }
            IBRD => {
                self.ibrd = value;
            }
            FBRD => {
                self.fbrd = value;
            }
            LCR_H => {
                let new_val: registers::LineControl = value.into();
                // Reset the FIFO state on FIFO enable or disable
                if self.line_control.fifos_enabled() != new_val.fifos_enabled() {
                    self.reset_rx_fifo();
                    self.reset_tx_fifo();
                }
                let update = (self.line_control.send_break() != new_val.send_break()) && {
                    let break_enable = new_val.send_break();
                    let _ = char_backend.send_break(break_enable);
                    self.loopback_break(break_enable)
                };
                self.line_control = new_val;
                self.set_read_trigger();
                return update;
            }
            CR => {
                // ??? Need to implement the enable bit.
                self.control = value.into();
                return self.loopback_mdmctrl();
            }
            FLS => {
                self.ifl = value;
                self.set_read_trigger();
            }
            IMSC => {
                self.int_enabled = Interrupt::from(value);
                return true;
            }
            RIS => {}
            MIS => {}
            ICR => {
                self.int_level &= !Interrupt::from(value);
                return true;
            }
            DMACR => {
                self.dmacr = value;
                if value & 3 > 0 {
                    log_mask_ln!(Log::Unimp, "pl011: DMA not implemented");
                }
            }
        }
        false
    }

    fn read_data_register(&mut self, update: &mut bool) -> u32 {
        self.flags.set_receive_fifo_full(false);
        let c = self.read_fifo[self.read_pos];

        if self.read_count > 0 {
            self.read_count -= 1;
            self.read_pos = (self.read_pos + 1) & (self.fifo_depth() - 1);
        }
        if self.read_count == 0 {
            self.flags.set_receive_fifo_empty(true);
        }
        if self.read_count + 1 == self.read_trigger {
            self.int_level &= !Interrupt::RX;
        }
        self.receive_status_error_clear.set_from_data(c);
        *update = true;
        u32::from(c)
    }

    fn write_data_register(&mut self, value: u32) -> bool {
        if !self.control.enable_uart() {
            log_mask_ln!(Log::GuestError, "PL011 data written to disabled UART");
        }
        if !self.control.enable_transmit() {
            log_mask_ln!(Log::GuestError, "PL011 data written to disabled TX UART");
        }
        // interrupts always checked
        let _ = self.loopback_tx(value.into());
        self.int_level |= Interrupt::TX;
        true
    }

    #[inline]
    #[must_use]
    fn loopback_tx(&mut self, value: registers::Data) -> bool {
        // Caveat:
        //
        // In real hardware, TX loopback happens at the serial-bit level
        // and then reassembled by the RX logics back into bytes and placed
        // into the RX fifo. That is, loopback happens after TX fifo.
        //
        // Because the real hardware TX fifo is time-drained at the frame
        // rate governed by the configured serial format, some loopback
        // bytes in TX fifo may still be able to get into the RX fifo
        // that could be full at times while being drained at software
        // pace.
        //
        // In such scenario, the RX draining pace is the major factor
        // deciding which loopback bytes get into the RX fifo, unless
        // hardware flow-control is enabled.
        //
        // For simplicity, the above described is not emulated.
        self.loopback_enabled() && self.fifo_rx_put(value)
    }

    #[must_use]
    fn loopback_mdmctrl(&mut self) -> bool {
        if !self.loopback_enabled() {
            return false;
        }

        /*
         * Loopback software-driven modem control outputs to modem status inputs:
         *   FR.RI  <= CR.Out2
         *   FR.DCD <= CR.Out1
         *   FR.CTS <= CR.RTS
         *   FR.DSR <= CR.DTR
         *
         * The loopback happens immediately even if this call is triggered
         * by setting only CR.LBE.
         *
         * CTS/RTS updates due to enabled hardware flow controls are not
         * dealt with here.
         */

        self.flags.set_ring_indicator(self.control.out_2());
        self.flags.set_data_carrier_detect(self.control.out_1());
        self.flags.set_clear_to_send(self.control.request_to_send());
        self.flags
            .set_data_set_ready(self.control.data_transmit_ready());

        // Change interrupts based on updated FR
        let mut il = self.int_level;

        il &= !Interrupt::MS;

        if self.flags.data_set_ready() {
            il |= Interrupt::DSR;
        }
        if self.flags.data_carrier_detect() {
            il |= Interrupt::DCD;
        }
        if self.flags.clear_to_send() {
            il |= Interrupt::CTS;
        }
        if self.flags.ring_indicator() {
            il |= Interrupt::RI;
        }
        self.int_level = il;
        true
    }

    fn loopback_break(&mut self, enable: bool) -> bool {
        enable && self.loopback_tx(registers::Data::BREAK)
    }

    fn set_read_trigger(&mut self) {
        self.read_trigger = 1;
    }

    pub fn reset(&mut self) {
        self.line_control.reset();
        self.receive_status_error_clear.reset();
        self.dmacr = 0;
        self.int_enabled = 0.into();
        self.int_level = 0.into();
        self.ilpr = 0;
        self.ibrd = 0;
        self.fbrd = 0;
        self.read_trigger = 1;
        self.ifl = 0x12;
        self.control.reset();
        self.flags.reset();
        self.reset_rx_fifo();
        self.reset_tx_fifo();
    }

    pub fn reset_rx_fifo(&mut self) {
        self.read_count = 0;
        self.read_pos = 0;

        // Reset FIFO flags
        self.flags.set_receive_fifo_full(false);
        self.flags.set_receive_fifo_empty(true);
    }

    pub fn reset_tx_fifo(&mut self) {
        // Reset FIFO flags
        self.flags.set_transmit_fifo_full(false);
        self.flags.set_transmit_fifo_empty(true);
    }

    #[inline]
    pub fn fifo_enabled(&self) -> bool {
        self.line_control.fifos_enabled() == registers::Mode::FIFO
    }

    #[inline]
    pub fn loopback_enabled(&self) -> bool {
        self.control.enable_loopback()
    }

    #[inline]
    pub fn fifo_depth(&self) -> u32 {
        // Note: FIFO depth is expected to be power-of-2
        if self.fifo_enabled() {
            return PL011_FIFO_DEPTH;
        }
        1
    }

    #[must_use]
    pub fn fifo_rx_put(&mut self, value: registers::Data) -> bool {
        let depth = self.fifo_depth();
        assert!(depth > 0);
        let slot = (self.read_pos + self.read_count) & (depth - 1);
        self.read_fifo[slot] = value;
        self.read_count += 1;
        self.flags.set_receive_fifo_empty(false);
        if self.read_count == depth {
            self.flags.set_receive_fifo_full(true);
        }

        if self.read_count == self.read_trigger {
            self.int_level |= Interrupt::RX;
            return true;
        }
        false
    }

    pub fn post_load(&mut self) -> Result<(), ()> {
        /* Sanity-check input state */
        if self.read_pos >= self.read_fifo.len() || self.read_count > self.read_fifo.len() {
            return Err(());
        }

        if !self.fifo_enabled() && self.read_count > 0 && self.read_pos > 0 {
            // Older versions of PL011 didn't ensure that the single
            // character in the FIFO in FIFO-disabled mode is in
            // element 0 of the array; convert to follow the current
            // code's assumptions.
            self.read_fifo[0] = self.read_fifo[self.read_pos];
            self.read_pos = 0;
        }

        self.ibrd &= IBRD_MASK;
        self.fbrd &= FBRD_MASK;

        Ok(())
    }
}

impl PL011State {
    /// Initializes a pre-allocated, uninitialized instance of `PL011State`.
    ///
    /// # Safety
    ///
    /// `self` must point to a correctly sized and aligned location for the
    /// `PL011State` type. It must not be called more than once on the same
    /// location/instance. All its fields are expected to hold uninitialized
    /// values with the sole exception of `parent_obj`.
    unsafe fn init(mut this: ParentInit<Self>) {
        static PL011_OPS: MemoryRegionOps<PL011State> = MemoryRegionOpsBuilder::<PL011State>::new()
            .read(&PL011State::read)
            .write(&PL011State::write)
            .native_endian()
            .impl_sizes(4, 4)
            .build();

        // SAFETY: this and this.iomem are guaranteed to be valid at this point
        MemoryRegion::init_io(
            &mut uninit_field_mut!(*this, iomem),
            &PL011_OPS,
            "pl011",
            0x1000,
        );

        uninit_field_mut!(*this, regs).write(Default::default());

        let clock = DeviceState::init_clock_in(
            &mut this,
            "clk",
            &Self::clock_update,
            ClockEvent::ClockUpdate,
        );
        uninit_field_mut!(*this, clock).write(clock);
    }

    const fn clock_update(&self, _event: ClockEvent) {
        /* pl011_trace_baudrate_change(s); */
    }

    fn post_init(&self) {
        self.init_mmio(&self.iomem);
        for irq in self.interrupts.iter() {
            self.init_irq(irq);
        }
    }

    fn read(&self, offset: hwaddr, _size: u32) -> u64 {
        match RegisterOffset::try_from(offset) {
            Err(v) if (0x3f8..0x400).contains(&(v >> 2)) => {
                let device_id = self.get_class().device_id;
                u64::from(device_id[(offset - 0xfe0) >> 2])
            }
            Err(_) => {
                log_mask_ln!(Log::GuestError, "PL011State::read: Bad offset {offset}");
                0
            }
            Ok(field) => {
                let (update_irq, result) = self.regs.borrow_mut().read(field);
                if update_irq {
                    self.update();
                    self.char_backend.accept_input();
                }
                result.into()
            }
        }
    }

    fn write(&self, offset: hwaddr, value: u64, _size: u32) {
        let mut update_irq = false;
        if let Ok(field) = RegisterOffset::try_from(offset) {
            // qemu_chr_fe_write_all() calls into the can_receive
            // callback, so handle writes before entering PL011Registers.
            if field == RegisterOffset::DR {
                // ??? Check if transmitter is enabled.
                let ch: [u8; 1] = [value as u8];
                // XXX this blocks entire thread. Rewrite to use
                // qemu_chr_fe_write and background I/O callbacks
                let _ = self.char_backend.write_all(&ch);
            }

            update_irq = self
                .regs
                .borrow_mut()
                .write(field, value as u32, &self.char_backend);
        } else {
            log_mask_ln!(
                Log::GuestError,
                "PL011State::write: Bad offset {offset} value {value}"
            );
        }
        if update_irq {
            self.update();
        }
    }

    fn can_receive(&self) -> u32 {
        let regs = self.regs.borrow();
        // trace_pl011_can_receive(s->lcr, s->read_count, r);
        regs.fifo_depth() - regs.read_count
    }

    fn receive(&self, buf: &[u8]) {
        let mut regs = self.regs.borrow_mut();
        if regs.loopback_enabled() {
            // In loopback mode, the RX input signal is internally disconnected
            // from the entire receiving logics; thus, all inputs are ignored,
            // and BREAK detection on RX input signal is also not performed.
            return;
        }

        let mut update_irq = false;
        for &c in buf {
            let c: u32 = c.into();
            update_irq |= regs.fifo_rx_put(c.into());
        }

        // Release the BqlRefCell before calling self.update()
        drop(regs);
        if update_irq {
            self.update();
        }
    }

    fn event(&self, event: Event) {
        let mut update_irq = false;
        let mut regs = self.regs.borrow_mut();
        if event == Event::CHR_EVENT_BREAK && !regs.loopback_enabled() {
            update_irq = regs.fifo_rx_put(registers::Data::BREAK);
        }
        // Release the BqlRefCell before calling self.update()
        drop(regs);

        if update_irq {
            self.update()
        }
    }

    fn realize(&self) -> qemu_api::Result<()> {
        self.char_backend
            .enable_handlers(self, Self::can_receive, Self::receive, Self::event);
        Ok(())
    }

    fn reset_hold(&self, _type: ResetType) {
        self.regs.borrow_mut().reset();
    }

    fn update(&self) {
        let regs = self.regs.borrow();
        let flags = regs.int_level & regs.int_enabled;
        for (irq, i) in self.interrupts.iter().zip(IRQMASK) {
            irq.set(flags.any_set(i));
        }
    }

    pub fn post_load(&self, _version_id: u32) -> Result<(), ()> {
        self.regs.borrow_mut().post_load()
    }
}

/// Which bits in the interrupt status matter for each outbound IRQ line ?
const IRQMASK: [Interrupt; 6] = [
    Interrupt::all(),
    Interrupt::RX,
    Interrupt::TX,
    Interrupt::RT,
    Interrupt::MS,
    Interrupt::E,
];

/// # Safety
///
/// We expect the FFI user of this function to pass a valid pointer for `chr`
/// and `irq`.
#[no_mangle]
pub unsafe extern "C" fn pl011_create(
    addr: u64,
    irq: *mut IRQState,
    chr: *mut Chardev,
) -> *mut DeviceState {
    // SAFETY: The callers promise that they have owned references.
    // They do not gift them to pl011_create, so use `Owned::from`.
    let irq = unsafe { Owned::<IRQState>::from(&*irq) };

    let dev = PL011State::new();
    if !chr.is_null() {
        let chr = unsafe { Owned::<Chardev>::from(&*chr) };
        dev.prop_set_chr("chardev", &chr);
    }
    dev.sysbus_realize();
    dev.mmio_map(0, addr);
    dev.connect_irq(0, &irq);

    // The pointer is kept alive by the QOM tree; drop the owned ref
    dev.as_mut_ptr()
}

#[repr(C)]
#[derive(qemu_api_macros::Object)]
/// PL011 Luminary device model.
pub struct PL011Luminary {
    parent_obj: ParentField<PL011State>,
}

qom_isa!(PL011Luminary : PL011State, SysBusDevice, DeviceState, Object);

unsafe impl ObjectType for PL011Luminary {
    type Class = <PL011State as ObjectType>::Class;
    const TYPE_NAME: &'static CStr = crate::TYPE_PL011_LUMINARY;
}

impl ObjectImpl for PL011Luminary {
    type ParentType = PL011State;

    const CLASS_INIT: fn(&mut Self::Class) = Self::Class::class_init::<Self>;
}

impl PL011Impl for PL011Luminary {
    const DEVICE_ID: DeviceId = DeviceId(&[0x11, 0x00, 0x18, 0x01, 0x0d, 0xf0, 0x05, 0xb1]);
}

impl DeviceImpl for PL011Luminary {}
impl ResettablePhasesImpl for PL011Luminary {}
impl SysBusDeviceImpl for PL011Luminary {}

extern "C" fn pl011_clock_needed(opaque: *mut c_void) -> bool {
    let state = NonNull::new(opaque).unwrap().cast::<PL011State>();
    unsafe { state.as_ref().migrate_clock }
}

/// Migration subsection for [`PL011State`] clock.
static VMSTATE_PL011_CLOCK: VMStateDescription = VMStateDescription {
    name: c"pl011/clock".as_ptr(),
    version_id: 1,
    minimum_version_id: 1,
    needed: Some(pl011_clock_needed),
    fields: vmstate_fields! {
        vmstate_clock!(PL011State, clock),
    },
    ..Zeroable::ZERO
};

extern "C" fn pl011_post_load(opaque: *mut c_void, version_id: c_int) -> c_int {
    let state = NonNull::new(opaque).unwrap().cast::<PL011State>();
    let result = unsafe { state.as_ref().post_load(version_id as u32) };
    if result.is_err() {
        -1
    } else {
        0
    }
}

static VMSTATE_PL011_REGS: VMStateDescription = VMStateDescription {
    name: c"pl011/regs".as_ptr(),
    version_id: 2,
    minimum_version_id: 2,
    fields: vmstate_fields! {
        vmstate_of!(PL011Registers, flags),
        vmstate_of!(PL011Registers, line_control),
        vmstate_of!(PL011Registers, receive_status_error_clear),
        vmstate_of!(PL011Registers, control),
        vmstate_of!(PL011Registers, dmacr),
        vmstate_of!(PL011Registers, int_enabled),
        vmstate_of!(PL011Registers, int_level),
        vmstate_of!(PL011Registers, read_fifo),
        vmstate_of!(PL011Registers, ilpr),
        vmstate_of!(PL011Registers, ibrd),
        vmstate_of!(PL011Registers, fbrd),
        vmstate_of!(PL011Registers, ifl),
        vmstate_of!(PL011Registers, read_pos),
        vmstate_of!(PL011Registers, read_count),
        vmstate_of!(PL011Registers, read_trigger),
    },
    ..Zeroable::ZERO
};

pub static VMSTATE_PL011: VMStateDescription = VMStateDescription {
    name: c"pl011".as_ptr(),
    version_id: 2,
    minimum_version_id: 2,
    post_load: Some(pl011_post_load),
    fields: vmstate_fields! {
        vmstate_unused!(core::mem::size_of::<u32>()),
        vmstate_struct!(PL011State, regs, &VMSTATE_PL011_REGS, BqlRefCell<PL011Registers>),
    },
    subsections: vmstate_subsections! {
        VMSTATE_PL011_CLOCK
    },
    ..Zeroable::ZERO
};

qemu_api::declare_properties! {
    PL011_PROPERTIES,
    qemu_api::define_property!(
        c"chardev",
        PL011State,
        char_backend,
        unsafe { &qdev_prop_chr },
        CharBackend
    ),
    qemu_api::define_property!(
        c"migrate-clk",
        PL011State,
        migrate_clock,
        unsafe { &qdev_prop_bool },
        bool,
        default = true
    ),
}
