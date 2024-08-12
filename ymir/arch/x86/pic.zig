//! Legacy Intel 8259 Programmable Interrupt Controller (PIC) driver.
//!
//! You can check the status of the PIC in QEMU by running: info pic
//!
//! Reference:
//! - https://wiki.osdev.org/8259_PIC

const am = @import("asm.zig");

/// Interrupt vector for the primary PIC.
/// Must be divisible by 8.
pub const primary_vector_offset: usize = 32;
/// Interrupt vector for the secondary PIC.
/// Must be divisible by 8.
pub const secondary_vector_offset: usize = primary_vector_offset + 8;

// I/O Ports
const primary_command_port: u16 = 0x20;
const primary_data_port: u16 = primary_command_port + 1;
const secondary_command_port: u16 = 0xA0;
const secondary_data_port: u16 = secondary_command_port + 1;

// Commands
/// Indicates that ICW4 is needed.
const icw1_icw4 = 0x01;
/// Single (cascade) mode.
const icw1_single = 0x02;
/// Call address interval 4 (8).
const icw1_interval4 = 0x04;
/// Level triggered (edge) mode.
const icw1_level = 0x08;
/// Initialization command.
const icw1_init = 0x10;
/// 8086/88 mode.
const icw4_8086 = 0x01;
/// Auto EOI.
const icw4_auto = 0x02;
/// Buffered mode/secondary.
const icw4_buf_secondary = 0x08;
/// Buffered mode/primary.
const icw4_buf_primary = 0x0C;
/// End-of-interrupt command.
const eoi = 0x20;

/// Initialize the PIC remapping its interrupt vectors.
/// You MUST call this function before using the PIC.
pub fn init() void {
    // Save the current interrupt mask.
    const mask_primary = am.inb(primary_data_port);
    const mask_secondary = am.inb(secondary_data_port);

    // Start initialization sequence.
    am.outb(icw1_init | icw1_icw4, primary_command_port);
    am.relax();
    am.outb(icw1_init | icw1_icw4, secondary_command_port);
    am.relax();

    // Set the vector offsets.
    am.outb(primary_vector_offset, primary_data_port);
    am.relax();
    am.outb(secondary_vector_offset, secondary_data_port);
    am.relax();

    // Tell primary PIC that there is a slave PIC at IRQ2.
    am.outb(4, primary_data_port);
    am.relax();
    // Tell secondary PIC its cascade identity.
    am.outb(2, secondary_data_port);
    am.relax();

    // Set the mode.
    am.outb(icw4_8086, primary_data_port);
    am.relax();
    am.outb(icw4_8086, secondary_data_port);
    am.relax();

    // Restore the saved interrupt mask.
    am.outb(mask_primary, primary_data_port);
    am.outb(mask_secondary, secondary_data_port);
}

/// Mask the given IRQ line.
pub fn setMask(irq: IrqLine) void {
    const irq_value: u8 = @intFromEnum(irq);
    const port = if (irq_value < 8) primary_data_port else secondary_data_port;
    const irq_line = if (irq_value < 8) irq_value else irq_value - 8;
    am.outb(am.inb(port) | (@as(u8, 1) << @truncate(irq_line)), port);
}

/// Unset the mask of the given IRQ line.
pub fn unsetMask(irq: IrqLine) void {
    const irq_value: u8 = @intFromEnum(irq);
    const port = if (irq_value < 8) primary_data_port else secondary_data_port;
    const irq_line = if (irq_value < 8) irq_value else irq_value - 8;
    am.outb(am.inb(port) & (~(@as(u8, 1) << @truncate(irq_line))), port);
}

/// Notify the end of interrupt (EOI) to the PIC.
pub fn notifyEoi(irq: IrqLine) void {
    if (@intFromEnum(irq) >= 8) {
        am.outb(eoi, secondary_command_port);
    }
    am.outb(eoi, primary_command_port);
}

/// Line numbers for the PIC.
pub const IrqLine = enum(u8) {
    /// Timer
    Timer = 0,
    /// Keyboard
    Keyboard = 1,
    /// Secondary PIC
    Secondary = 2,
    /// Serial Port 2
    Serial2 = 3,
    /// Serial Port 1
    Serial1 = 4,
    /// Parallel Port 2/3
    Parallel23 = 5,
    /// Floppy Disk
    Floppy = 6,
    /// Parallel Port 1
    Parallel1 = 7,
    /// Real Time Clock
    Rtc = 8,
    /// ACPI
    Acpi = 9,
    /// Available 1
    Open1 = 10,
    /// Available 2
    Open2 = 11,
    /// Mouse
    Mouse = 12,
    /// Coprocessor
    Cop = 13,
    /// Primary ATA
    PrimaryAta = 14,
    /// Secondary ATA
    SecondaryAta = 15,
};
