//! Legacy Intel 8259 Programmable Interrupt Controller (PIC) driver.
//!
//! You can check the status of the PIC in QEMU by running: info pic
//!
//! Reference:
//! - https://wiki.osdev.org/8259_PIC
//! - https://pdos.csail.mit.edu/6.828/2014/readings/hardware/8259A.pdf

const am = @import("asm.zig");

/// Interrupt vector for the primary PIC.
/// Must be divisible by 8.
pub const primary_vector_offset: usize = 32;
/// Interrupt vector for the secondary PIC.
/// Must be divisible by 8.
pub const secondary_vector_offset: usize = primary_vector_offset + 8;

/// Primary command port
const primary_command_port: u16 = 0x20;
/// Primary data port
const primary_data_port: u16 = primary_command_port + 1;
/// Secondary command port
const secondary_command_port: u16 = 0xA0;
/// Secondary data port
const secondary_data_port: u16 = secondary_command_port + 1;

/// Command constants
const cmd = struct {
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
};

// PS/2 I/O Ports
const ps2_data_port: u16 = 0x60;
const ps2_status_port: u16 = 0x64;
const ps2_command_port: u16 = ps2_status_port;

/// Initialize the PIC remapping its interrupt vectors.
/// All interrupts are masked after initialization.
/// You MUST call this function before using the PIC.
pub fn init() void {
    // We have to disable interrupts to prevent PIC-driven interrupts before registering handlers.
    am.cli();
    defer am.sti();

    // Start initialization sequence.
    am.outb(cmd.icw1_init | cmd.icw1_icw4, primary_command_port);
    am.relax();
    am.outb(cmd.icw1_init | cmd.icw1_icw4, secondary_command_port);
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
    am.outb(cmd.icw4_8086, primary_data_port);
    am.relax();
    am.outb(cmd.icw4_8086, secondary_data_port);
    am.relax();

    // Mask all IRQ lines.
    am.outb(0xFF, primary_data_port);
    am.outb(0xFF, secondary_data_port);
}

/// Mask the given IRQ line.
pub fn setMask(irq: IrqLine) void {
    const port = if (irq.isPrimary()) primary_data_port else secondary_data_port;
    const irq_line = irq.delta();
    am.outb(am.inb(port) | (@as(u8, 1) << @truncate(irq_line)), port);
}

/// Unset the mask of the given IRQ line.
pub fn unsetMask(irq: IrqLine) void {
    const port = if (irq.isPrimary()) primary_data_port else secondary_data_port;
    const irq_line = irq.delta();
    am.outb(am.inb(port) & ~((@as(u8, 1) << @truncate(irq_line))), port);
}

/// Notify the end of interrupt (EOI) to the PIC.
/// This function uses specific-EOI.
pub fn notifyEoi(irq: IrqLine) void {
    am.outb(
        eoiOcw2Value(irq),
        if (irq.isPrimary()) primary_command_port else secondary_command_port,
    );
}

/// Get IRQ mask from the PIC.
pub inline fn getIrqMask() u16 {
    const val1: u16 = am.inb(primary_data_port);
    const val2: u16 = am.inb(secondary_data_port);
    return (val2 << 8) | val1;
}

/// Set IRQ mask to the PIC.
pub inline fn setIrqMask(mask: u16) void {
    am.outb(@truncate(mask), primary_data_port);
    am.outb(@truncate(mask >> 8), secondary_data_port);
}

/// Get the OCW2 value for a specific EOI to the given IRQ.
inline fn eoiOcw2Value(irq: IrqLine) u8 {
    return 0x60 + irq.delta();
}

/// Line numbers for the PIC.
pub const IrqLine = enum(u8) {
    /// Timer
    timer = 0,
    /// Keyboard
    keyboard = 1,
    /// Secondary PIC
    secondary = 2,
    /// Serial Port 2
    serial2 = 3,
    /// Serial Port 1
    serial1 = 4,
    /// Parallel Port 2/3
    parallel23 = 5,
    /// Floppy Disk
    floppy = 6,
    /// Parallel Port 1
    parallel1 = 7,
    /// Real Time Clock
    rtc = 8,
    /// ACPI
    acpi = 9,
    /// Available 1
    open1 = 10,
    /// Available 2
    open2 = 11,
    /// Mouse
    mouse = 12,
    /// Coprocessor
    cop = 13,
    /// Primary ATA
    primary_ata = 14,
    /// Secondary ATA
    secondary_ata = 15,

    /// Return true if the IRQ belongs to the primary PIC.
    pub fn isPrimary(self: IrqLine) bool {
        return @intFromEnum(self) < 8;
    }

    /// Get the offset of the IRQ within the PIC.
    pub fn delta(self: IrqLine) u8 {
        return if (self.isPrimary()) @intFromEnum(self) else (@intFromEnum(self) - 8);
    }
};
