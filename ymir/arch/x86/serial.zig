//! Serial 8250 UART.

const ymir = @import("ymir");
const bits = ymir.bits;
const am = @import("asm.zig");

const Serial = ymir.serial.Serial;

/// Available serial ports.
pub const Ports = enum(u16) {
    com1 = 0x3F8,
    com2 = 0x2F8,
    com3 = 0x3E8,
    com4 = 0x2E8,
};

/// IRQs to which serial ports can generate interrupts.
const Irq = struct {
    pub const com1 = 4;
    pub const com2 = 3;
    pub const com3 = 4;
    pub const com4 = 3;
};

const divisor_latch_numerator = 115200;
const default_baud_rate = 9600;

const offsets = struct {
    /// Transmitter Holding Buffer: DLAB=0, W
    pub const txr = 0;
    /// Receiver Buffer: DLAB=0, R
    pub const rxr = 0;
    /// Divisor Latch Low Byte: DLAB=1, R/W
    pub const dll = 0;
    /// Interrupt Enable Register: DLAB=0, R/W
    pub const ier = 1;
    /// Divisor Latch High Byte: DLAB=1, R/W
    pub const dlm = 1;
    /// Interrupt Identification Register: DLAB=X, R
    pub const iir = 2;
    /// FIFO Control Register: DLAB=X, W
    pub const fcr = 2;
    /// Line Control Register: DLAB=X, R/W
    pub const lcr = 3;
    /// Line Control Register: DLAB=0, R/W
    pub const mcr = 4;
    /// Line Status Register: DLAB=X, R
    pub const lsr = 5;
    /// Modem Status Register: DLAB=X, R
    pub const msr = 6;
    /// Scratch Register: DLAB=X, R/W
    pub const sr = 7;
};

/// Initialize a serial console, then set a write-function to `Serial.write_fn`.
pub fn initSerial(serial: *Serial, port: Ports, baud: u32) void {
    const p = @intFromEnum(port);
    am.outb(0b00_000_0_00, p + offsets.lcr); // 8n1: no parity, 1 stop bit, 8 data bit
    am.outb(0, p + offsets.ier); // Disable interrupts
    am.outb(0, p + offsets.fcr); // Disable FIFO

    // Set baud rate
    const divisor = divisor_latch_numerator / baud;
    const c = am.inb(p + offsets.lcr);
    am.outb(c | 0b1000_0000, p + offsets.lcr); // Enable DLAB
    am.outb(@truncate(divisor & 0xFF), p + offsets.dll);
    am.outb(@truncate((divisor >> 8) & 0xFF), p + offsets.dlm);
    am.outb(c & 0b0111_1111, p + offsets.lcr); // Disable DLAB

    getSerial(serial, port);
}

/// Get a serial console, then set a write-function to `Serial.write_fn`.
/// You MUST ensure that the console of the `port` is initialized before calling this function.
pub fn getSerial(serial: *Serial, port: Ports) void {
    serial._write_fn = switch (port) {
        .com1 => writeByteCom1,
        .com2 => writeByteCom2,
        .com3 => writeByteCom3,
        .com4 => writeByteCom4,
    };
    serial._read_fn = switch (port) {
        .com1 => tryReadByteCom1,
        .com2 => tryReadByteCom2,
        .com3 => tryReadByteCom3,
        .com4 => tryReadByteCom4,
    };
}

/// Enable serial console interrupt for Rx-available and Tx-empty.
pub fn enableInterrupt(port: Ports) void {
    var ie = am.inb(@intFromEnum(port) + offsets.ier);
    ie |= 0b0000_0011; // Rx-available, Tx-empty
    am.outb(ie, @intFromEnum(port) + offsets.ier); // Rx-available, Tx-empty
}

/// Check if the given port is any of serial ports.
pub fn isSerialPort(port: u16) bool {
    inline for (@typeInfo(Ports).@"enum".fields) |field| {
        if (field.value == port) return true;
    }
    return false;
}

/// Write a single byte to the serial console.
pub fn writeByte(byte: u8, port: Ports) void {
    // Wait until the transmitter holding buffer is empty
    while (!bits.isset(am.inb(@intFromEnum(port) + offsets.lsr), 5)) {
        am.relax();
    }

    // Put char to the transmitter holding buffer
    am.outb(byte, @intFromEnum(port));
}

fn writeByteCom1(byte: u8) void {
    writeByte(byte, .com1);
}

fn writeByteCom2(byte: u8) void {
    writeByte(byte, .com2);
}

fn writeByteCom3(byte: u8) void {
    writeByte(byte, .com3);
}

fn writeByteCom4(byte: u8) void {
    writeByte(byte, .com4);
}

/// Read a byte from Rx buffer.
/// If Rx buffer is empty, return null.
fn tryReadByte(port: Ports) ?u8 {
    // Check if Rx buffer is not empty
    if (!bits.isset(am.inb(@intFromEnum(port) + offsets.lsr), 0)) {
        return null;
    }

    // read char from the receiver buffer
    return am.inb(@intFromEnum(port));
}

fn tryReadByteCom1() ?u8 {
    return tryReadByte(.com1);
}

fn tryReadByteCom2() ?u8 {
    return tryReadByte(.com2);
}

fn tryReadByteCom3() ?u8 {
    return tryReadByte(.com3);
}

fn tryReadByteCom4() ?u8 {
    return tryReadByte(.com4);
}
