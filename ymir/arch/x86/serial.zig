//! Serial 8250 UART.

const ymir = @import("ymir");
const am = @import("asm.zig");

const Serial = ymir.serial.Serial;

/// Available serial ports.
pub const Ports = enum(u16) {
    COM1 = 0x3F8,
    COM2 = 0x2F8,
    COM3 = 0x3E8,
    COM4 = 0x2E8,
};

/// IRQs to which serial ports can generate interrupts.
const Irq = struct {
    pub const COM1 = 4;
    pub const COM2 = 3;
    pub const COM3 = 4;
    pub const COM4 = 3;
};

const DIVISOR_LATCH_NUMERATOR = 115200;
const DEFAULT_BAUD_RATE = 9600;

const UartOffset = struct {
    /// Transmitter Holding Buffer: DLAB=0, W
    pub const TXR = 0;
    /// Receiver Buffer: DLAB=0, R
    pub const RXR = 0;
    /// Divisor Latch Low Byte: DLAB=1, R/W
    pub const DLL = 0;
    /// Interrupt Enable Register: DLAB=0, R/W
    pub const IER = 1;
    /// Divisor Latch High Byte: DLAB=1, R/W
    pub const DLM = 1;
    /// Interrupt Identification Register: DLAB=X, R
    pub const IIR = 2;
    /// FIFO Control Register: DLAB=X, W
    pub const FCR = 2;
    /// Line Control Register: DLAB=X, R/W
    pub const LCR = 3;
    /// Line Control Register: DLAB=0, R/W
    pub const MCR = 4;
    /// Line Status Register: DLAB=X, R
    pub const LSR = 5;
    /// Modem Status Register: DLAB=X, R
    pub const MSR = 6;
    /// Scratch Register: DLAB=X, R/W
    pub const SR = 7;
};

/// Initialize a serial console, then set a write-function to `Serial.write_fn`.
pub fn initSerial(serial: *Serial, port: Ports, baud: u32) void {
    const p = @intFromEnum(port);
    am.outb(0b00_000_0_00, p + UartOffset.LCR); // 8n1: no paritiy, 1 stop bit, 8 data bit
    am.outb(0, p + UartOffset.IER); // Disable interrupts
    am.outb(0, p + UartOffset.FCR); // Disable FIFO
    am.outb(0b0000_0011, p + UartOffset.MCR); // Request-to-send, Data-terminal-ready

    // set baud rate
    const divisor = DIVISOR_LATCH_NUMERATOR / baud;
    const c = am.inb(p + UartOffset.LCR);
    am.outb(c | 0b1000_0000, p + UartOffset.LCR); // Enable DLAB
    am.outb(@truncate(divisor & 0xFF), p + UartOffset.DLL);
    am.outb(@truncate((divisor >> 8) & 0xFF), p + UartOffset.DLM);
    am.outb(c & 0b0111_1111, p + UartOffset.LCR); // Disable DLAB

    getSerial(serial, port);
}

/// Get a serial console, then set a write-function to `Serial.write_fn`.
/// You MUST ensure that the console of the `port` is initialized before calling this function.
pub fn getSerial(serial: *Serial, port: Ports) void {
    serial._write_fn = switch (port) {
        Ports.COM1 => writeByteCom1,
        Ports.COM2 => writeByteCom2,
        Ports.COM3 => writeByteCom3,
        Ports.COM4 => writeByteCom5,
    };
    serial._read_fn = switch (port) {
        Ports.COM1 => readByteCom1,
        Ports.COM2 => readByteCom2,
        Ports.COM3 => readByteCom3,
        Ports.COM4 => readByteCom4,
    };
}

pub fn enableInterrupt(port: Ports) void {
    const p = @intFromEnum(port);
    am.outb(0b0000_0001, p + UartOffset.IER); // Receive data available interrupt
}

fn writeByte(byte: u8, port: Ports) void {
    // wait until the transmitter holding buffer is empty
    while (am.inb(@intFromEnum(port) + UartOffset.LSR) & 0b0010_0000 == 0) {
        am.relax();
    }

    // put char to the transmitter holding buffer
    am.outb(byte, @intFromEnum(port));
}

fn writeByteCom1(byte: u8) void {
    writeByte(byte, Ports.COM1);
}

fn writeByteCom2(byte: u8) void {
    writeByte(byte, Ports.COM2);
}

fn writeByteCom3(byte: u8) void {
    writeByte(byte, Ports.COM3);
}

fn writeByteCom5(byte: u8) void {
    writeByte(byte, Ports.COM4);
}

fn readByte(port: Ports) u8 {
    // wait until the receiver buffer is not empty
    while (am.inb(@intFromEnum(port) + UartOffset.LSR) & 0b0000_0001 == 0) {
        am.relax();
    }

    // read char from the receiver buffer
    return am.inb(@intFromEnum(port));
}

fn readByteCom1() u8 {
    return readByte(Ports.COM1);
}

fn readByteCom2() u8 {
    return readByte(Ports.COM2);
}

fn readByteCom3() u8 {
    return readByte(Ports.COM3);
}

fn readByteCom4() u8 {
    return readByte(Ports.COM4);
}
