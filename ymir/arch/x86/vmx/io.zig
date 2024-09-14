const std = @import("std");
const log = std.log.scoped(.vmio);

const vmx = @import("../vmx.zig");
const QualIo = @import("qual.zig").QualIo;
const Vcpu = vmx.Vcpu;
const VmxError = vmx.VmxError;
const sr = @import("../serial.zig");
const am = @import("../asm.zig");

pub fn handleIo(vcpu: *Vcpu, qual: QualIo) VmxError!void {
    return switch (qual.direction) {
        .in => try handleIoIn(vcpu, qual),
        .out => try handleIoOut(vcpu, qual),
    };
}

fn handleIoIn(vcpu: *Vcpu, qual: QualIo) VmxError!void {
    const regs = &vcpu.guest_regs;
    switch (qual.port) {
        0x0040...0x0048 => try handlePitIn(vcpu, qual),
        0x03F8...0x0400 => try handleSerialIn(vcpu, qual),
        0x0CFC => regs.rax = 0, // PCI CONFIG_DATA, Unimplemented.
        0x0CFE => {}, // TODO: PCI ?
        else => {
            log.err("Unhandled I/O-in port: 0x{X}", .{qual.port});
            log.err("I/O size: {s}", .{@tagName(qual.size)});
            unreachable;
        },
    }
}

fn handleIoOut(vcpu: *Vcpu, qual: QualIo) VmxError!void {
    switch (qual.port) {
        0x0040...0x0048 => try handlePitOut(vcpu, qual),
        0x3C0, 0x3C2, 0x3C4, 0x3C6, 0x3C8, 0x3CE, 0x3D4, 0x3D5 => {}, // VGA. ignore
        0x03F8...0x0400 => try handleSerialOut(vcpu, qual),
        0x0CF8 => {}, // PCI CONFIG_ADDRESS. ignore
        else => {
            log.err("Unhandled I/O-out port: 0x{X}", .{qual.port});
            log.err("I/O size: {s}", .{@tagName(qual.size)});
            unreachable;
        },
    }
}

fn handleSerialIn(vcpu: *Vcpu, qual: QualIo) VmxError!void {
    const regs = &vcpu.guest_regs;
    switch (qual.port) {
        // Line Control Register (MSB is DLAB).
        0x3FB => regs.rax = 0x00, // ignore
        // Line Status Register.
        0x3FD => regs.rax = 0b0110_0000, // THRE / TEMT. Always DR clear.
        else => {
            log.err("Unsupported I/O-in to the first serial port: 0x{X}", .{qual.port});
            unreachable;
        },
    }
}

fn handleSerialOut(vcpu: *Vcpu, qual: QualIo) VmxError!void {
    const regs = &vcpu.guest_regs;
    switch (qual.port) {
        // Transmit buffer.
        0x3F8 => sr.writeByte(@truncate(regs.rax), .com1),
        // Interrupt Enable Register.
        0x3F9 => {}, // ignore
        // FIFO control registers.
        0x3FA => {}, // ignore
        // Line Control Register (MSB is DLAB).
        0x3FB => {}, // ignore
        // Modem Control Register.
        0x3FC => {}, // ignore
        else => {
            log.err("Unsupported I/O-out to the first serial port: 0x{X}", .{qual.port});
            unreachable;
        },
    }
}

fn handlePitIn(vcpu: *Vcpu, qual: QualIo) VmxError!void {
    const regs = &vcpu.guest_regs;
    // Pass-through.
    switch (qual.size) {
        .byte => regs.rax = @as(u64, am.inb(qual.port)),
        .word => regs.rax = @as(u64, am.inw(qual.port)),
        .dword => regs.rax = @as(u64, am.inl(qual.port)),
    }
}

fn handlePitOut(vcpu: *Vcpu, qual: QualIo) VmxError!void {
    // Pass-through.
    switch (qual.size) {
        .byte => am.outb(@truncate(vcpu.guest_regs.rax), qual.port),
        .word => am.outw(@truncate(vcpu.guest_regs.rax), qual.port),
        .dword => am.outl(@truncate(vcpu.guest_regs.rax), qual.port),
    }
}
