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
        0x0020, 0x0021 => try handlePicIn(vcpu, qual),
        0x0040...0x0048 => try handlePitIn(vcpu, qual),
        0x0070, 0x0071 => regs.rax = 0, // RTC. Unimplemented.
        0x00A0, 0x00A1 => try handlePicIn(vcpu, qual),
        0x03B0...0x03E0 => regs.rax = 0, // VGA. Uniimplemented.
        0x03F8...0x0400 => try handleSerialIn(vcpu, qual),
        0x0CFC => regs.rax = 0, // PCI CONFIG_DATA, Unimplemented.
        0x0CFE => regs.rax = 0, // TODO: PCI ?
        else => {
            log.err("Unhandled I/O-in port: 0x{X}", .{qual.port});
            log.err("I/O size: {s}", .{@tagName(qual.size)});
            unreachable;
        },
    }
}

fn handleIoOut(vcpu: *Vcpu, qual: QualIo) VmxError!void {
    switch (qual.port) {
        0x0020, 0x0021 => try handlePicOut(vcpu, qual),
        0x0040...0x0048 => try handlePitOut(vcpu, qual),
        0x0070, 0x0071 => {}, // RTC. Unimplemented.
        0x80...0x90 => {}, // DMA. Unimplemented.
        0x00A0, 0x00A1 => try handlePicOut(vcpu, qual),
        0x03B0...0x03E0 => {}, // VGA. Uniimplemented.
        0x03F8...0x0400 => try handleSerialOut(vcpu, qual),
        0x0CF8 => {}, // PCI CONFIG_ADDRESS. ignore
        else => {
            log.err("Unhandled I/O-out port: 0x{X}", .{qual.port});
            log.err("I/O size: {s}", .{@tagName(qual.size)});
            unreachable;
        },
    }
}

// =============================================================================

fn handleSerialIn(vcpu: *Vcpu, qual: QualIo) VmxError!void {
    const regs = &vcpu.guest_regs;
    switch (qual.port) {
        // Interrupt Enable Register (DLAB=1) / Divisor Latch High Register (DLAB=0).
        0x3F9 => regs.rax = am.inb(qual.port),
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

fn handlePicIn(vcpu: *Vcpu, qual: QualIo) VmxError!void {
    if (qual.size != .byte) {
        log.err("Unsupported I/O-in size to PIC: size={s}, port=0x{X}", .{ @tagName(qual.size), qual.port });
        unreachable;
    }

    const regs = &vcpu.guest_regs;
    const pic = &vcpu.pic;

    switch (qual.port) {
        // Primary PIC data.
        0x21 => switch (pic.primary_phase) {
            .uninitialized, .inited => regs.rax = pic.primary_mask,
            else => unreachable,
        },
        else => {
            log.err("Unsupported I/O-in to PIC: port=0x{X}", .{qual.port});
            unreachable;
        },
    }
}

fn handlePicOut(vcpu: *Vcpu, qual: QualIo) VmxError!void {
    if (qual.size != .byte) {
        log.err("Unsupported I/O-out size to PIC: size={s}, port=0x{X}", .{ @tagName(qual.size), qual.port });
        unreachable;
    }

    const regs = &vcpu.guest_regs;
    const pic = &vcpu.pic;
    const dx: u8 = @truncate(regs.rax);

    switch (qual.port) {
        // Primary PIC command.
        0x20 => if (dx == 0x11) {
            pic.primary_phase = .phase1;
        } else {
            log.err("Unsupported command to primary PIC: port=0x{X}", .{dx});
            unreachable;
        },
        // Primary PIC data.
        0x21 => switch (pic.primary_phase) {
            .uninitialized, .inited => pic.primary_mask = dx,
            .phase1 => {
                log.info("Primary PIC vector offset: 0x{X}", .{dx});
                pic.primary_base = dx;
                pic.primary_phase = .phase2;
            },
            .phase2 => if (dx != (1 << 2)) {
                log.err("Invalid secondary PIC location: 0x{X}", .{dx});
                unreachable;
            } else {
                pic.primary_phase = .phase3;
            },
            .phase3 => pic.primary_phase = .inited,
        },
        // Secondary PIC command.
        0xA0 => if (dx == 0x11) {
            pic.secondary_phase = .phase1;
        } else {
            log.err("Unsupported command to secondary PIC: port=0x{X}", .{dx});
            unreachable;
        },
        // Secondary PIC data.
        0xA1 => switch (pic.secondary_phase) {
            .uninitialized, .inited => pic.secondary_mask = dx,
            .phase1 => {
                log.info("Secondary PIC vector offset: 0x{X}", .{dx});
                pic.secondary_base = dx;
                pic.secondary_phase = .phase2;
            },
            .phase2 => if (dx != 2) {
                log.err("Invalid PIC cascade identity: 0x{X}", .{dx});
                unreachable;
            } else {
                pic.secondary_phase = .phase3;
            },
            .phase3 => pic.secondary_phase = .inited,
        },
        else => {
            log.err("Unsupported I/O-out to PIC: port=0x{X}", .{qual.port});
            unreachable;
        },
    }
}

/// 8259 Programmable Interrupt Controller.
pub const Pic = struct {
    /// Mask of the primary PIC.
    primary_mask: u8,
    /// Mask of the secondary PIC.
    secondary_mask: u8,
    /// Initialization phase of the primary PIC.
    primary_phase: InitPhase = .uninitialized,
    /// Initialization phase of the secondary PIC.
    secondary_phase: InitPhase = .uninitialized,
    /// Vector offset of the primary PIC.
    primary_base: u8 = 0,
    /// Vector offset of the secondary PIC.
    secondary_base: u8 = 0,

    const InitPhase = enum {
        uninitialized,
        phase1,
        phase2,
        phase3,
        inited,
    };

    pub fn new() Pic {
        return Pic{
            .primary_mask = 0xFF,
            .secondary_mask = 0xFF,
        };
    }
};