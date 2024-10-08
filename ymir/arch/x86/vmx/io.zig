const std = @import("std");
const log = std.log.scoped(.vmio);

const vmx = @import("../vmx.zig");
const QualIo = @import("qual.zig").QualIo;
const Vcpu = vmx.Vcpu;
const VmxError = vmx.VmxError;
const sr = @import("../serial.zig");
const am = @import("../asm.zig");
const IrqLine = @import("../pic.zig").IrqLine;

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
        0x0040...0x0047 => try handlePitIn(vcpu, qual),
        0x0060...0x64 => regs.rax = 0, // PS/2. Unimplemented.
        0x0070, 0x0071 => regs.rax = 0, // RTC. Unimplemented.
        0x0080...0x008F => {}, // DMA. Unimplemented.
        0x00A0, 0x00A1 => try handlePicIn(vcpu, qual),
        0x02E8...0x02EF => {}, // Fourth serial port. Ignore.
        0x02F8...0x02FF => {}, // Second serial port. Ignore.
        0x03B0...0x03DF => regs.rax = 0, // VGA. Uniimplemented.
        0x03E8...0x03EF => {}, // Third serial port. Ignore.
        0x03F8...0x03FF => try handleSerialIn(vcpu, qual),
        0x0CF8...0x0CFB => try vcpu.pci.in(vcpu, qual.port),
        0x0CFC...0x0CFF => try vcpu.pci.in(vcpu, qual.port),
        0xC000...0xCFFF => {}, // Old PCI. Ignore.
        else => {
            log.err("Unhandled I/O-in port: 0x{X}", .{qual.port});
            log.err("I/O size: {s}", .{@tagName(qual.size)});
            vcpu.abort();
        },
    }
}

fn handleIoOut(vcpu: *Vcpu, qual: QualIo) VmxError!void {
    switch (qual.port) {
        0x0020, 0x0021 => try handlePicOut(vcpu, qual),
        0x0040...0x0047 => try handlePitOut(vcpu, qual),
        0x0060...0x64 => {}, // PS/2. Unimplemented.
        0x0070, 0x0071 => {}, // RTC. Unimplemented.
        0x0080...0x008F => {}, // DMA. Unimplemented.
        0x00A0, 0x00A1 => try handlePicOut(vcpu, qual),
        0x2E8...0x2EF => {}, // Fourth serial port. Ignore.
        0x02F8...0x02FF => {}, // Second serial port. Ignore.
        0x03B0...0x03DF => {}, // VGA. Uniimplemented.
        0x03F8...0x03FF => try handleSerialOut(vcpu, qual),
        0x3E8...0x3EF => {}, // Third serial port. Ignore.
        0x0CF8...0x0CFB => try vcpu.pci.out(vcpu, qual.port),
        0x0CFC...0x0CFF => try vcpu.pci.out(vcpu, qual.port),
        0xC000...0xCFFF => {}, // Old PCI. Ignore.
        else => {
            log.err("Unhandled I/O-out port: 0x{X}", .{qual.port});
            log.err("I/O size: {s}", .{@tagName(qual.size)});
            vcpu.abort();
        },
    }
}

// =============================================================================

fn handleSerialIn(vcpu: *Vcpu, qual: QualIo) VmxError!void {
    const regs = &vcpu.guest_regs;
    switch (qual.port) {
        // Receive buffer.
        0x3F8 => regs.rax = am.inb(qual.port), // pass-through
        // Interrupt Enable Register (DLAB=1) / Divisor Latch High Register (DLAB=0).
        0x3F9 => regs.rax = vcpu.serial.ier,
        // Interrupt Identification Register.
        0x3FA => regs.rax = am.inb(qual.port), // pass-through
        // Line Control Register (MSB is DLAB).
        0x3FB => regs.rax = 0x00, // ignore
        // Modem Control Register.
        0x3FC => regs.rax = vcpu.serial.mcr,
        // Line Status Register.
        0x3FD => regs.rax = am.inb(qual.port), // pass-through
        // Modem Status Register.
        0x3FE => regs.rax = vcpu.serial.msr,
        // Scratch Register.
        0x3FF => regs.rax = 0, // 8250
        else => {
            log.err("Unsupported I/O-in to the first serial port: 0x{X}", .{qual.port});
            vcpu.abort();
        },
    }
}

fn handleSerialOut(vcpu: *Vcpu, qual: QualIo) VmxError!void {
    const regs = &vcpu.guest_regs;
    switch (qual.port) {
        // Transmit buffer.
        0x3F8 => {
            sr.writeByte(@truncate(regs.rax), .com1);
            // If "TX empty" interrupt is enabled, set the pending IRQ.
            if (vcpu.serial.ier & 0b0010 != 0) {
                vcpu.pending_irq |= 1 << @intFromEnum(IrqLine.serial1);
            }
        },
        // Interrupt Enable Register.
        0x3F9 => vcpu.serial.ier = @truncate(regs.rax),
        // FIFO control registers.
        0x3FA => {}, // ignore
        // Line Control Register (MSB is DLAB).
        0x3FB => {}, // ignore
        // Modem Control Register.
        0x3FC => vcpu.serial.mcr = @truncate(regs.rax),
        // Modem Status Register.
        0x3FE => vcpu.serial.msr = @truncate(regs.rax),
        // Scratch Register.
        0x3FF => {}, // ignore
        else => {
            log.err("Unsupported I/O-out to the first serial port: 0x{X}", .{qual.port});
            vcpu.abort();
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
        vcpu.abort();
    }

    const regs = &vcpu.guest_regs;
    const pic = &vcpu.pic;

    switch (qual.port) {
        // Primary PIC data.
        0x21 => switch (pic.primary_phase) {
            .uninitialized, .inited => regs.rax = pic.primary_mask,
            else => {
                log.err("Unsupported I/O-in to primary PIC: phase={s}", .{@tagName(pic.primary_phase)});
                vcpu.abort();
            },
        },
        // Secondary PIC data.
        0xA1 => switch (pic.secondary_phase) {
            .uninitialized, .inited => regs.rax = pic.secondary_mask,
            else => {
                log.err("Unsupported I/O-in to secondary PIC: phase={s}", .{@tagName(pic.secondary_phase)});
                vcpu.abort();
            },
        },
        else => {
            log.err("Unsupported I/O-in to PIC: port=0x{X}", .{qual.port});
            vcpu.abort();
        },
    }
}

fn handlePicOut(vcpu: *Vcpu, qual: QualIo) VmxError!void {
    if (qual.size != .byte) {
        log.err("Unsupported I/O-out size to PIC: size={s}, port=0x{X}", .{ @tagName(qual.size), qual.port });
        vcpu.abort();
    }

    const regs = &vcpu.guest_regs;
    const pic = &vcpu.pic;
    const dx: u8 = @truncate(regs.rax);

    switch (qual.port) {
        // Primary PIC command.
        0x20 => switch (dx) {
            0x11 => pic.primary_phase = .phase1,
            // Specific-EOI.
            // It's Ymir's responsibility to send EOI, so guests are not allowed to send EOI.
            0x60...0x67 => {},
            else => {
                log.err("Unsupported command to primary PIC: command=0x{X}", .{dx});
                vcpu.abort();
            },
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
                vcpu.abort();
            } else {
                pic.primary_phase = .phase3;
            },
            .phase3 => pic.primary_phase = .inited,
        },
        // Secondary PIC command.
        0xA0 => switch (dx) {
            0x11 => pic.secondary_phase = .phase1,
            // Specific-EOI.
            // It's Ymir's responsibility to send EOI, so guests are not allowed to send EOI.
            0x60...0x67 => {},
            else => {
                log.err("Unsupported command to secondary PIC: command=0x{X}", .{dx});
                vcpu.abort();
            },
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
                vcpu.abort();
            } else {
                pic.secondary_phase = .phase3;
            },
            .phase3 => pic.secondary_phase = .inited,
        },
        else => {
            log.err("Unsupported I/O-out to PIC: port=0x{X}", .{qual.port});
            vcpu.abort();
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

/// Virtual PCI.
pub const Pci = struct {
    const Self = @This();

    /// Configuration address register.
    config_addr: u32,
    /// Configuration data register.
    config_data: u32,

    pub fn new() Self {
        return Self{
            .config_addr = 0,
            .config_data = 0,
        };
    }

    pub fn in(self: *Self, vcpu: *Vcpu, port: u16) VmxError!void {
        const regs = &vcpu.guest_regs;
        switch (port) {
            0xCF8...0xCFB => regs.rax = self.config_addr, // TODO: should check offset and return appropriate value
            0xCFC...0xCFF => {},
            else => {
                log.err("Unsupported I/O-in to PCI: port=0x{X}", .{port});
                vcpu.abort();
            },
        }
    }

    pub fn out(self: *Self, vcpu: *Vcpu, port: u16) VmxError!void {
        const regs = &vcpu.guest_regs;
        switch (port) {
            0xCF8...0xCFB => self.config_addr = @truncate(regs.rax),
            0xCFC...0xCFF => {}, // TODO: Unimplemented.
            else => {
                log.err("Unsupported I/O-out to PCI: port=0x{X}", .{port});
                vcpu.abort();
            },
        }
    }
};

pub const Serial = struct {
    /// Interrupt Enable Register.
    ier: u8 = 0,
    /// Modem Control Register.
    mcr: u8 = 0,
    /// Line Status Register.
    msr: u8 = 0,

    pub fn new() Serial {
        return Serial{};
    }
};
