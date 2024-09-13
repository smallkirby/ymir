//! This file provides really really really limited emulation of x64 instructions.
//! Supposing that this file is used only to decode MOV instructions.

const std = @import("std");
const log = std.log.scoped(.vmemu);

const EmulationError = error{
    /// Unsupported x64 instruction.
    UnsupInst,
};
const Error = EmulationError;

pub fn decode(inst: []u8) Error!EmuResult {
    switch (inst[0]) {
        0x89 => { // MOV r32,r/m32
            return .{
                .op = .mov2mem,
                .reg = decodeRm(inst[1]),
                .size = .b32,
            };
        },
        0x8B => { // MOV r/m32,r32
            return .{
                .op = .mov2reg,
                .reg = decodeRm(inst[1]),
                .size = .b32,
            };
        },
        else => return Error.UnsupInst,
    }
}

fn decodeRm(modrm: u8) EmuRegister {
    const rm: u3 = @truncate(modrm & 0b111);
    const reg: u3 = @truncate((modrm >> 3) & 0b111);
    const mod: u2 = @truncate((modrm >> 6) & 0b11);
    _ = rm;
    _ = mod;

    return switch (reg) {
        0b000 => .ax,
        0b001 => .cx,
        0b010 => .dx,
        0b011 => .bx,
        0b100 => .sp,
        0b101 => .bp,
        0b110 => .si,
        0b111 => .di,
    };
}

const EmuResult = struct {
    op: EmuOp,
    reg: EmuRegister,
    size: EmuSize,
};

const EmuOp = enum {
    mov2mem,
    mov2reg,
};

const EmuRegister = enum {
    ax,
    cx,
    dx,
    bx,
    sp,
    bp,
    si,
    di,
    r8,
    r9,
    r10,
    r11,
    r12,
    r13,
    r14,
    r15,
};

const EmuSize = enum {
    b8,
    b16,
    b32,
    b64,
};
