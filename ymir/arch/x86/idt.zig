//! LICENSE NOTICE
//!
//! The impletentation is heavily inspired by https://github.com/AndreaOrru/zen
//! Original LICENSE follows:
//!
//! BSD 3-Clause License
//!
//! Copyright (c) 2017, Andrea Orru
//! All rights reserved.
//!
//! Redistribution and use in source and binary forms, with or without
//! modification, are permitted provided that the following conditions are met:
//!
//! * Redistributions of source code must retain the above copyright notice, this
//!   list of conditions and the following disclaimer.
//!
//! * Redistributions in binary form must reproduce the above copyright notice,
//!   this list of conditions and the following disclaimer in the documentation
//!   and/or other materials provided with the distribution.
//!
//! * Neither the name of the copyright holder nor the names of its
//!   contributors may be used to endorse or promote products derived from
//!   this software without specific prior written permission.
//!
//! THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//! AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//! IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//! DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
//! FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//! DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//! SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
//! CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
//! OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//! OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//!

const std = @import("std");
const log = std.log.scoped(.idt);

const am = @import("asm.zig");
const gdt = @import("gdt.zig");

/// Maximum number of gates in the IDT.
pub const max_num_gates = 256;
/// Interrupt Descriptor Table.
var idt: [max_num_gates]GateDesriptor align(4096) = [_]GateDesriptor{std.mem.zeroes(GateDesriptor)} ** max_num_gates;
/// IDT Register.
var idtr = IdtRegister{
    .limit = @sizeOf(@TypeOf(idt)) - 1,
    // TODO: BUG: Zig v0.13.0. https://github.com/ziglang/zig/issues/17856
    //.base = &idt,
    // This initialization invokes LLVM error.
    // As a workaround, we make `idtr` mutable and initialize it in `init()`.
    .base = undefined,
};

/// ISR signature.
pub const Isr = fn () callconv(.Naked) void;

/// Initialize the IDT.
pub fn init() void {
    idtr.base = &idt;
    am.lidt(@intFromPtr(&idtr));
}

/// Set a gate descriptor in the IDT.
pub fn setGate(
    index: usize,
    gate_type: GateType,
    offset: Isr,
) void {
    idt[index] = GateDesriptor{
        .offset_low = @truncate(@intFromPtr(&offset)),
        .seg_selector = gdt.kernel_cs_index << 3,
        .gate_type = gate_type,
        .offset_middle = @truncate(@as(u64, @intFromPtr(&offset)) >> 16),
        .offset_high = @truncate(@as(u64, @intFromPtr(&offset)) >> 32),
        .dpl = 0,
    };
}

/// Entry in the Interrupt Descriptor Table.
pub const GateDesriptor = packed struct(u128) {
    /// Lower 16 bits of the offset to the ISR.
    offset_low: u16,
    /// Segment Selector that must point to a valid code segment in the GDT.
    seg_selector: u16,
    /// Interrupt Stack Table. Not used.
    ist: u3 = 0,
    /// Reserved.
    _reserved1: u5 = 0,
    /// Gate Type.
    gate_type: GateType,
    /// Reserved.
    _reserved2: u1 = 0,
    /// Descriptor Privilege Level is the required CPL to call the ISR via the INT inst.
    /// Hardware interrupts ignore this field.
    dpl: u2,
    /// Present flag. Must be 1.
    present: bool = true,
    /// Middle 16 bits of the offset to the ISR.
    offset_middle: u16,
    /// Higher 32 bits of the offset to the ISR.
    offset_high: u32,
    /// Reserved.
    _reserved3: u32 = 0,

    pub fn offset(self: GateDesriptor) u64 {
        return @as(u64, self.offset_high) << 32 | @as(u64, self.offset_middle) << 16 | @as(u64, self.offset_low);
    }
};

const IdtRegister = packed struct {
    limit: u16,
    base: *[max_num_gates]GateDesriptor,
};

/// Gate type of the gate descriptor in IDT.
pub const GateType = enum(u4) {
    Invalid = 0b0000,
    /// Interrupt Gate.
    /// Interrupts are disabled when the ISR is called.
    Interrupt64 = 0b1110,
    /// Trap Gate.
    Trap64 = 0b1111,
};

const testing = std.testing;

test "gate descriptor" {
    const gate = GateDesriptor{
        .offset_low = 0x1234,
        .seg_selector = 0x5678,
        .gate_type = .Interrupt64,
        .offset_middle = 0x9abc,
        .offset_high = 0x0123def0,
        .dpl = 0,
    };

    try testing.expectEqual(0x0123def0_9abc_1234, gate.offset());
}

test "IDTR limit" {
    try testing.expectEqual(256 * 16 - 1, idtr.limit);
}
