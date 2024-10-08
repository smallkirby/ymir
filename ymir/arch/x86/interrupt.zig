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
const log = std.log.scoped(.intr);

const ymir = @import("ymir");
const am = @import("asm.zig");
const idt = @import("idt.zig");
const isr = @import("isr.zig");
const page = @import("page.zig");

/// Context for interrupt handlers.
pub const Context = isr.Context;

/// Subscriber to interrupts.
pub const Subscriber = struct {
    /// Context of the subscriber.
    self: *anyopaque,
    /// Context of the interrupt.
    callback: Callback,

    pub const Callback = *const fn (*anyopaque, *Context) void;
};

/// Interrupt handler function signature.
pub const Handler = *const fn (*Context) void;

/// Maximum number of subscribers.
const max_subscribers = 10;
/// Subscribers to interrupts.
var subscribers: [max_subscribers]?Subscriber = [_]?Subscriber{null} ** max_subscribers;

/// Interrupt handlers.
var handlers: [256]Handler = [_]Handler{unhandledHandler} ** 256;

/// Initialize the IDT.
pub fn init() void {
    inline for (0..idt.max_num_gates) |i| {
        idt.setGate(
            i,
            .Interrupt64,
            isr.generateIsr(i),
        );
    }

    // Detailed handling for page faults.
    registerHandler(page_fault, unhandledFaultHandler);

    idt.init();

    am.sti();
}

/// Register interrupt handler.
pub fn registerHandler(comptime vector: u8, handler: Handler) void {
    handlers[vector] = handler;
    idt.setGate(
        vector,
        .Interrupt64,
        isr.generateIsr(vector),
    );
}

/// Subscribe to interrupts.
/// Subscribers are called when an interrupt is triggered before the interrupt handler.
pub fn subscribe(ctx: *anyopaque, callback: Subscriber.Callback) !void {
    for (subscribers, 0..) |sub, i| {
        if (sub == null) {
            subscribers[i] = Subscriber{
                .callback = callback,
                .self = ctx,
            };
            return;
        }
    }
    return error.SubscriberFull;
}

/// Called from the ISR stub.
/// Dispatches the interrupt to the appropriate handler.
pub fn dispatch(context: *Context) void {
    const vector = context.vector;
    // Notify subscribers.
    for (subscribers) |subscriber| {
        if (subscriber) |s| s.callback(s.self, context);
    }
    // Call the handler.
    handlers[vector](context);
}

fn unhandledHandler(context: *Context) void {
    @setCold(true);

    log.err("============ Oops! ===================", .{});
    log.err("Unhandled interrupt: {s} ({})", .{
        exceptionName(context.vector),
        context.vector,
    });
    log.err("Error Code: 0x{X}", .{context.error_code});
    log.err("RIP    : 0x{X:0>16}", .{context.rip});
    log.err("RSP    : 0x{X:0>16}", .{context.rsp});
    log.err("EFLAGS : 0x{X:0>16}", .{context.rflags});
    log.err("RAX    : 0x{X:0>16}", .{context.registers.rax});
    log.err("RBX    : 0x{X:0>16}", .{context.registers.rbx});
    log.err("RCX    : 0x{X:0>16}", .{context.registers.rcx});
    log.err("RDX    : 0x{X:0>16}", .{context.registers.rdx});
    log.err("RSI    : 0x{X:0>16}", .{context.registers.rsi});
    log.err("RDI    : 0x{X:0>16}", .{context.registers.rdi});
    log.err("RBP    : 0x{X:0>16}", .{context.registers.rbp});
    log.err("R8     : 0x{X:0>16}", .{context.registers.r8});
    log.err("R9     : 0x{X:0>16}", .{context.registers.r9});
    log.err("R10    : 0x{X:0>16}", .{context.registers.r10});
    log.err("R11    : 0x{X:0>16}", .{context.registers.r11});
    log.err("R12    : 0x{X:0>16}", .{context.registers.r12});
    log.err("R13    : 0x{X:0>16}", .{context.registers.r13});
    log.err("R14    : 0x{X:0>16}", .{context.registers.r14});
    log.err("R15    : 0x{X:0>16}", .{context.registers.r15});
    log.err("CS     : 0x{X:0>4}", .{context.cs});
    log.err("SS     : 0x{X:0>4}", .{context.ss});

    ymir.endlessHalt();
}

fn unhandledFaultHandler(context: *Context) void {
    @setCold(true);

    log.err("============ Unhandled Fault ===================", .{});

    const cr2 = am.readCr2();
    log.err("Fault Address: 0x{X:0>16}", .{cr2});
    page.showPageTable(cr2, log);
    log.err("\nCommon unhandled handler continues...\n", .{});

    unhandledHandler(context);
}

// Exception vectors.
const divide_by_zero = 0;
const debug = 1;
const non_maskable_interrupt = 2;
const breakpoint = 3;
const overflow = 4;
const bound_range_exceeded = 5;
const invalid_opcode = 6;
const device_not_available = 7;
const double_fault = 8;
const coprocessor_segment_overrun = 9;
const invalid_tss = 10;
const segment_not_present = 11;
const stack_segment_fault = 12;
const general_protection_fault = 13;
const page_fault = 14;
const floating_point_exception = 16;
const alignment_check = 17;
const machine_check = 18;
const simd_exception = 19;
const virtualization_exception = 20;
const control_protection_excepton = 21;

pub const num_system_exceptions = 32;

/// Get the name of an exception.
pub inline fn exceptionName(vector: u64) []const u8 {
    return switch (vector) {
        divide_by_zero => "#DE: Divide by zero",
        debug => "#DB: Debug",
        non_maskable_interrupt => "NMI: Non-maskable interrupt",
        breakpoint => "#BP: Breakpoint",
        overflow => "#OF: Overflow",
        bound_range_exceeded => "#BR: Bound range exceeded",
        invalid_opcode => "#UD: Invalid opcode",
        device_not_available => "#NM: Device not available",
        double_fault => "#DF: Double fault",
        coprocessor_segment_overrun => "Coprocessor segment overrun",
        invalid_tss => "#TS: Invalid TSS",
        segment_not_present => "#NP: Segment not present",
        stack_segment_fault => "#SS: Stack-segment fault",
        general_protection_fault => "#GP: General protection fault",
        page_fault => "#PF: Page fault",
        floating_point_exception => "#MF: Floating-point exception",
        alignment_check => "#AC: Alignment check",
        machine_check => "#MC: Machine check",
        simd_exception => "#XM: SIMD exception",
        virtualization_exception => "#VE: Virtualization exception",
        control_protection_excepton => "#CP: Control protection exception",
        else => "Unknown exception",
    };
}
