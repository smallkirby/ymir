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
//!

const std = @import("std");
const log = std.log.scoped(.isr);

const intr = @import("interrupt.zig");
const idt = @import("idt.zig");

// Execution Context
pub const Context = packed struct {
    /// General purpose registers.
    registers: Registers,
    /// Interrupt Vector.
    vector: u64,
    /// Error Code.
    error_code: u64,

    // CPU status:
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
};

/// Structure holding general purpose registers as saved by PUSHA.
const Registers = packed struct {
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rsp: u64,
    rbx: u64,
    rdx: u64,
    rcx: u64,
    rax: u64,
};

/// Zig entry point of the interrupt handler.
export fn intrZigEntry(ctx: *Context) void {
    intr.dispatch(ctx);
}

/// Get ISR function for the given vector.
pub fn generateIsr(comptime vector: usize) idt.Isr {
    return struct {
        fn handler() callconv(.Naked) void {
            // Clear the interrupt flag.
            asm volatile (
                \\cli
            );

            // If the interrupt does not provide an error code, push a dummy one.
            if (vector != 8 and !(vector >= 10 and vector <= 14) and vector != 17) {
                asm volatile (
                    \\pushq $0
                );
            }

            // Push the vector.
            asm volatile (
                \\pushq %[vector]
                :
                : [vector] "n" (vector),
            );
            // Jump to the common ISR.
            asm volatile (
                \\jmp isrCommon
            );
        }
    }.handler;
}

/// Common stub for all ISR, that all the ISRs will use.
/// This function assumes that `Context` is saved at the top of the stack except for general-purpose registers.
export fn isrCommon() callconv(.Naked) void {
    // Save the general-purpose registers.
    asm volatile (
        \\pushq %%rax
        \\pushq %%rcx
        \\pushq %%rdx
        \\pushq %%rbx
        \\pushq %%rsp
        \\pushq %%rbp
        \\pushq %%rsi
        \\pushq %%rdi
        \\pushq %%r15
        \\pushq %%r14
        \\pushq %%r13
        \\pushq %%r12
        \\pushq %%r11
        \\pushq %%r10
        \\pushq %%r9
        \\pushq %%r8
    );

    // Push the context and call the handler.
    // NOTE: I'm not sure but we have to put context address both to RDI and stack.
    asm volatile (
        \\pushq %%rsp
        \\popq %%rdi
        \\pushq %%rdi
        \\call  intrZigEntry
    );

    // Handler function must return the saved stack pointer, so restore it.
    asm volatile (
        \\add  $0x8, %%rsp
    );

    // Remove general-purpose registers, error code, and vector from the stack.
    asm volatile (
        \\popq %%r8
        \\popq %%r9
        \\popq %%r10
        \\popq %%r11
        \\popq %%r12
        \\popq %%r13
        \\popq %%r14
        \\popq %%r15
        \\popq %%rdi
        \\popq %%rsi
        \\popq %%rbp
        \\popq %%rsp
        \\popq %%rbx
        \\popq %%rdx
        \\popq %%rcx
        \\popq %%rax
        \\add   $0x10, %%rsp
        \\iretq
    );
}
