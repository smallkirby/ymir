const std = @import("std");
const log = std.log.scoped(.cpuid);

const vmx = @import("../vmx.zig");
const Vcpu = vmx.Vcpu;
const VmxError = vmx.VmxError;
const cpuid = @import("../cpuid.zig");
const am = @import("../asm.zig");

/// Handle VM-exit caused by CPUID instruction.
/// Note that this function does not increment the RIP.
pub fn handleCpuidExit(vcpu: *Vcpu) VmxError!void {
    const regs = &vcpu.guest_regs;
    const leaf = Leaf.from(regs.rax);

    switch (leaf) {
        .maximum_input => passthrough(vcpu),
        .version_info => passthrough(vcpu),
        .extended_function => passthrough(vcpu),
        .extended_processor_signature => passthrough(vcpu),
        .seven => passthroughEcx(vcpu),
    }
}

fn passthrough(vcpu: *Vcpu) void {
    const gregs = &vcpu.guest_regs;
    const regs = am.cpuid(@truncate(gregs.rax));
    gregs.rax = regs.eax;
    gregs.rbx = regs.ebx;
    gregs.rcx = regs.ecx;
    gregs.rdx = regs.edx;
}

fn passthroughEcx(vcpu: *Vcpu) void {
    const gregs = &vcpu.guest_regs;
    const regs = am.cpuidEcx(@truncate(gregs.rax), @truncate(gregs.rcx));
    gregs.rax = regs.eax;
    gregs.rbx = regs.ebx;
    gregs.rcx = regs.ecx;
    gregs.rdx = regs.edx;
}

const Leaf = enum(u64) {
    /// Maximum input value for basic CPUID.
    maximum_input = 0x0,
    /// Version information.
    version_info = 0x1,
    /// TODO
    seven = 0x7,
    /// Maximum input value for extended function CPUID information.
    extended_function = 0x80000000,
    /// EAX: Extended processor signature and feature bits.
    extended_processor_signature = 0x80000001,

    pub fn from(rax: u64) Leaf {
        return @enumFromInt(rax);
    }
};
