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

    if (invalid_cpuid_start <= regs.rax and regs.rax <= invalid_cpuid_end) {
        // Linux kernel checks KVM support using CPUID in this range.
        // We should return 0 even for these ranges.
        return invalid(vcpu);
    }

    switch (Leaf.from(regs.rax)) {
        .maximum_input => {
            const pass = am.cpuid(@truncate(regs.rax));
            regs.rax = pass.eax;
            regs.rbx = 0x72_69_6D_59; // Ymir
            regs.rcx = 0x72_69_6D_59; // Ymir
            regs.rdx = 0x72_69_6D_59; // Ymir
        },
        .version_info,
        .extended_function,
        .extended_processor_signature,
        .thermal_power,
        .ext_feature,
        .ext_topology,
        .rdt_l3cache,
        .cache_allocation,
        .sgx,
        .v2_ext_topology,
        .ext_enumuration,
        .brand1,
        .brand2,
        .brand3,
        .invariant_tsc,
        .address_size,
        => passthrough(vcpu),
        .reserved,
        .cacheline,
        => invalid(vcpu),
    }
}

fn passthrough(vcpu: *Vcpu) void {
    const gregs = &vcpu.guest_regs;
    const regs = am.cpuidEcx(@truncate(gregs.rax), @truncate(gregs.rcx));
    gregs.rax = regs.eax;
    gregs.rbx = regs.ebx;
    gregs.rcx = regs.ecx;
    gregs.rdx = regs.edx;
}

fn invalid(vcpu: *Vcpu) void {
    const gregs = &vcpu.guest_regs;
    gregs.rax = 0;
    gregs.rbx = 0;
    gregs.rcx = 0;
    gregs.rdx = 0;
}

/// SDM Vol2A Chapter 3.3 Table 3-8.
const Leaf = enum(u32) {
    /// Maximum input value for basic CPUID.
    maximum_input = 0x0,
    /// Version information.
    version_info = 0x1,
    /// Thermal and power management.
    thermal_power = 0x6,
    /// Structured extended feature enumeration.
    /// Output depends on the value of ECX.
    ext_feature = 0x7,
    /// Extended topology enumeration.
    ext_topology = 0xB,
    /// Processor extended state enumeration.
    /// Output depends on the ECX input value.
    ext_enumuration = 0xD,
    /// Intel Resouce Director Technology monitoring enumeration when ECX = 0,
    /// L3 Cache RDT monitoring capability enumeration when ECX = 1.
    rdt_l3cache = 0xF,
    /// RDT allocation enumeration when ECX = 0,
    /// L3 cache allocation technology enumeration when ECX = 1.
    /// L2 cache allocation technology enumeration when ECX = 2.
    /// Memory bandwidth allocation enumeration when ECX = 3.
    cache_allocation = 0x10,
    /// Intel SGX capability enumeration when ECX = 0.
    /// SGX attributes enumeration when ECX = 1.
    /// SGX EPC enumeration when ECX = 2.
    sgx = 0x12,
    /// V2 extended topology enumeration.
    v2_ext_topology = 0x1F,
    /// Maximum input value for extended function CPUID information.
    extended_function = 0x80000000,
    /// EAX: Extended processor signature and feature bits.
    extended_processor_signature = 0x80000001,
    /// Processor brand string.
    brand1 = 0x80000002,
    /// Processor brand string continued.
    brand2 = 0x80000003,
    /// Processor brand string continued.
    brand3 = 0x80000004,
    /// Reserved.
    reserved = 0x80000005,
    /// Cache line size.
    cacheline = 0x80000006,
    /// Envariant TSC available.
    invariant_tsc = 0x80000007,
    /// Linear/Physical address size.
    address_size = 0x80000008,

    pub fn from(rax: u64) Leaf {
        return @enumFromInt(rax);
    }
};

const invalid_cpuid_start: u32 = 0x40_000_000;
const invalid_cpuid_end: u32 = 0x4F_FFF_FFF;
