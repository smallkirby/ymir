//! Handle CPUID instruction.
//! Information returned by CPUID instruction is listed in SDM Chapter 3.3 Table 3-8.

const std = @import("std");
const log = std.log.scoped(.cpuid);

const vmx = @import("../vmx.zig");
const Vcpu = vmx.Vcpu;
const VmxError = vmx.VmxError;
const cpuid = @import("../cpuid.zig");
const am = @import("../asm.zig");

// CPUID[Leaf=1] return value.
// Linux defines the mandatory features in this leaf.
const feature_info_ecx = cpuid.FeatureInformationEcx{
    .pcid = true,
};
const feature_info_edx = cpuid.FeatureInformationEdx{
    .fpu = true,
    .vme = true,
    .de = true,
    .pse = true,
    .msr = true,
    .pae = true,
    .cx8 = true,
    .sep = true,
    .pge = true,
    .cmov = true,
    .pse36 = true,
    .acpi = true, // TODO
    .fxsr = true,
    .sse = true,
    .sse2 = true,
};
// CPUID[Leaf=7,Sub=0] return value.
const ext_feature0_ebx = cpuid.ExtFeatureEbx0{
    .smep = true,
    .invpcid = true,
    .smap = true,
};

/// Handle VM-exit caused by CPUID instruction.
/// Note that this function does not increment the RIP.
pub fn handleCpuidExit(vcpu: *Vcpu) VmxError!void {
    const regs = &vcpu.guest_regs;

    if (std.meta.intToEnum(Leaf, regs.rax)) |leaf| switch (leaf) {
        .maximum_input => {
            regs.rax = 0x20; // Maximum input value for basic CPUID.
            regs.rbx = 0x72_69_6D_59; // Ymir
            regs.rcx = 0x72_69_6D_59; // Ymir
            regs.rdx = 0x72_69_6D_59; // Ymir
        },
        .version_info => {
            const orig = am.cpuid(1);
            regs.rax = orig.eax; // Version information.
            regs.rbx = orig.ebx; // Brand index / CLFLUSH line size / Addressable IDs / Initial APIC ID
            regs.rcx = @as(u32, @bitCast(feature_info_ecx));
            regs.rdx = @as(u32, @bitCast(feature_info_edx));
        },
        .extended_function => {
            regs.rax = 0x8000_0000 + 1; // Maximum input value for extended function CPUID.
            regs.rbx = 0; // Reserved.
            regs.rcx = 0; // Reserved.
            regs.rdx = 0; // Reserved.
        },
        .extended_processor_signature => {
            const orig = am.cpuid(@intFromEnum(Leaf.extended_processor_signature));
            regs.rax = 0; // Extended processor signature and feature bits.
            regs.rbx = 0; // Reserved.
            regs.rcx = orig.ecx; // LAHF in 64-bit mode / LZCNT / PREFETCHW
            regs.rdx = orig.edx; // SYSCALL / XD / 1GB large page / RDTSCP and IA32_TSC_AUX / Intel64
        },
        .thermal_power => {
            regs.rax = 0; // Hide all features.
            regs.rbx = 0; // Number of interrupt thresholds in digital thermal sensor.
            regs.rcx = 0; // Hide all features.
            regs.rdx = 0; // Hide all features.
        },
        .ext_feature => {
            switch (regs.rcx) {
                0 => {
                    regs.rax = 1; // Maximum input value for supported leaf 7 sub-leaves.
                    regs.rbx = @as(u32, @bitCast(ext_feature0_ebx));
                    regs.rcx = 0; // Unimplemented.
                    regs.rdx = 0; // Unimplemented.
                },
                1, 2 => {
                    regs.rax = 0; // Unimplemented.
                    regs.rbx = 0; // Unimplemented.
                    regs.rcx = 0; // Unimplemented.
                    regs.rdx = 0; // Unimplemented.
                },
                else => {
                    log.err("Unhandled CPUID: Leaf=0x{X:0>8}, Sub=0x{X:0>8}", .{ regs.rax, regs.rcx });
                    vcpu.abort();
                },
            }
        },
        .ext_enumuration => {
            switch (regs.rcx) {
                1 => {
                    regs.rax = 0; // Hide all features.
                    regs.rbx = 0; // Unimplemented.
                    regs.rcx = 0; // Unimplemented.
                    regs.rdx = 0; // Unimplemented.
                },
                else => {
                    log.err("Unhandled CPUID: Leaf=0x{X:0>8}, Sub=0x{X:0>8}", .{ regs.rax, regs.rcx });
                    vcpu.abort();
                },
            }
        },
        else => {
            log.warn("Unhandled CPUID: Leaf=0x{X:0>8}, Sub=0x{X:0>8}", .{ regs.rax, regs.rcx });
            invalid(vcpu);
        },
    } else |_| {
        log.warn("Unimplemented CPUID: Leaf=0x{X:0>8}, Sub=0x{X:0>8}", .{ regs.rax, regs.rcx });
        invalid(vcpu);
    }
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
