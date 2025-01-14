//! Handle CPUID instruction.
//! Information returned by CPUID instruction is listed in SDM Chapter 3.3 Table 3-8.

const std = @import("std");
const log = std.log.scoped(.vmcpuid);

const arch = @import("arch.zig");
const cpuid = arch.cpuid;

const vmx = @import("common.zig");
const Vcpu = @import("vcpu.zig").Vcpu;

const VmxError = vmx.VmxError;
const Leaf = cpuid.Leaf;

const feature_info_ecx = cpuid.FeatureInfoEcx{
    .pcid = true,
};
const feature_info_edx = cpuid.FeatureInfoEdx{
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
    .acpi = false,
    .fxsr = true,
    .sse = true,
    .sse2 = true,
};
const ext_feature0_ebx = cpuid.ExtFeatureEbx0{
    .fsgsbase = false, // NOTE: rdfsbase seemingly cannot be intercepted.
    .smep = true,
    .invpcid = true,
    .smap = true,
};

/// Handle VM-exit caused by CPUID instruction.
/// Note that this function does not increment the RIP.
pub fn handleCpuidExit(vcpu: *Vcpu) VmxError!void {
    const regs = &vcpu.guest_regs;

    switch (Leaf.from(regs.rax)) {
        .maximum_input => {
            setValue(&regs.rax, 0x20); // Maximum input value for basic CPUID.
            setValue(&regs.rbx, 0x72_69_6D_59); // Ymir
            setValue(&regs.rcx, 0x72_69_6D_59); // Ymir
            setValue(&regs.rdx, 0x72_69_6D_59); // Ymir
        },
        .vers_and_feat_info => {
            const orig = Leaf.query(.vers_and_feat_info, null);
            setValue(&regs.rax, orig.eax); // Version information.
            setValue(&regs.rbx, orig.ebx); // Brand index / CLFLUSH line size / Addressable IDs / Initial APIC ID
            setValue(&regs.rcx, @as(u32, @bitCast(feature_info_ecx)));
            setValue(&regs.rdx, @as(u32, @bitCast(feature_info_edx)));
        },
        .ext_func => {
            setValue(&regs.rax, 0x8000_0000 + 1); // Maximum input value for extended function CPUID.
            setValue(&regs.rbx, 0); // Reserved.
            setValue(&regs.rcx, 0); // Reserved.
            setValue(&regs.rdx, 0); // Reserved.
        },
        .ext_proc_signature => {
            const orig = Leaf.ext_proc_signature.query(null);
            setValue(&regs.rax, 0); // Extended processor signature and feature bits.
            setValue(&regs.rbx, 0); // Reserved.
            setValue(&regs.rcx, orig.ecx); // LAHF in 64-bit mode / LZCNT / PREFETCHW
            setValue(&regs.rdx, orig.edx); // SYSCALL / XD / 1GB large page / RDTSCP and IA32_TSC_AUX / Intel64
        },
        .thermal_power => invalid(vcpu),
        .ext_feature => {
            switch (regs.rcx) {
                0 => {
                    setValue(&regs.rax, 1); // Maximum input value for supported leaf 7 sub-leaves.
                    setValue(&regs.rbx, @as(u32, @bitCast(ext_feature0_ebx)));
                    setValue(&regs.rcx, 0); // Unimplemented.
                    setValue(&regs.rdx, 0); // Unimplemented.
                },
                1, 2 => invalid(vcpu),
                else => {
                    log.err("Unhandled CPUID: Leaf=0x{X:0>8}, Sub=0x{X:0>8}", .{ regs.rax, regs.rcx });
                    vcpu.abort();
                },
            }
        },
        .ext_enumeration => {
            switch (regs.rcx) {
                1 => invalid(vcpu),
                else => {
                    log.err("Unhandled CPUID: Leaf=0x{X:0>8}, Sub=0x{X:0>8}", .{ regs.rax, regs.rcx });
                    vcpu.abort();
                },
            }
        },
        _ => {
            log.warn("Unhandled CPUID: Leaf=0x{X:0>8}, Sub=0x{X:0>8}", .{ regs.rax, regs.rcx });
            invalid(vcpu);
        },
    }
}

/// Set a 32-bit value to the given 64-bit without modifying the upper 32-bits.
inline fn setValue(reg: *u64, val: u64) void {
    @as(*u32, @ptrCast(reg)).* = @as(u32, @truncate(val));
}

/// Set an invalid value to the registers.
fn invalid(vcpu: *Vcpu) void {
    const gregs = &vcpu.guest_regs;
    setValue(&gregs.rax, 0);
    setValue(&gregs.rbx, 0);
    setValue(&gregs.rcx, 0);
    setValue(&gregs.rdx, 0);
}
