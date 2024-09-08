const std = @import("std");
const log = std.log.scoped(.vmmsr);

const vmx = @import("../vmx.zig");
const Vcpu = vmx.Vcpu;
const VmxError = vmx.VmxError;
const am = @import("../asm.zig");
const vmcs = @import("vmcs.zig");
const vmwrite = vmcs.vmwrite;
const vmread = vmcs.vmread;

/// Handle VM-exit caused by RDMSR instruction.
/// Note that this function does not increment the RIP.
pub fn handleRdmsrExit(vcpu: *Vcpu) VmxError!void {
    const guest_regs = &vcpu.guest_regs;
    const rcx: u32 = @truncate(guest_regs.rcx);
    const msr_kind: am.Msr = @enumFromInt(rcx);

    switch (msr_kind) {
        .tsc_adjust,
        .bios_sign_id,
        .mtrrcap,
        .arch_cap,
        .misc_enable,
        .mtrr_physbase0,
        .mtrr_physmask0,
        .mtrr_physbase1,
        .mtrr_physmask1,
        .mtrr_physbase2,
        .mtrr_physmask2,
        .mtrr_physbase3,
        .mtrr_physmask3,
        .mtrr_physbase4,
        .mtrr_physmask4,
        .mtrr_physbase5,
        .mtrr_physmask5,
        .mtrr_physbase6,
        .mtrr_physmask6,
        .mtrr_physbase7,
        .mtrr_physmask7,
        .mtrr_fix64K_00000,
        .mtrr_fix16K_80000,
        .mtrr_fix16K_A0000,
        .mtrr_fix4K_C0000,
        .mtrr_fix4K_C8000,
        .mtrr_fix4K_D0000,
        .mtrr_fix4K_D8000,
        .mtrr_fix4K_E0000,
        .mtrr_fix4K_E8000,
        .mtrr_fix4K_F0000,
        .mtrr_fix4K_F8000,
        .pat,
        .mtrr_def_type,
        => passthroughRdmsr(vcpu, msr_kind),
        .apic_base => {
            guest_regs.rdx = 0xDEADBEEF;
            guest_regs.rax = 0xCAFEBABE;
        },
        .efer => {
            const efer = try vmread(vmcs.Guest.efer);
            guest_regs.rdx = @as(u32, @truncate(efer >> 32));
            guest_regs.rax = @as(u32, @truncate(efer));
        },
        .fs_base => {
            const fs_base = try vmread(vmcs.Guest.fs_base);
            guest_regs.rdx = @as(u32, @truncate(fs_base >> 32));
            guest_regs.rax = @as(u32, @truncate(fs_base));
        },
        .gs_base => {
            const gs_base = try vmread(vmcs.Guest.gs_base);
            guest_regs.rdx = @as(u32, @truncate(gs_base >> 32));
            guest_regs.rax = @as(u32, @truncate(gs_base));
        },
        .kernel_gs_base => passthroughRdmsr(vcpu, msr_kind),
        else => {
            log.err("Unhandled RDMSR: {?}", .{msr_kind});
            unreachable;
        },
    }
}

/// Handle VM-exit caused by WRMSR instruction.
/// Note that this function does not increment the RIP.
pub fn handleWrmsrExit(vcpu: *Vcpu) VmxError!void {
    const guest_regs = &vcpu.guest_regs;
    const ecx: u32 = @truncate(guest_regs.rcx);
    const value = concat(guest_regs.rdx, guest_regs.rax);
    const msr_kind: am.Msr = @enumFromInt(ecx);

    switch (msr_kind) {
        .bios_sign_id => {}, // TODO
        .xss,
        .pat,
        .mtrr_def_type,
        => passthroughWrmsr(vcpu, msr_kind),
        .efer => try vmwrite(vmcs.Guest.efer, value),
        .gs_base => try vmwrite(vmcs.Guest.gs_base, value),
        .fs_base => try vmwrite(vmcs.Guest.fs_base, value),
        else => {
            log.err("Unhandled WRMSR: {?}", .{msr_kind});
            unreachable;
        },
    }
}

fn concat(r1: u64, r2: u64) u64 {
    return ((r1 & 0xFFFF_FFFF) << 32) | (r2 & 0xFFFF_FFFF);
}

fn passthroughRdmsr(vcpu: *Vcpu, msr_kind: am.Msr) void {
    const msr = am.readMsr(msr_kind);
    vcpu.guest_regs.rax = @as(u32, @truncate(msr));
    vcpu.guest_regs.rdx = @as(u32, @truncate(msr >> 32));
}

fn passthroughWrmsr(vcpu: *Vcpu, msr_kind: am.Msr) void {
    const value = concat(vcpu.guest_regs.rdx, vcpu.guest_regs.rax);
    am.writeMsr(msr_kind, value);
}
