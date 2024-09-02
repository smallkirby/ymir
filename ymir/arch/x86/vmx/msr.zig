const std = @import("std");
const log = std.log.scoped(.cpuid);

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
        .misc_enable => passthroughRdmsr(vcpu, msr_kind),
        .efer => {
            const efer = try vmread(vmcs.Guest.efer);
            guest_regs.rdx = @as(u32, @truncate(efer >> 32));
            guest_regs.rax = @as(u32, @truncate(efer));
        },
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
        .efer => try vmwrite(vmcs.Guest.efer, value),
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
