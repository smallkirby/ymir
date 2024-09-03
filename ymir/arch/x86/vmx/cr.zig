const std = @import("std");
const log = std.log.scoped(.cr);

const vmx = @import("../vmx.zig");
const Vcpu = vmx.Vcpu;
const VmxError = vmx.VmxError;
const am = @import("../asm.zig");
const vmcs = @import("vmcs.zig");
const QualCr = @import("exit.zig").QualCr;
const vmwrite = vmcs.vmwrite;
const vmread = vmcs.vmread;

/// Handle VM-exit caused by mov to CR3 instruction.
/// Note that this function does not increment the RIP.
pub fn handleAccessCr(vcpu: *Vcpu, qual: QualCr) VmxError!void {
    switch (qual.access_type) {
        .mov_to => {
            switch (qual.index) {
                0 => { // TODO: make this a function
                    const cr0: am.Cr0 = @bitCast(getValue(vcpu, qual));
                    vcpu.ia32_enabled = cr0.pg;
                    try vmwrite(vmcs.Guest.cr0, adjustCr0(@bitCast(cr0)));

                    var entry_ctrl = try vmcs.EntryCtrl.store();
                    entry_ctrl.ia32e_mode_guest = vcpu.ia32_enabled;
                    try entry_ctrl.load();

                    if (vcpu.ia32_enabled) {
                        var efer: am.Efer = @bitCast(try vmread(vmcs.Guest.efer));
                        efer.lma = efer.lme and vcpu.ia32_enabled;
                        try vmwrite(vmcs.Guest.efer, efer);
                    }
                },
                else => try passthroughWrite(vcpu, qual),
            }
        },
        .mov_from => try passthroughRead(vcpu, qual),
        else => {
            log.err("Unimplemented CR access: {?}", .{qual});
            unreachable;
        },
    }
}

fn passthroughRead(vcpu: *Vcpu, qual: QualCr) VmxError!void {
    const gregs = &vcpu.guest_regs;
    const value = switch (qual.index) {
        0 => try vmread(vmcs.Guest.cr0),
        4 => try vmread(vmcs.Guest.cr4),
        else => {
            log.err("Unhandled CR read: {}", .{qual.index});
            unreachable;
        },
    };

    switch (qual.reg) {
        .rax => gregs.rax = value,
        .rcx => gregs.rcx = value,
        .rdx => gregs.rdx = value,
        .rbx => gregs.rbx = value,
        .rbp => gregs.rbp = value,
        .rsi => gregs.rsi = value,
        .rdi => gregs.rdi = value,
        .r8 => gregs.r8 = value,
        .r9 => gregs.r9 = value,
        .r10 => gregs.r10 = value,
        .r11 => gregs.r11 = value,
        .r12 => gregs.r12 = value,
        .r13 => gregs.r13 = value,
        .r14 => gregs.r14 = value,
        .r15 => gregs.r15 = value,
        else => {
            log.err("Unhandled CR read to: {}", .{qual.reg});
            unreachable;
        },
    }
}

fn passthroughWrite(vcpu: *Vcpu, qual: QualCr) VmxError!void {
    const value = getValue(vcpu, qual);
    switch (qual.index) {
        0 => try vmwrite(vmcs.Guest.cr0, adjustCr0(value)),
        4 => try vmwrite(vmcs.Guest.cr4, adjustCr4(value)),
        else => {
            log.err("Unhandled CR write to: {}", .{qual.index});
            unreachable;
        },
    }
}

fn getValue(vcpu: *Vcpu, qual: QualCr) u64 {
    const gregs = &vcpu.guest_regs;
    return switch (qual.reg) {
        .rax => gregs.rax,
        .rcx => gregs.rcx,
        .rdx => gregs.rdx,
        .rbx => gregs.rbx,
        .rbp => gregs.rbp,
        .rsi => gregs.rsi,
        .rdi => gregs.rdi,
        .r8 => gregs.r8,
        .r9 => gregs.r9,
        .r10 => gregs.r10,
        .r11 => gregs.r11,
        .r12 => gregs.r12,
        .r13 => gregs.r13,
        .r14 => gregs.r14,
        .r15 => gregs.r15,
        else => {
            log.err("Unhandled CR access from: {}", .{qual.reg});
            unreachable;
        },
    };
}

fn adjustCr0(value: u64) u64 {
    var ret: u64 = @bitCast(value);
    const vmx_cr0_fixed0: u32 = @truncate(am.readMsr(.vmx_cr0_fixed0));
    const vmx_cr0_fixed1: u32 = @truncate(am.readMsr(.vmx_cr0_fixed1));

    ret |= vmx_cr0_fixed0;
    ret &= vmx_cr0_fixed1;

    return ret;
}

fn adjustCr4(value: u64) u64 {
    var ret: u64 = @bitCast(value);
    const vmx_cr4_fixed0: u32 = @truncate(am.readMsr(.vmx_cr4_fixed0));
    const vmx_cr4_fixed1: u32 = @truncate(am.readMsr(.vmx_cr4_fixed1));

    ret |= vmx_cr4_fixed0;
    ret &= vmx_cr4_fixed1;

    return ret;
}
