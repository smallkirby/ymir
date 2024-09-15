const std = @import("std");
const log = std.log.scoped(.cr);

const vmx = @import("../vmx.zig");
const Vcpu = vmx.Vcpu;
const VmxError = vmx.VmxError;
const am = @import("../asm.zig");
const vmcs = @import("vmcs.zig");
const QualCr = @import("qual.zig").QualCr;
const vmwrite = vmcs.vmwrite;
const vmread = vmcs.vmread;

/// Handle VM-exit caused by mov to CR3 instruction.
/// Note that this function does not increment the RIP.
pub fn handleAccessCr(vcpu: *Vcpu, qual: QualCr) VmxError!void {
    switch (qual.access_type) {
        .mov_to => {
            switch (qual.index) {
                0, 4 => {
                    try passthroughWrite(vcpu, qual);
                    try updateIa32e(vcpu);
                },
                3 => {
                    const val = getValue(vcpu, qual); // TODO: Why the guest sets the MSB?
                    try vmwrite(vmcs.Guest.cr3, val & ~@as(u64, (1 << 63)));
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

fn updateIa32e(vcpu: *Vcpu) VmxError!void {
    const cr0: am.Cr0 = @bitCast(try vmread(vmcs.Guest.cr0));
    const cr4: am.Cr4 = @bitCast(try vmread(vmcs.Guest.cr4));
    const ia32e_enabled = cr0.pg and cr4.pae;

    vcpu.ia32_enabled = ia32e_enabled;

    var entry_ctrl = try vmcs.EntryCtrl.store();
    entry_ctrl.ia32e_mode_guest = ia32e_enabled;
    try entry_ctrl.load();

    var efer: am.Efer = @bitCast(try vmread(vmcs.Guest.efer));
    efer.lma = vcpu.ia32_enabled;
    efer.lme = if (cr0.pg) efer.lma else efer.lme;
    try vmwrite(vmcs.Guest.efer, efer);
}

fn passthroughRead(vcpu: *Vcpu, qual: QualCr) VmxError!void {
    const value = switch (qual.index) {
        0 => try vmread(vmcs.Guest.cr0),
        3 => try vmread(vmcs.Guest.cr3),
        4 => try vmread(vmcs.Guest.cr4),
        else => {
            log.err("Unhandled CR read: {}", .{qual.index});
            unreachable;
        },
    };

    setValue(vcpu, qual, value);
}

fn passthroughWrite(vcpu: *Vcpu, qual: QualCr) VmxError!void {
    const value = getValue(vcpu, qual);
    switch (qual.index) {
        0 => {
            try vmwrite(vmcs.Guest.cr0, adjustCr0(value));
            try vmwrite(vmcs.Ctrl.cr0_read_shadow, value);
        },
        4 => {
            try vmwrite(vmcs.Guest.cr4, adjustCr4(value));
            try vmwrite(vmcs.Ctrl.cr4_read_shadow, value);
        },
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

fn setValue(vcpu: *Vcpu, qual: QualCr, value: u64) void {
    const gregs = &vcpu.guest_regs;
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
            log.err("Unhandled CR access to: {}", .{qual.reg});
            unreachable;
        },
    }
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
