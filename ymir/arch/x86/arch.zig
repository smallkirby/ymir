pub const cpuid = @import("cpuid.zig");
pub const gdt = @import("gdt.zig");
pub const intr = @import("interrupt.zig");
pub const page = @import("page.zig");
pub const pic = @import("pic.zig");
pub const serial = @import("serial.zig");

const am = @import("asm.zig");

/// Pause a CPU for a short period of time.
pub fn relax() void {
    am.relax();
}

/// Halt the current CPU.
pub inline fn halt() void {
    am.hlt();
}

/// Disable interrupts.
/// Note that exceptions and NMI are not ignored.
pub inline fn disableIntr() void {
    am.cli();
}

pub fn getCpuVendorId() [12]u8 {
    var ret: [12]u8 = undefined;
    const regs = cpuid.Leaf.query(.maximum_input, null);

    for ([_]u32{ regs.ebx, regs.edx, regs.ecx }, 0..) |reg, i| {
        for (0..4) |j| {
            const b: usize = (reg >> @truncate(j * 8));
            ret[i * 4 + j] = @as(u8, @truncate(b));
        }
    }
    return ret;
}

/// Check if virtualization technology is supported.
pub fn isVmxSupported() bool {
    // Check CPUID if VMX is supported.
    const regs = cpuid.Leaf.query(.vers_and_feat_info, null);
    const ecx: cpuid.FeatureInfoEcx = @bitCast(regs.ecx);
    if (!ecx.vmx) return false;

    // Check VMXON is allowed outside SMX.
    var msr_fctl: am.MsrFeatureControl = @bitCast(am.readMsr(.feature_control));
    if (!msr_fctl.vmx_outside_smx) {
        // Enable VMX outside SMX.
        if (msr_fctl.lock) @panic("IA32_FEATURE_CONTROL is locked while VMX outside SMX is disabled");
        msr_fctl.vmx_outside_smx = true;
        msr_fctl.lock = true;
        am.writeMsr(.feature_control, @bitCast(msr_fctl));
    }
    msr_fctl = @bitCast(am.readMsr(.feature_control));
    if (!msr_fctl.vmx_outside_smx) return false;

    return true;
}
