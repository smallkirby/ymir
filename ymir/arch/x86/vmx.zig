const std = @import("std");
const Allocator = std.mem.Allocator;

const ymir = @import("ymir");
const mem = ymir.mem;

const am = @import("asm.zig");

/// Enable VMX operations.
pub fn enableVmx() void {
    // Set VMXE bit in CR4.
    var cr4 = am.readCr4();
    cr4 |= 1 << 13; // VMXE
    am.loadCr4(cr4);

    // Check VMXON is allowed outside SMX.
    var msr = am.readMsrFeatureControl();
    if (!msr.vmx_outside_smx) {
        // Enable VMX outside SMX.
        if (msr.lock) @panic("IA32_FEATURE_CONTROL is locked while VMX outside SMX is disabled");
        msr.vmx_outside_smx = true;
        am.writeMsrFeatureControl(msr);
    }
}

/// Puts the logical processor in VMX operation with no VMCS loaded.
pub fn vmxon(page_allocator: Allocator) !void {
    const vmxon_region = page_allocator.alloc(u8, 4096) catch |err| return err;
    @memset(vmxon_region, 0);
    const vmcs_revision_id: *u32 = @alignCast(@ptrCast(vmxon_region.ptr));
    vmcs_revision_id.* = 0xDEADBEEF; // TODO

    asm volatile (
        \\vmxon %[vmxon_region]
        :
        : [vmxon_region] "m" (@intFromPtr(vmxon_region.ptr)),
        : "memory"
    );

    // Check if VMXON succeeded.
    const flags = am.readEflags();
    if (flags.cf) @panic("VMXON: VMCS pointer is invalid");
    if (flags.zf) @panic("VMXON: Error during VMXON");
}
