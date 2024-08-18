const std = @import("std");
const log = std.log.scoped(.vmx);
const Allocator = std.mem.Allocator;

const ymir = @import("ymir");
const mem = ymir.mem;
const Phys = mem.Phys;

const am = @import("asm.zig");
const vmcs = @import("vmcs.zig");

/// Enable VMX operations.
pub fn enableVmx() void {
    // Adjust control registers.
    adjustControlRegisters();

    // Check VMXON is allowed outside SMX.
    var msr = am.readMsrFeatureControl();
    if (!msr.vmx_outside_smx) {
        // Enable VMX outside SMX.
        if (msr.lock) @panic("IA32_FEATURE_CONTROL is locked while VMX outside SMX is disabled");
        msr.vmx_outside_smx = true;
        am.writeMsrFeatureControl(msr);
    }

    // Set VMXE bit in CR4.
    var cr4 = am.readCr4();
    cr4.vmxe = true;
    am.loadCr4(cr4);
}

fn adjustControlRegisters() void {
    const vmx_cr0_fixed0: u32 = @truncate(am.readMsr(.vmx_cr0_fixed0));
    const vmx_cr0_fixed1: u32 = @truncate(am.readMsr(.vmx_cr0_fixed1));
    const vmx_cr4_fixed0: u32 = @truncate(am.readMsr(.vmx_cr4_fixed0));
    const vmx_cr4_fixed1: u32 = @truncate(am.readMsr(.vmx_cr4_fixed1));

    var cr0: u64 = @bitCast(am.readCr0());
    cr0 |= vmx_cr0_fixed0; // Mandatory 1
    cr0 &= vmx_cr0_fixed1; // Mandatory 0
    var cr4: u64 = @bitCast(am.readCr4());
    cr4 |= vmx_cr4_fixed0; // Mandatory 1
    cr4 &= vmx_cr4_fixed1; // Mandatory 0;

    am.loadCr0(@bitCast(cr0));
    am.loadCr4(@bitCast(cr4));
}

fn getVmcsRevisionId() u31 {
    const vmx_basic = am.readMsrVmxBasic();
    return vmx_basic.vmcs_revision_id;
}

/// Puts the logical processor in VMX operation with no VMCS loaded.
pub fn vmxon(page_allocator: Allocator) !void {
    const vmxon_region = try VmxonRegion.new(page_allocator);
    vmxon_region.vmcs_revision_id = getVmcsRevisionId();
    log.debug("VMCS revision ID: 0x{X:0>8}", .{vmxon_region.vmcs_revision_id});

    const vmxon_phys = mem.virt2phys(@intFromPtr(vmxon_region));
    log.debug("VMXON region physical address: 0x{X:0>16}", .{vmxon_phys});

    debugPrintVmxonValidity();

    var rflags: u64 = undefined;
    asm volatile (
        \\clc
        \\vmxon (%[vmxon_phys])
        \\pushf
        \\popq %[rflags]
        : [rflags] "=r" (rflags),
        : [vmxon_phys] "r" (&vmxon_phys),
        : "cc", "memory"
    );

    // Check if VMXON succeeded.
    const flags: am.FlagsRegister = @bitCast(rflags);
    if (flags.cf) @panic("VMXON: VMCS pointer is invalid");
    if (flags.zf) @panic("VMXON: Error during VMXON");
}

/// Exit VMX operation.
pub fn vmxoff() void {
    asm volatile (
        \\vmxoff
        ::: "cc");
}

fn loadVmptr(vmcs_region: *align(4096) VmcsRegion) void {
    const vmcs_region_phys = mem.virt2phys(@intFromPtr(vmcs_region));
    var rflags: u64 = undefined;

    asm volatile (
        \\clc
        \\vmptrld (%[vmcs_region])
        \\pushf
        \\popq %%rflags
        : [rflags] "=r" (rflags),
        : [vmcs_region] "r" (&vmcs_region_phys),
    );

    const flags: am.FlagsRegister = @bitCast(rflags);
    if (flags.cf) @panic("VMPTRLD: VMCS pointer is invalid");
    if (flags.zf) @panic("VMPTRLD: Error during VMPTRLD");
}

fn debugPrintVmxonValidity() void {
    log.debug("VMX Validity", .{});

    const cpuid_feature = ymir.arch.getFeatureInformation();
    if (cpuid_feature.ecx.vmx) {
        log.debug("\t\tVMX is supported.", .{});
    } else @panic("\t\tVMX in CPUID not set");

    const feature_control = am.readMsrFeatureControl();
    if (feature_control.vmx_outside_smx) {
        log.debug("\t\tVMX outside SMX is enabled.", .{});
    } else @panic("\t\tVMX outside SMX is not enabled");
    if (feature_control.lock) {
        log.debug("\t\tIA32_FEATURE_CONTROL is locked.", .{});
    } else @panic("\t\tIA32_FEATURE_CONTROL is not locked");

    const vmx_basic = am.readMsrVmxBasic();
    log.debug("\t\tVMXON region size: 0x{X}", .{vmx_basic.vmxon_region_size});

    const vmx_cr0_fixed0: u32 = @truncate(am.readMsr(.vmx_cr0_fixed0));
    const vmx_cr0_fixed1: u32 = @truncate(am.readMsr(.vmx_cr0_fixed1));
    const vmx_cr4_fixed0: u32 = @truncate(am.readMsr(.vmx_cr4_fixed0));
    const vmx_cr4_fixed1: u32 = @truncate(am.readMsr(.vmx_cr4_fixed1));
    const cr0 = am.readCr0();
    const cr4 = am.readCr4();
    log.debug("\t\tCR0    : {b:0>32}", .{@as(u64, @bitCast(cr0))});
    log.debug("\t\tMask 0 : {b:0>32}", .{vmx_cr0_fixed1});
    log.debug("\t\tMask 1 : {b:0>32}", .{vmx_cr0_fixed0});
    log.debug("\t\tCR4    : {b:0>32}", .{@as(u64, @bitCast(cr4))});
    log.debug("\t\tMask 0 : {b:0>32}", .{vmx_cr4_fixed1});
    log.debug("\t\tMask 1 : {b:0>32}", .{vmx_cr4_fixed0});

    if (cr4.vmxe) {
        log.debug("\t\tVMXE bit is set.", .{});
    } else @panic("\t\tVMXE bit is not set");
}

pub const VmxonRegion = packed struct {
    vmcs_revision_id: u31,
    zero: u1 = 0,

    pub fn new(page_allocator: Allocator) !*align(4096) VmxonRegion {
        const page = try page_allocator.alloc(u8, 4096);
        if (page.len != 4096 or @intFromPtr(page.ptr) % 4096 != 0) {
            return error.OutOfMemory;
        }
        @memset(page, 0);
        return @alignCast(@ptrCast(page.ptr));
    }
};

pub const VmcsRegion = packed struct {
    /// VMCS revision identifier.
    vmcs_revision_id: u31,
    /// Must be zero.
    zero: u1 = 0,
    /// VMX-abort indicator.
    abort_indicator: u32,

    // VMCS data follows, but its exact layout is implementation-specific.
    // Use vmread/vmwrite with appropriate ComponentEncoding.

    pub fn new(page_allocator: Allocator) !*align(4096) VmcsRegion {
        const page = try page_allocator.alloc(u8, 4096);
        if (page.len != 4096 or @intFromPtr(page.ptr) % 4096 != 0) {
            return error.OutOfMemory;
        }
        @memset(page, 0);
        return @alignCast(@ptrCast(page.ptr));
    }
};
