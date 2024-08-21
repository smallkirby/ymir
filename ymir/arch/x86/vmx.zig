const std = @import("std");
const log = std.log.scoped(.vmx);
const Allocator = std.mem.Allocator;

const ymir = @import("ymir");
const mem = ymir.mem;
const Phys = mem.Phys;

const am = @import("asm.zig");
const vmcs = @import("vmx/vmcs.zig");
const regs = @import("vmx/regs.zig");

pub const VmxError = @import("vmx/error.zig").VmxError;
pub const VmxInstructionError = @import("vmx/error.zig").VmxInstructionError;

pub fn vmxtry(rflags: u64) VmxError!void {
    const flags: am.FlagsRegister = @bitCast(rflags);
    return if (flags.cf) VmxError.FailureInvalidVmcsPointer else if (flags.zf) VmxError.FailureStatusAvailable;
}

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

/// Adjust physical CPU's CR0 and CR4 registers.
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

/// Read VMCS revision identifier.
fn getVmcsRevisionId() u31 {
    const vmx_basic = am.readMsrVmxBasic();
    return vmx_basic.vmcs_revision_id;
}

/// Puts the logical processor in VMX operation with no VMCS loaded.
pub fn vmxon(page_allocator: Allocator) VmxError!void {
    // Set up VMXON region.
    // TODO: should return allocater VMXON region.
    const vmxon_region = try VmxonRegion.new(page_allocator);
    vmxon_region.vmcs_revision_id = getVmcsRevisionId();
    log.debug("VMCS revision ID: 0x{X:0>8}", .{vmxon_region.vmcs_revision_id});

    const vmxon_phys = mem.virt2phys(@intFromPtr(vmxon_region));
    log.debug("VMXON region physical address: 0x{X:0>16}", .{vmxon_phys});
    debugPrintVmxonValidity();

    try am.vmxon(vmxon_phys);
}

/// Exit VMX operation.
pub const vmxoff = am.vmxoff;

fn resetVmcs(vmcs_region: *VmcsRegion) VmxError!void {
    // The VMCS becomes inactive and flushed to memory.
    try am.vmclear(mem.virt2phys(@intFromPtr(vmcs_region)));
    // Load and activate the VMCS.
    try am.vmptrld(mem.virt2phys(@intFromPtr(vmcs_region)));
}

/// Set up VMCS for a logical processor.
/// TODO: This is a temporary implementation.
pub fn setupVmcs(page_allocator: Allocator) VmxError!void {
    // Init VMCS structure.
    // TODO: should return allocater VMCS region.
    const vmcs_region = try VmcsRegion.new(page_allocator);
    vmcs_region.vmcs_revision_id = getVmcsRevisionId();

    // Reset VMCS.
    try resetVmcs(vmcs_region);

    // Init fields.
    try setupExecCtrls();
    try setupExitCtrls();
    try setupEntryCtrls();

    // TODO
}

/// Set up VM-Execution control fields.
/// cf. SDM Vol.3C 27.2.1.1, Appendix A.3.
fn setupExecCtrls() VmxError!void {
    const basic_msr = am.readMsrVmxBasic();

    // Pin-based VM-Execution control.
    const pin_exec_ctrl = try vmcs.exec_control.PinBasedExecutionControl.get();
    try adjustRegMandatoryBits(
        pin_exec_ctrl,
        if (basic_msr.true_control) am.readMsr(.vmx_true_pinbased_ctls) else am.readMsr(.vmx_pinbased_ctls),
    ).load();

    // Primary Processor-based VM-Execution control.
    const ppb_exec_ctrl = try vmcs.exec_control.PrimaryProcessorBasedExecutionControl.get();
    try adjustRegMandatoryBits(
        ppb_exec_ctrl,
        if (basic_msr.true_control) am.readMsr(.vmx_true_procbased_ctls) else am.readMsr(.vmx_procbased_ctls),
    ).load();

    // CR-3 target.
    try vmcs.vmwrite(vmcs.control_cr3_target_count, 0);
}

/// Set up VM-Exit control fields.
/// cf. SDM Vol.3C 27.2.1.2.
fn setupExitCtrls() VmxError!void {
    const basic_msr = am.readMsrVmxBasic();

    // VM-Exit control.
    const exit_ctrl = try vmcs.exit_control.PrimaryExitControls.get();
    try adjustRegMandatoryBits(
        exit_ctrl,
        if (basic_msr.true_control) am.readMsr(.vmx_true_exit_ctls) else am.readMsr(.vmx_exit_ctls),
    ).load();
}

/// Set up VM-Entry control fields.
/// cf. SDM Vol.3C 27.2.1.3.
fn setupEntryCtrls() VmxError!void {
    const basic_msr = am.readMsrVmxBasic();

    // VM-Entry control.
    const entry_ctrl = try vmcs.entry_control.EntryControls.get();
    try adjustRegMandatoryBits(
        entry_ctrl,
        if (basic_msr.true_control) am.readMsr(.vmx_true_entry_ctls) else am.readMsr(.vmx_entry_ctls),
    ).load();
}

fn adjustRegMandatoryBits(control: anytype, mask: u64) @TypeOf(control) {
    var ret: u32 = @bitCast(control);
    ret |= @as(u32, @truncate(mask)); // Mandatory 1
    ret &= @as(u32, @truncate(mask >> 32)); // Mandatory 0
    return @bitCast(ret);
}

// TODO: template
pub fn launch() VmxError!void {
    // Launch VM.
    try am.vmlaunch();
}

/// Read error reason from the current logical processor's VMCS.
pub fn getErrorReason() VmxError!VmxInstructionError {
    return @enumFromInt(try vmcs.vmread(vmcs.ro_vminstruction_error));
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

    pub fn new(page_allocator: Allocator) VmxError!*align(4096) VmxonRegion {
        const page = page_allocator.alloc(u8, 4096) catch return VmxError.OutOfMemory;
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

    pub fn new(page_allocator: Allocator) VmxError!*align(4096) VmcsRegion {
        const page = try page_allocator.alloc(u8, 4096);
        if (page.len != 4096 or @intFromPtr(page.ptr) % 4096 != 0) {
            return error.OutOfMemory;
        }
        @memset(page, 0);
        return @alignCast(@ptrCast(page.ptr));
    }
};

test {
    std.testing.refAllDeclsRecursive(@This());

    std.testing.refAllDeclsRecursive(@import("vmx/vmcs.zig"));
}
