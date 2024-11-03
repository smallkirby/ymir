const std = @import("std");
const log = std.log.scoped(.vcpu);
const Allocator = std.mem.Allocator;

const ymir = @import("ymir");
const mem = ymir.mem;

const arch = @import("arch.zig");
const am = arch.am;

const vmx = @import("common.zig");
const VmxError = vmx.VmxError;

pub const Vcpu = struct {
    const Self = @This();

    /// ID of the logical processor.
    id: usize = 0,
    /// VPID of the virtual machine.
    vpid: u16 = 0,
    /// VMXON region.
    vmxon_region: *VmxonRegion = undefined,

    /// Create a new virtual CPU.
    /// This function does not virtualize the CPU.
    /// You MUST call `virtualize` to put the CPU in VMX root operation.
    pub fn new(vpid: u16) Self {
        return Self{
            .id = 0,
            .vpid = vpid,
        };
    }

    /// Enter VMX root operation and allocate VMCS region for this LP.
    pub fn virtualize(self: *Self, allocator: Allocator) VmxError!void {
        // Adjust control registers.
        adjustControlRegisters();

        // Set VMXE bit in CR4.
        var cr4 = am.readCr4();
        cr4.vmxe = true;
        am.loadCr4(cr4);

        // Enter VMX root operation.
        self.vmxon_region = try vmxon(allocator);
    }

    /// Exit VMX operation.
    pub fn devirtualize(_: *Self) void {
        am.vmxoff();
    }
};

/// VMXON region.
/// cf. SDM Vol.3C 25.11.5.
const VmxonRegion = packed struct {
    vmcs_revision_id: u31,
    zero: u1 = 0,

    /// Allocate VMXON region.
    pub fn new(page_allocator: Allocator) VmxError!*align(mem.page_size) VmxonRegion {
        const size = am.readMsrVmxBasic().vmxon_region_size;
        const page = page_allocator.alloc(u8, size) catch return VmxError.OutOfMemory;
        if (@intFromPtr(page.ptr) % mem.page_size != 0) {
            return error.OutOfMemory;
        }
        @memset(page, 0);
        return @alignCast(@ptrCast(page.ptr));
    }

    pub fn deinit(self: *VmxonRegion, page_allocator: Allocator) void {
        const size = am.readMsrVmxBasic().vmxon_region_size;
        const ptr: [*]u8 = @ptrCast(self);
        page_allocator.free(ptr[0..size]);
    }
};

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

    am.loadCr0(cr0);
    am.loadCr4(cr4);
}

/// Read VMCS revision identifier.
inline fn getVmcsRevisionId() u31 {
    return am.readMsrVmxBasic().vmcs_revision_id;
}

/// Puts the logical processor in VMX operation with no VMCS loaded.
fn vmxon(allocator: Allocator) VmxError!*VmxonRegion {
    // Set up VMXON region.
    const vmxon_region = try VmxonRegion.new(allocator);
    vmxon_region.vmcs_revision_id = getVmcsRevisionId();
    log.debug("VMCS revision ID: 0x{X:0>8}", .{vmxon_region.vmcs_revision_id});

    const vmxon_phys = mem.virt2phys(vmxon_region);
    log.debug("VMXON region physical address: 0x{X:0>16}", .{vmxon_phys});

    am.vmxon(vmxon_phys) catch |err| {
        vmxon_region.deinit(allocator);
        return err;
    };

    return vmxon_region;
}
