const std = @import("std");
const log = std.log.scoped(.vmxpage);

const am = @import("../asm.zig");
const Vcpu = @import("../vmx.zig").Vcpu;

/// Invalidate mappings associated with the EPTP of the given VCPU.
pub fn invalidateEpt(vcpu: *Vcpu, inv_type: InveptType) void {
    var inv_desc: InveptDescriptor align(64) = .{
        .eptp = @bitCast(vcpu.eptp),
    };

    switch (inv_type) {
        .single_context, .global => am.invept(
            @as(u64, @intFromEnum(inv_type)),
            @ptrCast(&inv_desc),
        ),
    }
}

/// Invalidate mappings associated with the VPID of the given VCPU.
pub fn invalidateVpid(vcpu: *Vcpu, inv_type: InvvpidType) void {
    var vpid_desc: InvvpidDescriptor align(64) = .{
        .vpid = vcpu.vpid,
    };

    switch (inv_type) {
        .all_addr,
        .almost_all_vpid,
        => am.invvpid(
            @as(u64, @intFromEnum(inv_type)),
            @ptrCast(&vpid_desc),
        ),
        .single_addr => {
            log.err("Invalidation of single address is not supported yet.", .{});
            vcpu.abort();
        },
    }
}

/// INVVPID descriptor.
const InvvpidDescriptor = packed struct(u128) {
    /// VPID (Virtual Processor Identifier).
    vpid: u16,
    /// ReservedZ.
    _reserved: u48 = 0,
    /// Guest virtual address.
    guest_va: u64 = 0,
};

const InvvpidType = enum(u64) {
    /// Invalidates mappings for the linear address and VPID.
    single_addr = 0,
    /// Invalidates all mappings tagged with VPID.
    all_addr = 1,
    /// Invalidates all mappings tagged with all VPIDs except VIPD 0x0000.
    almost_all_vpid = 2,
};

const InveptDescriptor = packed struct(u128) {
    /// EPTP.
    eptp: u64,
    /// ReservedZ.
    _reserved: u64 = 0,
};

const InveptType = enum(u64) {
    /// Invalidates mappings for the EPTP.
    single_context = 1,
    /// Invalidates all mappings.
    global = 2,
};
