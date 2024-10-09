const std = @import("std");
const Allocator = std.mem.Allocator;

const ymir = @import("ymir");
const mem = ymir.mem;

const vmx = @import("vmx/common.zig");
const ept = @import("vmx/ept.zig");

pub const Vcpu = @import("vmx/vcpu.zig").Vcpu;
pub const VmxError = vmx.VmxError;

/// Maps host pages to guest.
/// Host pages are mapped to 0 in the guest.
pub fn mapGuest(host_pages: []u8, allocator: Allocator) VmxError!ept.Eptp {
    return ept.initEpt(
        0,
        mem.virt2phys(host_pages.ptr),
        host_pages.len,
        allocator,
    );
}

test {
    std.testing.refAllDeclsRecursive(@This());
}
