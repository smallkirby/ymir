pub const serial = @import("serial.zig");
pub const arch = @import("arch.zig").impl;
pub const klog = @import("log.zig");
pub const mem = @import("mem.zig");
pub const spin = @import("spin.zig");

/// Base virtual address of direct mapping.
/// The virtual address starting from the address is directly mapped to the physical address.
pub const direct_map_base = 0xFFFF_8880_0000_0000;
/// The base virtual address of the kernel.
/// The physical address to which this virtual address is mapped is undefined.
pub const kernel_base = @import("option").kernel_base;

test {
    @import("std").testing.refAllDeclsRecursive(@This());
}
