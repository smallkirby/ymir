const builtin = @import("builtin");
pub const is_debug = builtin.mode == .Debug;

pub const intr = @import("interrupts.zig");
pub const serial = @import("serial.zig");
pub const arch = @import("arch.zig");
pub const klog = @import("log.zig");
pub const linux = @import("linux.zig");
pub const mem = @import("mem.zig");
pub const spin = @import("spin.zig");
pub const vmx = @import("vmx.zig");
pub const panic = @import("panic.zig");
pub const util = @import("util.zig");

/// Base virtual address of direct mapping.
/// The virtual address starting from the address is directly mapped to the physical address at 0x0.
pub const direct_map_base = 0xFFFF_8880_0000_0000;
/// Size in bytes of the direct mapping region.
pub const direct_map_size = 512 * mem.gib;
/// The base virtual address of the kernel.
/// The virtual address strating from the address is directly mapped to the physical address at 0x0.
pub const kernel_base = 0xFFFF_FFFF_8000_0000;

/// Set the default VM.
pub fn setVm(target_vm: *vmx.Vm) void {
    panic.setVm(target_vm);
}

/// Halt endlessly with interrupts disabled.
pub fn endlessHalt() noreturn {
    arch.disableIntr();
    while (true) arch.halt();
}

test {
    @import("std").testing.refAllDeclsRecursive(@This());
}
