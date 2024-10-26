pub const arch = @import("arch.zig");
pub const bits = @import("bits.zig");
pub const klog = @import("log.zig");
pub const serial = @import("serial.zig");

const std = @import("std");
const testing = std.testing;

/// Halt endlessly with interrupts disabled.
pub fn endlessHalt() noreturn {
    arch.disableIntr();
    while (true) arch.halt();
}

test {
    testing.refAllDeclsRecursive(@This());
}
