pub const boot = @import("linux/boot.zig");

pub const layout = struct {
    /// Where the kernel boot parameters are loaded, known as "zero page".
    /// Must be initialized by zeros.
    pub const bootparam = 0x0001_0000;
    /// Where the kernel cmdline is located.
    pub const cmdline = 0x0002_0000;
    /// Where the protected-mode kernel code is loaded
    pub const kernel_base = 0x0010_0000;
};
