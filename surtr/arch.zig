const builtin = @import("builtin");
pub usingnamespace switch (builtin.target.cpu.arch) {
    .x86_64 => @import("arch/x86/arch.zig"),
    else => @compileError("Unsupported architecture."),
};
