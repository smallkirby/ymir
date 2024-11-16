const std = @import("std");
const option = @import("option");
const log = std.log.scoped(.main);

pub const default_log_options = std.Options{
    .log_level = switch (option.log_level) {
        .debug => .debug,
        .info => .info,
        .warn => .warn,
        .err => .err,
    },
    .logFn = log,
};

fn asmVmcall(nr: u64) void {
    asm volatile (
        \\movq %[nr], %%rax
        \\vmcall
        :
        : [nr] "rax" (nr),
        : "memory"
    );
}

pub fn main() !void {
    asmVmcall(0);
}
