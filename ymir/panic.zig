const std = @import("std");
const builtin = std.builtin;
const debug = std.debug;
const log = std.log.scoped(.panic);
const format = std.fmt.format;

const ymir = @import("ymir");
const arch = ymir.arch;

/// Implementation of the panic function.
pub const panic_fn = panic;

/// Flag to indicate that a panic occurred.
var panicked = false;

fn panic(msg: []const u8, _: ?*builtin.StackTrace, _: ?usize) noreturn {
    @setCold(true);

    arch.disableIntr();

    log.err("{s}", .{msg});

    if (panicked) {
        log.err("Double panic detected. Halting.", .{});
        ymir.endlessHalt();
    }
    panicked = true;

    var it = std.debug.StackIterator.init(@returnAddress(), null);
    var ix: usize = 0;
    log.err("=== Stack Trace ==============", .{});
    while (it.next()) |frame| : (ix += 1) {
        log.err("#{d:0>2}: 0x{X:0>16}", .{ ix, frame });
    }

    ymir.endlessHalt();
}
