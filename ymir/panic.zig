//! This module provides a panic implementation.
//! Zig has panic impletentations for each target platform.
//! However, the impl for .freestanding is just a @breakpoint.
//! Therefore, we implement a simple panic handler here.

const std = @import("std");
const builtin = std.builtin;
const debug = std.debug;
const log = std.log.scoped(.panic);
const format = std.fmt.format;

const ymir = @import("ymir");
const vmx = ymir.vmx;
const serial = ymir.serial;
const arch = ymir.arch;

/// Implementation of the panic function.
pub const panic_fn = panic;

/// Instance of the initialized serial console.
var sr: serial.Serial = undefined;
/// Instance of the virtual machine.
var vm: ?*vmx.Vm = null;

/// Flag to indicate that a panic occurred.
var panicked = false;

const PanicError = error{};
const Writer = std.io.Writer(
    void,
    PanicError,
    writerFunction,
);

/// Set the target VM that is dumped when a panic occurs.
pub fn setVm(target_vm: *vmx.Vm) void {
    vm = target_vm;
}

fn write(comptime fmt: []const u8, args: anytype) void {
    format(
        Writer{ .context = {} },
        fmt,
        args,
    ) catch {};
}

fn writerFunction(_: void, bytes: []const u8) PanicError!usize {
    sr.write_string(bytes);
    return bytes.len;
}

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

    if (vm) |v| {
        v.vcpu.dump() catch |err| {
            log.err("Failed to dump VM information: {?}\n", .{err});
        };
    }

    ymir.endlessHalt();
}
