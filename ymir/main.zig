//! Ymir: The hypervisor.
//!

const std = @import("std");
const log = std.log.scoped(.main);
const surtr = @import("surtr");

const ymir = @import("ymir");
const kbd = @import("keyboard.zig");
const idefs = @import("interrupts.zig");
const serial = ymir.serial;
const klog = ymir.klog;
const arch = ymir.arch;

pub const panic = @import("panic.zig").panic_fn;
pub const std_options = klog.default_log_options;

/// Kernel entry point called by the bootloader.
export fn kernelEntry(boot_info: surtr.BootInfo) callconv(.Win64) noreturn {
    kernelMain(boot_info) catch |err| {
        log.err("Kernel aborted with error: {}", .{err});
        @panic("Exiting...");
    };

    unreachable;
}

fn kernelMain(boot_info: surtr.BootInfo) !void {
    // Initialize the serial console and logger.
    const sr = serial.init();
    klog.init(sr);
    log.info("Booting Ymir...", .{});

    // Validate the boot info.
    validateBootInfo(boot_info) catch |err| {
        log.err("Invalid boot info: {}", .{err});
        return error.InvalidBootInfo;
    };

    // Initialize GDT.
    arch.gdt.init();
    log.info("Initialized GDT.", .{});

    // Initialize IDT.
    // From this moment, interrupts are enabled.
    arch.intr.init();
    log.info("Initialized IDT.", .{});

    // Initialize PIC.
    arch.pic.init();
    log.info("Initialized PIC.", .{});

    // Enable PIT.
    arch.pic.unsetMask(.Timer);
    arch.intr.registerHandler(idefs.pic_timer, blobTimerHandler);

    // Init PS/2 keyboard.
    kbd.init();

    // EOL
    log.info("Reached EOL.", .{});
    while (true)
        arch.halt();
}

fn validateBootInfo(boot_info: surtr.BootInfo) !void {
    if (boot_info.magic != surtr.surtr_magic) {
        return error.InvalidMagic;
    }
}

// TODO: temporary
fn blobTimerHandler(_: *arch.intr.Context) void {
    arch.pic.notifyEoi(.Timer);
}
