const std = @import("std");
const log = std.log.scoped(.main);

const surtr = @import("surtr");
const ymir = @import("ymir");
const klog = ymir.klog;
const serial = ymir.serial;
const arch = ymir.arch;

/// Guard page placed below the kernel stack.
extern const __stackguard_lower: [*]const u8;

pub const std_options = klog.default_log_options;

/// Kernel entry point called by surtr.
/// The function switches stack from the surtr stack to the kernel stack.
export fn kernelEntry() callconv(.Naked) noreturn {
    asm volatile (
        \\movq %[new_stack], %%rsp
        \\call kernelTrampoline
        :
        : [new_stack] "r" (@intFromPtr(&__stackguard_lower) - 0x10),
    );
}

/// Trampoline function to call the kernel main function.
/// The role of this function is to make main function return errors.
export fn kernelTrampoline(boot_info: surtr.BootInfo) callconv(.Win64) noreturn {
    kernelMain(boot_info) catch {
        @panic("Exiting...");
    };

    unreachable;
}

/// Kernel main function.
fn kernelMain(boot_info: surtr.BootInfo) !void {
    // Initialize the serial console and logger.
    const sr = serial.init();
    klog.init(sr);
    log.info("Booting Ymir...", .{});

    // Validate the boot info.
    validateBootInfo(boot_info) catch {
        log.err("Invalid boot info", .{});
        return error.InvalidBootInfo;
    };

    // Initialize GDT.
    // It switches GDT from the one prepared by surtr to the ymir GDT.
    arch.gdt.init();
    log.info("Initialized GDT.", .{});

    // Initialize IDT.
    // From this moment, interrupts are enabled.
    arch.intr.init();
    log.info("Initialized IDT.", .{});

    while (true) asm volatile ("hlt");
}

fn validateBootInfo(boot_info: surtr.BootInfo) !void {
    if (boot_info.magic != surtr.magic) {
        return error.InvalidMagic;
    }
}
