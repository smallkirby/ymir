const std = @import("std");

const surtr = @import("surtr");

/// Guard page placed below the kernel stack.
extern const __stackguard_lower: [*]const u8;

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
    // Validate the boot info.
    validateBootInfo(boot_info) catch {
        return error.InvalidBootInfo;
    };

    while (true) asm volatile ("hlt");
}

fn validateBootInfo(boot_info: surtr.BootInfo) !void {
    if (boot_info.magic != surtr.magic) {
        return error.InvalidMagic;
    }
}
