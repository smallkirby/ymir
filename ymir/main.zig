const std = @import("std");
const log = std.log.scoped(.main);

const surtr = @import("surtr");
const ymir = @import("ymir");
const klog = ymir.klog;
const serial = ymir.serial;
const arch = ymir.arch;
const mem = ymir.mem;
const idefs = ymir.idefs;

/// Guard page placed below the kernel stack.
extern const __stackguard_lower: [*]const u8;

pub const panic = ymir.panic.panic_fn;
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

    // Copy boot_info into Ymir's stack since it becomes inaccessible soon.
    const memory_map = boot_info.memory_map;

    // Initialize GDT.
    // It switches GDT from the one prepared by surtr to the ymir GDT.
    arch.gdt.init();
    log.info("Initialized GDT.", .{});

    // Initialize IDT.
    // From this moment, interrupts are enabled.
    arch.intr.init();
    log.info("Initialized IDT.", .{});

    // Initialize page allocator.
    ymir.mem.initPageAllocator(memory_map);
    log.info("Initialized page allocator.", .{});

    // Reconstruct memory mapping from the one provided by UEFI and Sutr.
    log.info("Reconstructing memory mapping...", .{});
    try mem.reconstructMapping(mem.page_allocator);

    // Now, stack, GDT, and page tables are switched to the ymir's ones.
    // We are ready to destroy any usable regions in UEFI memory map.

    // Initialize general allocator.
    ymir.mem.initGeneralAllocator();
    log.info("Initialized general allocator.", .{});

    // Initialize PIC.
    arch.pic.init();
    log.info("Initialized PIC.", .{});

    // Enable PIT.
    arch.intr.registerHandler(idefs.pic_timer, blobIrqHandler);
    arch.pic.unsetMask(.timer);
    log.info("Enabled PIT.", .{});

    // Unmask serial interrupt.
    arch.intr.registerHandler(idefs.pic_serial1, blobIrqHandler);
    arch.pic.unsetMask(.serial1);
    arch.serial.enableInterrupt(.com1);

    while (true) asm volatile ("hlt");
}

fn validateBootInfo(boot_info: surtr.BootInfo) !void {
    if (boot_info.magic != surtr.magic) {
        return error.InvalidMagic;
    }
}

fn blobIrqHandler(ctx: *arch.intr.Context) void {
    const vector: u16 = @intCast(ctx.vector - idefs.user_intr_base);
    log.debug("IRQ: {d}", .{vector});
    arch.pic.notifyEoi(@enumFromInt(vector));
}
