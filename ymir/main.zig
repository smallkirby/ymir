//! Ymir: The hypervisor.
//!

const std = @import("std");
const log = std.log.scoped(.main);
const surtr = @import("surtr");

const ymir = @import("ymir");
const idefs = ymir.intr;
const serial = ymir.serial;
const klog = ymir.klog;
const arch = ymir.arch;
const mem = ymir.mem;
const vmx = ymir.vmx;
const BootstrapPageAllocator = ymir.mem.BootstrapPageAllocator;

const page_size = mem.page_size;

pub const panic = ymir.panic.panic_fn;
pub const std_options = klog.default_log_options;

/// Size in bytes pages of the kernel stack excluding the guard page.
const kstack_size = page_size * 5;
/// Kernel stack.
/// The first page is used as a guard page.
/// TODO: make the guard page read-only.
var kstack: [kstack_size + page_size]u8 align(page_size) = [_]u8{0} ** (kstack_size + page_size);

/// Kernel entry point called by surtr.
/// The function switches stack from the surtr stack to the kernel stack.
export fn kernelEntry() callconv(.Naked) noreturn {
    asm volatile (
        \\movq %[new_stack], %%rsp
        \\call kernelTrampoline
        :
        : [new_stack] "r" (@intFromPtr(&kstack) + kstack_size + page_size),
    );
}

/// Trampoline function to call the kernel main function.
/// The role of this function is to make main function return errors.
export fn kernelTrampoline(boot_info: surtr.BootInfo) callconv(.Win64) noreturn {
    kernelMain(boot_info) catch |err| {
        log.err("Kernel aborted with error: {}", .{err});
        @panic("Exiting...");
    };

    unreachable;
}

/// Kernel main function.
fn kernelMain(bs_boot_info: surtr.BootInfo) !void {
    // Initialize the serial console and logger.
    const sr = serial.init();
    klog.init(sr);
    log.info("Booting Ymir...", .{});

    // Validate the boot info.
    validateBootInfo(bs_boot_info) catch |err| {
        log.err("Invalid boot info: {}", .{err});
        return error.InvalidBootInfo;
    };

    // Copy boot_info into Ymir's stack since it becomes inaccessible soon.
    const guest_info = bs_boot_info.guest_info;
    const memory_map = bs_boot_info.memory_map;

    // Initialize GDT.
    // It switches GDT from the one prepared by surtr to the ymir GDT.
    arch.gdt.init();
    log.info("Initialized GDT.", .{});

    // Initialize IDT.
    // From this moment, interrupts are enabled.
    arch.intr.init();
    log.info("Initialized IDT.", .{});

    // Initialize BootstrapPageAllocator.
    BootstrapPageAllocator.init(memory_map);
    log.info("Initialized early stage page allocator.", .{});

    // Reconstruct memory mapping from the one provided by UEFI and Sutr.
    // This operation must be done before initializing allocators other than BootstrapPageAllocator,
    // that allocate pages from any usable regions.
    log.info("Reconstructing memory mapping...", .{});
    try mem.reconstructMapping();

    // Initialize page allocator.
    ymir.mem.initPageAllocator(memory_map);
    log.info("Initialized page allocator.", .{});

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

    // Check if VMX is supported.
    arch.enableCpuid();

    // Enable XSAVE features.
    arch.enableXstateFeature();

    // Enter VMX root operation.
    var vm = try vmx.Vm.new();
    try vm.init(ymir.mem.page_allocator);
    log.info("Entered VMX root operation.", .{});

    ymir.setVm(&vm);

    // Setup guest memory and load guest.
    const guest_kernel = b: {
        const ptr: [*]u8 = @ptrFromInt(ymir.mem.phys2virt(guest_info.guest_image));
        break :b ptr[0..guest_info.guest_size];
    };
    const initrd = b: {
        const ptr: [*]u8 = @ptrFromInt(ymir.mem.phys2virt(guest_info.initrd_addr));
        break :b ptr[0..guest_info.initrd_size];
    };
    try vm.setupGuestMemory(
        guest_kernel,
        initrd,
        ymir.mem.page_allocator,
        &ymir.mem.page_allocator_instance,
    );
    log.info("Setup guest memory.", .{});

    // Launch
    log.info("Starting the virtual machine...", .{});
    try vm.loop();

    // Exit VMX root operation.
    vm.devirtualize();

    // EOL
    log.info("Reached EOL.", .{});
    ymir.endlessHalt();
}

fn validateBootInfo(boot_info: surtr.BootInfo) !void {
    if (boot_info.magic != surtr.surtr_magic) {
        return error.InvalidMagic;
    }
}

fn blobIrqHandler(ctx: *arch.intr.Context) void {
    const vector: u16 = @intCast(ctx.vector - idefs.user_intr_base);
    arch.pic.notifyEoi(@enumFromInt(vector));
}
