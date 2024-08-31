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
const vmx = ymir.vmx;
const BootstrapPageAllocator = ymir.mem.BootstrapPageAllocator;

pub const panic = @import("panic.zig").panic_fn;
pub const std_options = klog.default_log_options;

/// Size in bytes pages of the kernel stack.
const kstack_size = arch.page_size * 5;
/// Kernel stack.
/// The first page is used as a guard page.
/// TODO: make the guard page read-only.
var kstack: [kstack_size + arch.page_size]u8 align(arch.page_size) = [_]u8{0} ** (kstack_size + arch.page_size);

/// Kernel entry point called by surtr.
/// The function switches stack from the surtr stack to the kernel stack.
export fn kernelEntry() callconv(.Naked) noreturn {
    asm volatile (
        \\movq %[new_stack], %%rsp
        \\call kernelTrampoline
        :
        : [new_stack] "r" (@intFromPtr(&kstack) + kstack_size + arch.page_size),
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

    // Copy guest info into Ymir's stack sice it becomes inaccessible soon.
    const guest_info = boot_info.guest_info;

    // Initialize GDT.
    // It switches GDT from the one prepared by surtr to the ymir GDT.
    arch.gdt.init();
    log.info("Initialized GDT.", .{});

    // Initialize IDT.
    // From this moment, interrupts are enabled.
    arch.intr.init();
    log.info("Initialized IDT.", .{});

    // Initialize BootstrapPageAllocator.
    BootstrapPageAllocator.init(boot_info.memory_map);
    log.info("Initialized early stage page allocator.", .{});

    // Clone page tables prepared by UEFI and surtr.
    // This operation must be done before initializing allocators other than BootstrapPageAllocator,
    // that allocate pages from any usable regions.
    log.info("Cloning UEFI page tables...", .{});
    try arch.page.cloneUefiPageTables();
    // Map direct map with offset region.
    log.info("Creating direct map region...", .{});
    try arch.page.directOffsetMap();

    // Initialize page allocator.
    ymir.mem.initPageAllocator(boot_info.memory_map);
    log.info("Initialized page allocator.", .{});

    // Now, stack, GDT, and page tables are switched to the ymir's ones.
    // We are ready to destroy any usable regions in UEFI memory map.

    // Unmap straight map region.
    // After this operation, memory map passed by UEFI is no longer used.
    log.info("Unmapping straight map region...", .{});
    try arch.page.unmapStraightMap();

    // Initialize general allocator.
    ymir.mem.initGeneralAllocator();
    log.info("Initialized general allocator.", .{});

    // Initialize PIC.
    arch.pic.init();
    log.info("Initialized PIC.", .{});

    // Enable PIT.
    arch.intr.registerHandler(idefs.pic_timer, blobTimerHandler);
    arch.pic.unsetMask(.Timer);
    log.info("Enabled PIT.", .{});

    // Init keyboard.
    kbd.init(.{ .serial = sr }); // TODO: make this configurable
    log.info("Initialized keyboard.", .{});

    // Check if VMX is supported.
    arch.enableCpuid();
    const vendor = arch.getCpuVendorId();
    log.info("CPU vendor: {s}", .{vendor});
    if (!std.mem.eql(u8, vendor[0..], "GenuineIntel")) @panic("Unsupported CPU vendor.");

    const feature = arch.getFeatureInformation();
    if (!feature.ecx.vmx) @panic("VMX is not supported.");

    // Enable VMX.
    vmx.enableVmx();
    log.info("Enabled VMX.", .{});

    // Enter VMX root operation.
    var vcpu = vmx.Vcpu.new();
    try vcpu.init(ymir.mem.page_allocator);
    log.info("Entered VMX root operation.", .{});

    // Setup VMCS
    try vcpu.setupVmcs();

    // Allocate guest pages.
    log.info("Guest kernel image @ {X:0>16} (0x{X}-bytes)", .{ @intFromPtr(guest_info.guest_image), guest_info.guest_size });
    const guest_memory_size = 0x100_000 * 100; // 100MB
    const guest_pages = ymir.mem.page_allocator_instance.allocPages(
        guest_memory_size,
        0x100_000 * 2, // 2MB
    ) orelse return error.OutOfMemory;
    log.info("Guest pages allocated at host memory @{X:0>16} (0x{X}-bytes)", .{ @intFromPtr(guest_pages.ptr), guest_memory_size });

    // TODO
    try vcpu.initGuestPage(guest_pages, ymir.mem.page_allocator);

    // Launch
    log.info("Entering VMX non-root operation...", .{});
    vcpu.loop() catch |err| switch (err) {
        error.FailureStatusAvailable => {
            log.err("VMLAUNCH failed: error={?}", .{try vmx.getInstError()});
            return err;
        },
        else => return err,
    };

    // Exit VMX root operation.
    log.info("Exiting VMX root operation...", .{});
    vcpu.vmxoff();

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
