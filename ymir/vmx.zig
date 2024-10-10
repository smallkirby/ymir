const builtin = @import("builtin");
const std = @import("std");
const log = std.log.scoped(.vmx);
const Allocator = std.mem.Allocator;

const ymir = @import("ymir");
const arch = ymir.arch;
const mem = ymir.mem;
const PageAllocator = mem.PageAllocator;
const vmx = ymir.vmx;
const linux = ymir.linux;
const BootParams = linux.BootParams;
const spin = ymir.spin;

const impl = switch (builtin.target.cpu.arch) {
    .x86_64 => @import("arch/x86/vmx.zig"),
    else => @compileError("Unsupported architecture."),
};

const VmError = error{
    /// Memory allocation failed.
    OutOfMemory,
    /// The system does not support virtualization.
    SystemNotSupported,
    /// Unknown error.
    UnknownError,
};
pub const Error = VmError || impl.VmxError;

/// Next virtual processor ID.
var vpid_next: u16 = 0;
/// Global VMX lock.
var global_lock = spin.SpinLock{};

/// Size in bytes of the guest memory.
const guest_memory_size = 100 * mem.mib;
comptime {
    if (guest_memory_size % (2 * mem.mib) != 0) {
        @compileError("Guest memory size must be a multiple of 2MiB.");
    }
}

/// Virtual machine instance.
/// TODO: currently, supports only single CPU.
pub const Vm = struct {
    const Self = @This();

    /// Guest memory.
    guest_mem: []u8 = undefined,
    /// Virtualized logical CPU.
    vcpu: impl.Vcpu,

    /// Create a new virtual machine instance.
    /// You MUST initialize the VM before using it.
    pub fn new() VmError!Self {
        // TODO: check the number of CPUs and abort if it's not 1.
        // TODO: repeat the same process for all CPUs.

        // Check CPU vendor.
        const vendor = arch.getCpuVendorId();
        if (!std.mem.eql(u8, vendor[0..], "GenuineIntel")) {
            log.err("Unsupported CPU vendor: {s}", .{vendor});
            return Error.SystemNotSupported;
        }

        // Check if VMX is supported.
        if (!arch.isVmxSupported()) {
            log.err("Virtualization is not supported.", .{});
            return Error.SystemNotSupported;
        }

        const irq = global_lock.lockSaveIrq();
        const vpid = vpid_next;
        vpid_next += 1;
        global_lock.unlockRestoreIrq(irq);

        const vcpu = impl.Vcpu.new(vpid);
        return Self{
            .vcpu = vcpu,
        };
    }

    /// Initialize the virtual machine, entering VMX root operation.
    pub fn init(self: *Self, allocator: Allocator) Error!void {
        // Initialize vCPU.
        try self.vcpu.virtualize(allocator);
        log.info("vCPU #{X} is created.", .{self.vcpu.id});

        // Setup VMCS.
        try self.vcpu.setupVmcs(allocator);
    }

    /// Deinitialize the virtual machine, exiting VMX root operation.
    pub fn devirtualize(self: *Self) void {
        self.vcpu.devirtualize();
    }

    /// Setup guest memory and load a guest kernel on the memory.
    pub fn setupGuestMemory(
        self: *Self,
        guest_image: []u8,
        initrd: []u8,
        allocator: Allocator,
        page_allocator: *PageAllocator,
    ) Error!void {
        // Allocate guest memory.
        self.guest_mem = page_allocator.allocPages(
            guest_memory_size / mem.page_size_4k,
            mem.page_size_2mb, // This alignment is required because EPT maps 2MiB pages.
        ) orelse return Error.OutOfMemory;

        try self.loadKernel(guest_image, initrd);

        // Create simple EPT mapping.
        const eptp = try impl.mapGuest(self.guest_mem, allocator);
        try self.vcpu.setEptp(eptp, self.guest_mem.ptr);
        log.info("Guet memory is mapped: HVA=0x{X:0>16} (size=0x{X})", .{ @intFromPtr(self.guest_mem.ptr), self.guest_mem.len });

        // Make the pages read only.
        for (0..self.guest_mem.len / mem.page_size_2mb) |i| {
            arch.page.changePageAttribute(
                .m2,
                @intFromPtr(self.guest_mem.ptr) + i * mem.page_size_2mb,
                .read_only,
                allocator,
            ) catch {
                @panic("Failed to make guest memory read-only.");
            };
        }
        log.info("Guest memory is made read-only for Ymir.", .{});
    }

    /// Kick off the virtual machine.
    pub fn loop(self: *Self) Error!void {
        arch.disableIntr();
        try self.vcpu.loop();
    }

    /// Load a protected kernel image and cmdline to the guest physical memory.
    fn loadKernel(self: *Self, kernel: []u8, initrd: []u8) Error!void {
        const guest_mem = self.guest_mem;

        if (kernel.len + initrd.len >= guest_mem.len) {
            return Error.OutOfMemory;
        }

        var bp = BootParams.from(kernel);
        bp.e820_entries = 0;

        // Setup necessary fields
        bp.hdr.type_of_loader = 0xFF;
        bp.hdr.ext_loader_ver = 0;
        bp.hdr.loadflags.loaded_high = true; // load kernel at 0x10_0000
        bp.hdr.loadflags.can_use_heap = true; // use memory 0..BOOTPARAM as heap
        bp.hdr.heap_end_ptr = linux.layout.bootparam - 0x200;
        bp.hdr.loadflags.keep_segments = true; // we set CS/DS/SS/ES to flag segments with a base of 0.
        bp.hdr.cmd_line_ptr = linux.layout.cmdline;
        bp.hdr.vid_mode = 0xFFFF; // VGA (normal)

        // Setup E820 map
        bp.addE820entry(0, linux.layout.kernel_base, .ram);
        bp.addE820entry(
            linux.layout.kernel_base,
            guest_mem.len - linux.layout.kernel_base,
            .ram,
        );

        // Setup cmdline
        const cmdline_max_size = if (bp.hdr.cmdline_size < 256) bp.hdr.cmdline_size else 256;
        const cmdline = guest_mem[linux.layout.cmdline .. linux.layout.cmdline + cmdline_max_size];
        const cmdline_val = "console=ttyS0 earlyprintk=serial nokaslr";
        @memset(cmdline, 0);
        @memcpy(cmdline[0..cmdline_val.len], cmdline_val);

        // Load initrd
        if (guest_mem.len - linux.layout.initrd < initrd.len) {
            return Error.OutOfMemory;
        }
        if (bp.hdr.initrd_addr_max < linux.layout.initrd + initrd.len) {
            return Error.OutOfMemory;
        }
        bp.hdr.ramdisk_image = linux.layout.initrd;
        bp.hdr.ramdisk_size = @truncate(initrd.len);
        try loadImage(guest_mem, initrd, linux.layout.initrd);

        // Copy boot_params
        try loadImage(
            guest_mem,
            std.mem.asBytes(&bp),
            linux.layout.bootparam,
        );

        // Load protected-mode kernel code
        const code_offset = bp.hdr.getProtectedCodeOffset();
        const code_size = kernel.len - code_offset;
        try loadImage(
            guest_mem,
            kernel[code_offset .. code_offset + code_size],
            linux.layout.kernel_base,
        );
        if (linux.layout.kernel_base + code_size > guest_mem.len) {
            return Error.OutOfMemory;
        }

        log.info("Guest memory region: 0x{X:0>16} - 0x{X:0>16}", .{ 0, guest_mem.len });
        log.info("Guest kernel code offset: 0x{X:0>16}", .{code_offset});
    }

    fn loadImage(memory: []u8, image: []u8, addr: usize) !void {
        if (memory.len < addr + image.len) {
            return Error.OutOfMemory;
        }
        @memcpy(memory[addr .. addr + image.len], image);
    }
};
