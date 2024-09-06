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

const impl = switch (builtin.target.cpu.arch) {
    .x86_64 => @import("arch/x86/vmx.zig"),
    else => @compileError("Unsupported architecture."),
};

pub const VmError = error{
    /// Memory allocation failed.
    OutOfMemory,
    /// The system does not support virtualization.
    SystemNotSupported,
    /// Unknown error.
    UnknownError,
};
const Error = VmError;

/// Next virtual processor ID.
var vpid_next: u16 = 0;

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
        const feature = arch.getFeatureInformation();
        if (!feature.ecx.vmx) {
            log.err("Virtualization is not supported.", .{});
            return Error.SystemNotSupported;
        }

        const vpid = vpid_next;
        vpid_next += 1;

        const vcpu = impl.Vcpu.new(vpid);
        return Self{
            .vcpu = vcpu,
        };
    }

    /// Initialize the virtual machine, entering VMX root operation.
    pub fn init(self: *Self, allocator: Allocator) Error!void {
        // Enable virtualization.
        self.vcpu.enableVmx();

        // Initialize vCPU.
        self.vcpu.virtualize(allocator) catch return Error.UnknownError; // TODO
        log.info("vCPU #{X} is created.", .{self.vcpu.id});

        // Setup VMCS.
        self.vcpu.setupVmcs() catch return Error.UnknownError; // TODO
    }

    /// Deinitialize the virtual machine, exiting VMX root operation.
    pub fn devirtualize(self: *Self) void {
        self.vcpu.devirtualize();
    }

    /// Setup guest memory and load a guest kernel on the memory.
    pub fn setupGuestMemory(self: *Self, guest_image: []u8, allocator: Allocator, page_allocator: *PageAllocator) Error!void {
        const guest_memory_size = mem.mib * 100; // TODO: make this configurable
        self.guest_mem = page_allocator.allocPages(
            // This alignment is required because EPT maps 2MiB pages.
            guest_memory_size,
            mem.page_size_2mb,
        ) orelse return Error.OutOfMemory;

        try self.loadKernel(guest_image);

        self.vcpu.initGuestMap(
            self.guest_mem,
            allocator,
        ) catch return Error.UnknownError; // TODO
    }

    /// Kick off the virtual machine.
    pub fn loop(self: *Self) Error!void {
        self.vcpu.loop() catch return Error.UnknownError; // TODO
    }

    /// Load a protected kernel image and cmdline to the guest physical memory.
    fn loadKernel(self: *Self, kernel: []u8) Error!void {
        const guest_mem = self.guest_mem;

        if (kernel.len >= guest_mem.len) {
            return Error.OutOfMemory;
        }

        var boot_params = BootParams.from_bytes(kernel);

        // Setup necessary fields
        boot_params.hdr.type_of_loader = 0xFF;
        boot_params.hdr.ext_loader_ver = 0;
        boot_params.hdr.loadflags.loaded_high = true; // load kernel at 0x10_0000
        boot_params.hdr.loadflags.can_use_heap = true; // use memory 0..BOOTPARAM as heap
        boot_params.hdr.heap_end_ptr = linux.layout.bootparam - 0x200;
        boot_params.hdr.loadflags.keep_segments = true; // we set CS/DS/SS/ES to flag segments with a base of 0.
        boot_params.hdr.cmd_line_ptr = linux.layout.cmdline;
        boot_params.hdr.vid_mode = 0xFFFF; // VGA (normal)

        // Setup E820 map
        boot_params.add_e820_entry(0, linux.layout.kernel_base, .ram);
        boot_params.add_e820_entry(
            linux.layout.kernel_base,
            guest_mem.len - linux.layout.kernel_base,
            .ram,
        );

        // Setup cmdline
        const cmdline = guest_mem[linux.layout.cmdline .. linux.layout.cmdline + boot_params.hdr.cmdline_size];
        const cmdline_val = "console=ttyS0 earlyprintk=serial nokaslr";
        @memset(cmdline, 0);
        @memcpy(cmdline[0..cmdline_val.len], cmdline_val);

        // Copy boot_params
        try loadImage(
            guest_mem,
            std.mem.asBytes(&boot_params),
            linux.layout.bootparam,
        );

        // Load protected-mode kernel code
        const code_offset = boot_params.hdr.get_protected_code_offset();
        const code_size = kernel.len - code_offset;
        try loadImage(
            guest_mem,
            kernel[code_offset .. code_offset + code_size],
            linux.layout.kernel_base,
        );
        log.debug("Guest kernel code offset: 0x{X:0>16}", .{code_offset});
        if (linux.layout.kernel_base + code_size > guest_mem.len) {
            return Error.OutOfMemory;
        }
    }

    fn loadImage(memory: []u8, image: []u8, addr: usize) !void {
        if (memory.len < addr + image.len) {
            return Error.OutOfMemory;
        }
        @memcpy(memory[addr .. addr + image.len], image);
    }
};
