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

const VmError = error{
    /// Memory allocation failed.
    OutOfMemory,
    /// The system does not support virtualization.
    SystemNotSupported,
    /// Unknown error.
    UnknownError,
};
pub const Error = VmError || impl.VmxError;

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

    /// Virtualized logical CPU.
    vcpu: impl.Vcpu,
    /// Guest memory.
    guest_mem: []u8 = undefined,

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

        const vcpu = impl.Vcpu.new(1);
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

    /// Kick off the virtual machine.
    pub fn loop(self: *Self) Error!void {
        arch.disableIntr();
        try self.vcpu.loop();
    }

    /// Setup guest memory.
    pub fn setupGuestMemory(
        self: *Self,
        allocator: Allocator,
        page_allocator: *PageAllocator,
    ) Error!void {
        // Allocate guest memory.
        self.guest_mem = page_allocator.allocPages(
            guest_memory_size / mem.page_size_4k,
            mem.page_size_2mb, // This alignment is required because EPT maps 2MiB pages.
        ) orelse return Error.OutOfMemory;

        // Create simple EPT mapping.
        const eptp = try impl.mapGuest(self.guest_mem, allocator);
        try self.vcpu.setEptp(eptp, self.guest_mem.ptr);
        log.info("Guet memory is mapped: HVA=0x{X:0>16} (size=0x{X})", .{ @intFromPtr(self.guest_mem.ptr), self.guest_mem.len });
    }
};
