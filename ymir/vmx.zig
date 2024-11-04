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

        const vcpu = impl.Vcpu.new(0);
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
};
