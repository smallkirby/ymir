const std = @import("std");
const log = std.log.scoped(.vmlapic);
const Allocator = std.mem.Allocator;

const ymir = @import("ymir");
const mem = ymir.mem;

const vmx = @import("../vmx.zig");
const pg = @import("../page.zig");
const ept = @import("ept.zig");
const vmcs = @import("vmcs.zig");
const emu = @import("emu.zig");
const Vcpu = vmx.Vcpu;
const VmxError = vmx.VmxError;

const lapic_base = 0xFEE0_0000;

/// Handle read access from the local APIC.
pub fn handleLapic(vcpu: *Vcpu, offset: usize) VmxError!void {
    const value = lapicRead(offset);
    const regs = &vcpu.guest_regs;

    const cr3 = try vmcs.vmread(vmcs.Guest.cr3);
    const inst_gva = try vmcs.vmread(vmcs.Guest.rip);
    const inst_gpa = pg.guestTranslateWalk(inst_gva, cr3, vcpu.guest_base) orelse {
        log.err("Failed to translate GVA to GPA: {X}", .{inst_gva});
        unreachable;
    };
    const inst_hpa = ept.translate(inst_gpa, vcpu.eptp.getLv4()) orelse {
        log.err("Failed to translate GPA to HPA: {X}", .{inst_gpa});
        unreachable;
    };
    const inst_hva = mem.phys2virt(inst_hpa);
    const inst: [*]u8 = @ptrFromInt(inst_hva);
    const inst_len = try vmcs.vmread(vmcs.Ro.vmexit_instruction_length);
    const dinst = emu.decode(inst[0..inst_len]) catch |err| abort(vcpu, "Failed to decode: {?}.", .{err});

    switch (dinst.op) {
        .mov2reg => switch (dinst.reg) {
            .ax => regs.rax = value,
            else => abort(vcpu, "VM: LAPIC: Unsupported register", .{}),
        },
        else => abort(vcpu, "Unsupported instruction", .{}),
    }
}

fn abort(vcpu: *Vcpu, comptime fmt: []const u8, args: anytype) noreturn {
    log.err(fmt, args);
    vcpu.abort();
}

/// Handle write access to the local APIC.
/// TODO: Assuming xAPIC mode (not x2APIC).
pub fn handleLapicWrite(vcpu: *Vcpu, offset: usize) VmxError!void {
    const lapic = &vcpu.virt_apic_regs;
    const written_value = lapic.get(offset);

    // TODO: For now, just pass-through the write.
    lapicWrite(offset, written_value);
}

fn lapicWrite(offset: usize, val: u32) void {
    const ptr: *u32 = @ptrFromInt(mem.phys2virt(lapic_base + offset));
    ptr.* = val;
}

fn lapicRead(offset: usize) u32 {
    const ptr: *u32 = @ptrFromInt(mem.phys2virt(lapic_base + offset));
    return ptr.*;
}

/// TODO: Document.
pub const VirtApicRegisters = struct {
    const Self = @This();

    /// Virtual-APIC page.
    page: []u8,

    pub fn new(allocator: Allocator) VmxError!Self {
        const page = allocator.alloc(u8, mem.page_size_4k) catch return VmxError.OutOfMemory;
        return Self{
            .page = page,
        };
    }

    /// Get the HPA of the virtual-APIC page.
    pub fn hpa(self: *Self) u64 {
        return mem.virt2phys(self.page.ptr);
    }

    /// Get the value of an register.
    pub fn get(self: *Self, offset: usize) u32 {
        // Registers are always 32-bit wide.
        const ptr: *u32 = @ptrFromInt(@intFromPtr(self.page.ptr) + offset);
        return ptr.*;
    }

    /// Set an register value.
    pub fn set(self: *Self, offset: Offsets, val: u32) void {
        // Registers are always 32-bit wide.
        const ptr: *u32 = @ptrFromInt(@intFromPtr(self.page.ptr) + @intFromEnum(offset));
        ptr.* = val;
    }

    const Offsets = enum(u16) {
        local_apic_id = 0x20,
        local_apic_version = 0x30,
        task_priority = 0x80,
        eoi = 0xB0,
        logical_dest = 0xD0,
        dest_fmt = 0xE0,
        spurious_intr_vec = 0xF0,
        err_status = 0x280,
        intr_cmd1 = 0x300,
        intr_cmd2 = 0x310,
        initial_count = 0x380,
        divide_conf = 0x3E0,
    };
};

/// IA32_APIC_BASE MSR.
pub const ApicBase = packed struct(u64) {
    /// Reserved.
    _reserved1: u8 = 0,
    /// Processor is BSP.
    bsp: bool,
    /// Reserved.
    _reserved2: u2 = 0,
    /// APIC global enable.
    global: bool,
    /// APIC base address.
    base: u24,
    /// Reserved.
    _reserved: u28 = 0,

    pub fn new(bsp: bool, enable: bool) ApicBase {
        return .{
            .base = lapic_base >> 12,
            .bsp = bsp,
            .global = enable,
        };
    }
};
