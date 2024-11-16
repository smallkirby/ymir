const std = @import("std");
const log = std.log.scoped(.vmmsr);
const Allocator = std.mem.Allocator;

const ymir = @import("ymir");
const mem = ymir.mem;

const arch = @import("arch.zig");
const am = arch.am;

const vmx = @import("common.zig");
const vmcs = @import("vmcs.zig");

const Vcpu = @import("vcpu.zig").Vcpu;
const VmxError = vmx.VmxError;

/// Handle VM-exit caused by RDMSR instruction.
/// Note that this function does not increment the RIP.
pub fn handleRdmsrExit(vcpu: *Vcpu) VmxError!void {
    const guest_regs = &vcpu.guest_regs;
    const msr_kind: am.Msr = @enumFromInt(guest_regs.rcx);

    switch (msr_kind) {
        .apic_base => setRetVal(vcpu, std.math.maxInt(u64)),
        .efer => setRetVal(vcpu, try vmx.vmread(vmcs.guest.efer)),
        .fs_base => setRetVal(vcpu, try vmx.vmread(vmcs.guest.fs_base)),
        .gs_base => setRetVal(vcpu, try vmx.vmread(vmcs.guest.gs_base)),
        .kernel_gs_base => shadowRead(vcpu, msr_kind),
        else => {
            log.err("Unhandled RDMSR: {?}", .{msr_kind});
            vcpu.abort();
        },
    }
}

/// Handle VM-exit caused by WRMSR instruction.
/// Note that this function does not increment the RIP.
pub fn handleWrmsrExit(vcpu: *Vcpu) VmxError!void {
    const regs = &vcpu.guest_regs;
    const value = concat(regs.rdx, regs.rax);
    const msr_kind: am.Msr = @enumFromInt(regs.rcx);

    switch (msr_kind) {
        .star,
        .lstar,
        .cstar,
        .tsc_aux,
        .fmask,
        .kernel_gs_base,
        => shadowWrite(vcpu, msr_kind),
        .sysenter_cs => try vmx.vmwrite(vmcs.guest.sysenter_cs, value),
        .sysenter_eip => try vmx.vmwrite(vmcs.guest.sysenter_eip, value),
        .sysenter_esp => try vmx.vmwrite(vmcs.guest.sysenter_esp, value),
        .efer => try vmx.vmwrite(vmcs.guest.efer, value),
        .gs_base => try vmx.vmwrite(vmcs.guest.gs_base, value),
        .fs_base => try vmx.vmwrite(vmcs.guest.fs_base, value),
        else => {
            log.err("Unhandled WRMSR: {?}", .{msr_kind});
            vcpu.abort();
        },
    }
}

/// Concatnate two 32-bit values into a 64-bit value.
fn concat(r1: u64, r2: u64) u64 {
    return ((r1 & 0xFFFF_FFFF) << 32) | (r2 & 0xFFFF_FFFF);
}

/// Set the 64-bit return value to the guest registers.
fn setRetVal(vcpu: *Vcpu, val: u64) void {
    const regs = &vcpu.guest_regs;
    @as(*u32, @ptrCast(&regs.rdx)).* = @as(u32, @truncate(val >> 32));
    @as(*u32, @ptrCast(&regs.rax)).* = @as(u32, @truncate(val));
}

/// Read from the shadow MSR.
fn shadowRead(vcpu: *Vcpu, msr_kind: am.Msr) void {
    if (vcpu.guest_msr.find(msr_kind)) |msr| {
        setRetVal(vcpu, msr.data);
    } else {
        log.err("RDMSR: MSR is not registered: {s}", .{@tagName(msr_kind)});
        vcpu.abort();
    }
}

/// Write to the shadow MSR.
fn shadowWrite(vcpu: *Vcpu, msr_kind: am.Msr) void {
    const regs = &vcpu.guest_regs;
    if (vcpu.guest_msr.find(msr_kind)) |_| {
        vcpu.guest_msr.set(msr_kind, concat(regs.rdx, regs.rax));
    } else {
        log.err("WRMSR: MSR is not registered: {s}", .{@tagName(msr_kind)});
        vcpu.abort();
    }
}

/// Shadow MSR page.
pub const ShadowMsr = struct {
    /// Maximum number of MSR entries in a page.
    const max_num_ents = 512;

    /// MSR entries.
    ents: []SavedMsr,
    /// Number of registered MSR entries.
    num_ents: usize = 0,

    /// MSR Entry.
    /// cf. SDM Vol.3C. 25.7.2. Table 25-15.
    pub const SavedMsr = packed struct(u128) {
        index: u32,
        reserved: u32 = 0,
        data: u64,
    };

    /// Initialize saved MSR page.
    pub fn init(allocator: Allocator) !ShadowMsr {
        const ents = try allocator.alloc(SavedMsr, max_num_ents);
        @memset(ents, std.mem.zeroes(SavedMsr));

        return ShadowMsr{
            .ents = ents,
        };
    }

    /// Register or update MSR entry.
    pub fn set(self: *ShadowMsr, index: am.Msr, data: u64) void {
        return self.setByIndex(@intFromEnum(index), data);
    }

    /// Register or update MSR entry indexed by `index`.
    pub fn setByIndex(self: *ShadowMsr, index: u32, data: u64) void {
        for (0..self.num_ents) |i| {
            if (self.ents[i].index == index) {
                self.ents[i].data = data;
                return;
            }
        }
        self.ents[self.num_ents] = SavedMsr{ .index = index, .data = data };
        self.num_ents += 1;
        if (self.num_ents > max_num_ents) {
            @panic("Too many MSR entries registered.");
        }
    }

    /// Get the saved MSRs.
    pub fn savedEnts(self: *ShadowMsr) []SavedMsr {
        return self.ents[0..self.num_ents];
    }

    /// Find the saved MSR entry.
    pub fn find(self: *ShadowMsr, index: am.Msr) ?*SavedMsr {
        const index_num = @intFromEnum(index);
        for (0..self.num_ents) |i| {
            if (self.ents[i].index == index_num) {
                return &self.ents[i];
            }
        }
        return null;
    }

    /// Get the host physical address of the MSR page.
    pub fn phys(self: *ShadowMsr) u64 {
        return mem.virt2phys(self.ents.ptr);
    }
};
