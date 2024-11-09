const std = @import("std");
const log = std.log.scoped(.vcpu);
const Allocator = std.mem.Allocator;

const ymir = @import("ymir");
const mem = ymir.mem;

const arch = @import("arch.zig");
const am = arch.am;

const vmx = @import("common.zig");
const vmcs = @import("vmcs.zig");
const vmam = @import("asm.zig");
const ept = @import("ept.zig");
const VmxError = vmx.VmxError;
const vmread = vmx.vmread;
const vmwrite = vmx.vmwrite;

const Phys = mem.Phys;

pub const Vcpu = struct {
    const Self = @This();

    /// ID of the logical processor.
    id: usize = 0,
    /// VPID of the virtual machine.
    vpid: u16,
    /// VMXON region.
    vmxon_region: *VmxonRegion = undefined,
    /// VMCS region.
    vmcs_region: *VmcsRegion = undefined,
    /// The first VM-entry has been done.
    launch_done: bool = false,
    /// Saved guest registers.
    guest_regs: vmx.GuestRegisters = undefined,
    /// EPT pointer.
    eptp: ept.Eptp = undefined,
    /// Host physical address where the guest is mapped.
    guest_base: Phys = undefined,

    /// Create a new virtual CPU.
    /// This function does not virtualize the CPU.
    /// You MUST call `virtualize` to put the CPU in VMX root operation.
    pub fn new(vpid: u16) Self {
        return Self{
            .id = 0,
            .vpid = vpid,
        };
    }

    /// Enter VMX root operation and allocate VMCS region for this LP.
    pub fn virtualize(self: *Self, allocator: Allocator) VmxError!void {
        // Adjust control registers.
        adjustControlRegisters();

        // Set VMXE bit in CR4.
        var cr4 = am.readCr4();
        cr4.vmxe = true;
        am.loadCr4(cr4);

        // Enter VMX root operation.
        self.vmxon_region = try vmxon(allocator);
    }

    /// Exit VMX operation.
    pub fn devirtualize(_: *Self) void {
        am.vmxoff();
    }

    /// Set up VMCS for a logical processor.
    pub fn setupVmcs(self: *Self, allocator: Allocator) VmxError!void {
        // Initialize VMCS region.
        const vmcs_region = try VmcsRegion.new(allocator);
        vmcs_region.vmcs_revision_id = getVmcsRevisionId();
        self.vmcs_region = vmcs_region;

        // Reset VMCS.
        try resetVmcs(self.vmcs_region);

        // Initialize VMCS fields.
        try setupExecCtrls(self, allocator);
        try setupExitCtrls(self);
        try setupEntryCtrls(self);
        try setupHostState(self);
        try setupGuestState(self);
    }

    /// Start executing vCPU.
    pub fn loop(self: *Self) VmxError!void {
        // Copy blobGuest() to the guest memory at physical address 0x0.
        const func: [*]const u8 = @ptrCast(&blobGuest);
        const guest_map: [*]u8 = @ptrFromInt(mem.phys2virt(self.guest_base));
        @memcpy(guest_map[0..0x20], func[0..0x20]);
        try vmwrite(vmcs.guest.rip, 0);

        // Start endless VM-entry / VM-exit loop.
        while (true) {
            // Enter VMX non-root operation.
            self.vmentry() catch |err| {
                log.err("VM-entry failed: {?}", .{err});
                if (err == VmxError.VmxStatusAvailable) {
                    const inst_err = try vmx.InstructionError.load();
                    log.err("VM Instruction error: {?}", .{inst_err});
                }
                self.abort();
            };

            // Handle VM-exit.
            try self.handleExit(try vmx.ExitInfo.load());
        }
    }

    /// Set EPTP to the vCPU.
    pub fn setEptp(self: *Self, eptp: ept.Eptp, host_start: [*]u8) VmxError!void {
        self.eptp = eptp;
        self.guest_base = ymir.mem.virt2phys(host_start);
        try vmwrite(vmcs.ctrl.eptp, eptp);
    }

    // Enter VMX non-root operation.
    fn vmentry(self: *Self) VmxError!void {
        const success = asm volatile (
            \\mov %[self], %%rdi
            \\call asmVmEntry
            : [ret] "={ax}" (-> u8),
            : [self] "r" (self),
            : "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"
        ) == 0;

        if (!self.launch_done and success) {
            self.launch_done = true;
        }

        if (!success) {
            const inst_err = try vmread(vmcs.ro.vminstruction_error);
            return if (inst_err != 0) VmxError.VmxStatusAvailable else VmxError.VmxStatusUnavailable;
        }
    }

    /// Handle the VM-exit.
    fn handleExit(self: *Self, exit_info: vmx.ExitInfo) VmxError!void {
        switch (exit_info.basic_reason) {
            .hlt => {
                try self.stepNextInst();
                log.debug("HLT", .{});
            },
            else => {
                log.err("Unhandled VM-exit: reason={?}", .{exit_info.basic_reason});
                self.abort();
            },
        }
    }

    /// Increment RIP by the length of the current instruction.
    fn stepNextInst(_: *Self) VmxError!void {
        const rip = try vmread(vmcs.guest.rip);
        try vmwrite(vmcs.guest.rip, rip + try vmread(vmcs.ro.exit_inst_len));
    }

    /// Print guest state and stack trace, and abort.
    pub fn abort(self: *Self) noreturn {
        @setCold(true);
        self.dump() catch log.err("Failed to dump VM information.", .{});
        ymir.endlessHalt();
    }

    /// Dump guest state and guest stack trace.
    pub fn dump(self: *Self) VmxError!void {
        try self.printGuestState();
    }

    fn printGuestState(self: *Self) VmxError!void {
        log.err("=== vCPU Information ===", .{});
        log.err("[Guest State]", .{});
        log.err("RIP: 0x{X:0>16}", .{try vmread(vmcs.guest.rip)});
        log.err("RSP: 0x{X:0>16}", .{try vmread(vmcs.guest.rsp)});
        log.err("RAX: 0x{X:0>16}", .{self.guest_regs.rax});
        log.err("RBX: 0x{X:0>16}", .{self.guest_regs.rbx});
        log.err("RCX: 0x{X:0>16}", .{self.guest_regs.rcx});
        log.err("RDX: 0x{X:0>16}", .{self.guest_regs.rdx});
        log.err("RSI: 0x{X:0>16}", .{self.guest_regs.rsi});
        log.err("RDI: 0x{X:0>16}", .{self.guest_regs.rdi});
        log.err("RBP: 0x{X:0>16}", .{self.guest_regs.rbp});
        log.err("R8 : 0x{X:0>16}", .{self.guest_regs.r8});
        log.err("R9 : 0x{X:0>16}", .{self.guest_regs.r9});
        log.err("R10: 0x{X:0>16}", .{self.guest_regs.r10});
        log.err("R11: 0x{X:0>16}", .{self.guest_regs.r11});
        log.err("R12: 0x{X:0>16}", .{self.guest_regs.r12});
        log.err("R13: 0x{X:0>16}", .{self.guest_regs.r13});
        log.err("R14: 0x{X:0>16}", .{self.guest_regs.r14});
        log.err("R15: 0x{X:0>16}", .{self.guest_regs.r15});
        log.err("CR0: 0x{X:0>16}", .{try vmread(vmcs.guest.cr0)});
        log.err("CR3: 0x{X:0>16}", .{try vmread(vmcs.guest.cr3)});
        log.err("CR4: 0x{X:0>16}", .{try vmread(vmcs.guest.cr4)});
        log.err("EFER:0x{X:0>16}", .{try vmread(vmcs.guest.efer)});
        log.err(
            "CS : 0x{X:0>4} 0x{X:0>16} 0x{X:0>8}",
            .{
                try vmread(vmcs.guest.cs_sel),
                try vmread(vmcs.guest.cs_base),
                try vmread(vmcs.guest.cs_limit),
            },
        );
    }
};

/// Adjust physical CPU's CR0 and CR4 registers.
fn adjustControlRegisters() void {
    const vmx_cr0_fixed0: u32 = @truncate(am.readMsr(.vmx_cr0_fixed0));
    const vmx_cr0_fixed1: u32 = @truncate(am.readMsr(.vmx_cr0_fixed1));
    const vmx_cr4_fixed0: u32 = @truncate(am.readMsr(.vmx_cr4_fixed0));
    const vmx_cr4_fixed1: u32 = @truncate(am.readMsr(.vmx_cr4_fixed1));

    var cr0: u64 = @bitCast(am.readCr0());
    cr0 |= vmx_cr0_fixed0; // Mandatory 1
    cr0 &= vmx_cr0_fixed1; // Mandatory 0
    var cr4: u64 = @bitCast(am.readCr4());
    cr4 |= vmx_cr4_fixed0; // Mandatory 1
    cr4 &= vmx_cr4_fixed1; // Mandatory 0;

    am.loadCr0(cr0);
    am.loadCr4(cr4);
}

/// Clear and reset VMCS.
/// After this operation, the VMCS becomes active and current logical processor.
fn resetVmcs(vmcs_region: *VmcsRegion) VmxError!void {
    // The VMCS becomes inactive and flushed to memory.
    try am.vmclear(mem.virt2phys(vmcs_region));
    // Load and activate the VMCS.
    try am.vmptrld(mem.virt2phys(vmcs_region));
}

fn setupExecCtrls(vcpu: *Vcpu, _: Allocator) VmxError!void {
    const basic_msr = am.readMsrVmxBasic();

    // Pin-based VM-Execution control.
    const pin_exec_ctrl = try vmcs.PinExecCtrl.store();
    try adjustRegMandatoryBits(
        pin_exec_ctrl,
        if (basic_msr.true_control) am.readMsr(.vmx_true_pinbased_ctls) else am.readMsr(.vmx_pinbased_ctls),
    ).load();

    // Primary Processor-based VM-Execution control.
    var ppb_exec_ctrl = try vmcs.PrimaryProcExecCtrl.store();
    ppb_exec_ctrl.activate_secondary_controls = true;
    ppb_exec_ctrl.use_tpr_shadow = false;
    try adjustRegMandatoryBits(
        ppb_exec_ctrl,
        if (basic_msr.true_control) am.readMsr(.vmx_true_procbased_ctls) else am.readMsr(.vmx_procbased_ctls),
    ).load();

    // Secondary Processor-based VM-Execution control.
    var ppb_exec_ctrl2 = try vmcs.SecondaryProcExecCtrl.store();
    ppb_exec_ctrl2.unrestricted_guest = true;
    ppb_exec_ctrl2.ept = true;
    ppb_exec_ctrl2.vpid = isVpidSupported();
    try adjustRegMandatoryBits(
        ppb_exec_ctrl2,
        am.readMsr(.vmx_procbased_ctls2),
    ).load();

    // VPID
    if (isVpidSupported()) {
        try vmwrite(vmcs.ctrl.vpid, vcpu.vpid);
    }
}

fn setupExitCtrls(_: *Vcpu) VmxError!void {
    const basic_msr = am.readMsrVmxBasic();

    // VM-Exit control.
    var exit_ctrl = try vmcs.PrimaryExitCtrl.store();
    exit_ctrl.host_addr_space_size = true;
    exit_ctrl.load_ia32_efer = true;
    try adjustRegMandatoryBits(
        exit_ctrl,
        if (basic_msr.true_control) am.readMsr(.vmx_true_exit_ctls) else am.readMsr(.vmx_exit_ctls),
    ).load();
}

fn setupEntryCtrls(_: *Vcpu) VmxError!void {
    const basic_msr = am.readMsrVmxBasic();

    // VM-Entry control.
    var entry_ctrl = try vmcs.EntryCtrl.store();
    entry_ctrl.ia32e_mode_guest = false;
    try adjustRegMandatoryBits(
        entry_ctrl,
        if (basic_msr.true_control) am.readMsr(.vmx_true_entry_ctls) else am.readMsr(.vmx_entry_ctls),
    ).load();
}

fn setupHostState(_: *Vcpu) VmxError!void {
    // Control registers.
    try vmwrite(vmcs.host.cr0, am.readCr0());
    try vmwrite(vmcs.host.cr3, am.readCr3());
    try vmwrite(vmcs.host.cr4, am.readCr4());

    // General registers.
    try vmwrite(vmcs.host.rip, &vmam.asmVmExit);

    // Segment registers.
    try vmwrite(vmcs.host.cs_sel, am.readSegSelector(.cs));
    try vmwrite(vmcs.host.ss_sel, am.readSegSelector(.ss));
    try vmwrite(vmcs.host.ds_sel, am.readSegSelector(.ds));
    try vmwrite(vmcs.host.es_sel, am.readSegSelector(.es));
    try vmwrite(vmcs.host.fs_sel, am.readSegSelector(.fs));
    try vmwrite(vmcs.host.gs_sel, am.readSegSelector(.gs));
    try vmwrite(vmcs.host.tr_sel, am.readSegSelector(.tr));
    try vmwrite(vmcs.host.gs_base, am.readMsr(.gs_base));
    try vmwrite(vmcs.host.fs_base, am.readMsr(.fs_base));
    try vmwrite(vmcs.host.tr_base, 0); // Not used in Ymir.
    try vmwrite(vmcs.host.gdtr_base, am.sgdt().base);
    try vmwrite(vmcs.host.idtr_base, am.sidt().base);

    // MSR.
    try vmwrite(vmcs.host.efer, am.readMsr(.efer));
}

fn setupGuestState(_: *Vcpu) VmxError!void {
    // Control registers.
    var cr0 = std.mem.zeroes(am.Cr0);
    cr0.pe = true; // Protected-mode
    cr0.ne = true; // Numeric error
    cr0.et = true; // Extension type
    cr0.pg = false; // Paging
    try vmwrite(vmcs.guest.cr0, cr0);
    try vmwrite(vmcs.guest.cr3, am.readCr3());
    try vmwrite(vmcs.guest.cr4, am.readCr4());

    // TODO: CR0/CR4 shadow

    // Segment registers.
    {
        // Base
        try vmwrite(vmcs.guest.cs_base, 0);
        try vmwrite(vmcs.guest.ss_base, 0);
        try vmwrite(vmcs.guest.ds_base, 0);
        try vmwrite(vmcs.guest.es_base, 0);
        try vmwrite(vmcs.guest.fs_base, 0);
        try vmwrite(vmcs.guest.gs_base, 0);
        try vmwrite(vmcs.guest.tr_base, 0);
        try vmwrite(vmcs.guest.gdtr_base, 0);
        try vmwrite(vmcs.guest.idtr_base, 0);
        try vmwrite(vmcs.guest.ldtr_base, 0xDEAD00); // Marker to indicate the guest.

        // Limit
        try vmwrite(vmcs.guest.cs_limit, @as(u64, std.math.maxInt(u32)));
        try vmwrite(vmcs.guest.ss_limit, @as(u64, std.math.maxInt(u32)));
        try vmwrite(vmcs.guest.ds_limit, @as(u64, std.math.maxInt(u32)));
        try vmwrite(vmcs.guest.es_limit, @as(u64, std.math.maxInt(u32)));
        try vmwrite(vmcs.guest.fs_limit, @as(u64, std.math.maxInt(u32)));
        try vmwrite(vmcs.guest.gs_limit, @as(u64, std.math.maxInt(u32)));
        try vmwrite(vmcs.guest.tr_limit, 0);
        try vmwrite(vmcs.guest.ldtr_limit, 0);
        try vmwrite(vmcs.guest.idtr_limit, 0);
        try vmwrite(vmcs.guest.gdtr_limit, 0);

        // Access Rights
        const cs_right = vmx.SegmentRights{
            .rw = true,
            .dc = false,
            .executable = true,
            .desc_type = .code_data,
            .dpl = 0,
            .granularity = .kbyte,
            .long = true,
            .db = 0,
        };
        const ds_right = vmx.SegmentRights{
            .rw = true,
            .dc = false,
            .executable = false,
            .desc_type = .code_data,
            .dpl = 0,
            .granularity = .kbyte,
            .long = false,
            .db = 1,
        };
        const tr_right = vmx.SegmentRights{
            .rw = true,
            .dc = false,
            .executable = true,
            .desc_type = .system,
            .dpl = 0,
            .granularity = .byte,
            .long = false,
            .db = 0,
        };
        const ldtr_right = vmx.SegmentRights{
            .accessed = false,
            .rw = true,
            .dc = false,
            .executable = false,
            .desc_type = .system,
            .dpl = 0,
            .granularity = .byte,
            .long = false,
            .db = 0,
        };
        try vmwrite(vmcs.guest.cs_rights, cs_right);
        try vmwrite(vmcs.guest.ss_rights, ds_right);
        try vmwrite(vmcs.guest.ds_rights, ds_right);
        try vmwrite(vmcs.guest.es_rights, ds_right);
        try vmwrite(vmcs.guest.fs_rights, ds_right);
        try vmwrite(vmcs.guest.gs_rights, ds_right);
        try vmwrite(vmcs.guest.tr_rights, tr_right);
        try vmwrite(vmcs.guest.ldtr_rights, ldtr_right);

        // Selector
        try vmwrite(vmcs.guest.cs_sel, am.readSegSelector(.cs));
        try vmwrite(vmcs.guest.ss_sel, 0);
        try vmwrite(vmcs.guest.ds_sel, 0);
        try vmwrite(vmcs.guest.es_sel, 0);
        try vmwrite(vmcs.guest.fs_sel, 0);
        try vmwrite(vmcs.guest.gs_sel, 0);
        try vmwrite(vmcs.guest.tr_sel, 0);
        try vmwrite(vmcs.guest.ldtr_sel, 0);

        // FS/GS base
        try vmwrite(vmcs.guest.fs_base, 0);
        try vmwrite(vmcs.guest.gs_base, 0);
    }

    // MSR
    try vmwrite(vmcs.guest.efer, am.readMsr(.efer));

    // General registers.
    try vmwrite(vmcs.guest.rflags, am.FlagsRegister.new());

    // Other crucial fields.
    try vmwrite(vmcs.guest.vmcs_link_pointer, std.math.maxInt(u64));
}

/// Set host stack pointer.
/// This function is called directly from assembly.
export fn setHostStack(rsp: u64) callconv(.C) void {
    vmwrite(vmcs.host.rsp, rsp) catch {};
}

/// Read VMCS revision identifier.
inline fn getVmcsRevisionId() u31 {
    return am.readMsrVmxBasic().vmcs_revision_id;
}

/// Adjust mandatory bits of a control field.
/// Upper 32 bits of `mask` is mandatory 1, and lower 32 bits is mandatory 0.
fn adjustRegMandatoryBits(control: anytype, mask: u64) @TypeOf(control) {
    var ret: u32 = @bitCast(control);
    ret |= @as(u32, @truncate(mask)); // Mandatory 1
    ret &= @as(u32, @truncate(mask >> 32)); // Mandatory 0
    return @bitCast(ret);
}

/// Puts the logical processor in VMX operation with no VMCS loaded.
fn vmxon(allocator: Allocator) VmxError!*VmxonRegion {
    // Set up VMXON region.
    const vmxon_region = try VmxonRegion.new(allocator);
    vmxon_region.vmcs_revision_id = getVmcsRevisionId();
    log.debug("VMCS revision ID: 0x{X:0>8}", .{vmxon_region.vmcs_revision_id});

    const vmxon_phys = mem.virt2phys(vmxon_region);
    log.debug("VMXON region physical address: 0x{X:0>16}", .{vmxon_phys});

    am.vmxon(vmxon_phys) catch |err| {
        vmxon_region.deinit(allocator);
        return err;
    };

    return vmxon_region;
}

/// Check if INVVPID is supported.
fn isVpidSupported() bool {
    const cap: am.MsrVmxEptVpidCap = @bitCast(am.readMsr(.vmx_ept_vpid_cap));
    return cap.invvpid and cap.invvpid_single and cap.invvpid_all and cap.invvpid_individual and cap.invvpid_single_globals;
}

/// VMXON region.
/// cf. SDM Vol.3C 25.11.5.
const VmxonRegion = packed struct {
    vmcs_revision_id: u31,
    zero: u1 = 0,

    /// Allocate VMXON region.
    pub fn new(page_allocator: Allocator) VmxError!*align(mem.page_size) VmxonRegion {
        const size = am.readMsrVmxBasic().vmxon_region_size;
        const page = page_allocator.alloc(u8, size) catch return VmxError.OutOfMemory;
        if (@intFromPtr(page.ptr) % mem.page_size != 0) {
            return error.OutOfMemory;
        }
        @memset(page, 0);
        return @alignCast(@ptrCast(page.ptr));
    }

    pub fn deinit(self: *VmxonRegion, page_allocator: Allocator) void {
        const size = am.readMsrVmxBasic().vmxon_region_size;
        const ptr: [*]u8 = @ptrCast(self);
        page_allocator.free(ptr[0..size]);
    }
};

/// VMCS region.
/// cf. SDM Vol.3C 25.2.
const VmcsRegion = packed struct {
    /// VMCS revision identifier.
    vmcs_revision_id: u31,
    /// Must be zero.
    zero: u1 = 0,
    /// VMX-abort indicator.
    abort_indicator: u32,
    // VMCS data follows, but its exact layout is implementation-specific.
    // Use vmread/vmwrite with appropriate ComponentEncoding.

    /// Allocate a VMCS region.
    pub fn new(page_allocator: Allocator) VmxError!*align(mem.page_size) VmcsRegion {
        const size = am.readMsrVmxBasic().vmxon_region_size;
        const page = try page_allocator.alloc(u8, size);
        if (@intFromPtr(page.ptr) % mem.page_size != 0) {
            return error.OutOfMemory;
        }
        @memset(page, 0);
        return @alignCast(@ptrCast(page.ptr));
    }

    pub fn deinit(self: *VmcsRegion, page_allocator: Allocator) void {
        const size = am.readMsrVmxBasic().vmxon_region_size;
        const ptr: [*]u8 = @ptrCast(self);
        page_allocator.free(ptr[0..size]);
    }
};

export fn blobGuest() callconv(.Naked) noreturn {
    while (true)
        asm volatile (
            \\hlt
        );
}
