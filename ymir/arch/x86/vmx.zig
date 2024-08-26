const std = @import("std");
const log = std.log.scoped(.vmx);
const Allocator = std.mem.Allocator;

const ymir = @import("ymir");
const mem = ymir.mem;
const Phys = mem.Phys;

const am = @import("asm.zig");
const vmcs = @import("vmx/vmcs.zig");
const regs = @import("vmx/regs.zig");

const vmwrite = vmcs.vmwrite;
const vmread = vmcs.vmread;

const vmx_error = @import("vmx/error.zig");
pub const VmxError = vmx_error.VmxError;
pub const ExitInformation = vmx_error.ExitInformation;
pub const InstructionError = vmx_error.InstructionError;

/// Read RFLAGS and checks if a VMX instruction has failed.
pub fn vmxtry(rflags: u64) VmxError!void {
    const flags: am.FlagsRegister = @bitCast(rflags);
    return if (flags.cf) VmxError.FailureInvalidVmcsPointer else if (flags.zf) VmxError.FailureStatusAvailable;
}

/// Virtual logical CPU.
/// TODO: must be per-CPU variable. Currently, it only supports single CPU.
pub const Vcpu = struct {
    const Self = @This();

    /// VMXON region.
    vmxon_region: *VmxonRegion,
    /// VMCS region.
    vmcs_region: *VmcsRegion,
    /// The first VM-entry has been done.
    launch_done: bool = false,
    /// Saved guest registers.
    guest_regs: GuestRegisters = undefined,

    pub fn new() Self {
        return Self{
            .vmxon_region = undefined,
            .vmcs_region = undefined,
        };
    }

    /// Enter VMX root operation and allocate VMCS region for this LP.
    pub fn init(self: *Self, page_allocator: Allocator) VmxError!void {
        // Enter VMX root operation.
        self.vmxon_region = try vmxon(page_allocator);

        // Set up VMCS region.
        const vmcs_region = try VmcsRegion.new(page_allocator);
        vmcs_region.vmcs_revision_id = getVmcsRevisionId();
        self.vmcs_region = vmcs_region;
    }

    /// Set up VMCS for a logical processor.
    /// TODO: This is a temporary implementation.
    pub fn setupVmcs(self: *Self) VmxError!void {
        // Reset VMCS.
        try resetVmcs(self.vmcs_region);

        // Init fields.
        try setupExecCtrls();
        try setupExitCtrls();
        try setupEntryCtrls();
        try setupHostState();
        try setupGuestState();
    }

    // Enter VMX non-root operation.
    pub fn vmentry(self: *Self) VmxError!void {
        if (self.launch_done) {
            @panic("VMRESUME not implemented yet");
        } else {
            self.launch_done = true;
            self.asmVmEntry();
        }

        log.debug("[VM-EXIT]", .{});
        log.debug("RAX: 0x{X:0>16}", .{self.guest_regs.rax});
        log.debug("RBX: 0x{X:0>16}", .{self.guest_regs.rbx});
        log.debug("R15: 0x{X:0>16}", .{self.guest_regs.r15});
        log.debug("REASON: {?}", .{try getExitReason()});
    }

    /// VMLAUNCH or VMRESUME.
    /// The function is designed to return to the caller as a normal function via asmVmExit().
    fn asmVmEntry(self: *Self) void {
        // Save callee saved registers.
        asm volatile (
            \\mov %%rsp, %%rbp
            \\push %%r15
            \\push %%r14
            \\push %%r13
            \\push %%r12
            \\push %%rbx
        );

        // Push arguments and set host stack
        asm volatile (
            \\push %[self]
            \\mov %%rsp, %%rdi
            \\call setHostStack
            :
            : [self] "r" (self),
        );

        // TODO: Set guest registers here.

        // VMLAUNCH
        asm volatile (
            \\vmlaunch
            ::: "cc", "memory");
    }

    fn asmVmExit() callconv(.Naked) noreturn {
        asm volatile (
            \\push %%rax
            \\movq 8(%%rsp), %%rax
        );

        // Save guest registers.
        asm volatile (std.fmt.comptimePrint(
                \\pop {[rax]}(%%rax)
                \\add $8, %%rsp
                \\mov %%rcx, {[rcx]}(%%rax)
                \\mov %%rdx, {[rdx]}(%%rax)
                \\mov %%rbx, {[rbx]}(%%rax)
                \\mov %%rsi, {[rsi]}(%%rax)
                \\mov %%rdi, {[rdi]}(%%rax)
                \\mov %%rbp, {[rbp]}(%%rax)
                \\mov %%r8, {[r8]}(%%rax)
                \\mov %%r9, {[r9]}(%%rax)
                \\mov %%r10, {[r10]}(%%rax)
                \\mov %%r11, {[r11]}(%%rax)
                \\mov %%r12, {[r12]}(%%rax)
                \\mov %%r13, {[r13]}(%%rax)
                \\mov %%r14, {[r14]}(%%rax)
                \\mov %%r15, {[r15]}(%%rax)
            ,
                .{
                    .rax = @offsetOf(GuestRegisters, "rax"),
                    .rcx = @offsetOf(GuestRegisters, "rcx"),
                    .rdx = @offsetOf(GuestRegisters, "rdx"),
                    .rbx = @offsetOf(GuestRegisters, "rbx"),
                    .rsi = @offsetOf(GuestRegisters, "rsi"),
                    .rdi = @offsetOf(GuestRegisters, "rdi"),
                    .rbp = @offsetOf(GuestRegisters, "rbp"),
                    .r8 = @offsetOf(GuestRegisters, "r8"),
                    .r9 = @offsetOf(GuestRegisters, "r9"),
                    .r10 = @offsetOf(GuestRegisters, "r10"),
                    .r11 = @offsetOf(GuestRegisters, "r11"),
                    .r12 = @offsetOf(GuestRegisters, "r12"),
                    .r13 = @offsetOf(GuestRegisters, "r13"),
                    .r14 = @offsetOf(GuestRegisters, "r14"),
                    .r15 = @offsetOf(GuestRegisters, "r15"),
                },
            ));

        // Restore callee saved registers.
        asm volatile (
            \\pop %%rbx
            \\pop %%r12
            \\pop %%r13
            \\pop %%r14
            \\pop %%r15
        );

        // Epilogue.
        // This function itself is naked, but asmVmEntry() has prologue.
        // So we have to pop the pushed frame pointer here.
        asm volatile (
            \\pop %%rax
            \\pop %%rbp
        );

        // Return to caller of asmVmEntry()
        asm volatile (
            \\ret
        );
    }

    /// Exit VMX operation.
    pub fn vmxoff(_: *Self) void {
        am.vmxoff();
    }
};

/// Enable VMX operations.
pub fn enableVmx() void {
    // Adjust control registers.
    adjustControlRegisters();

    // Check VMXON is allowed outside SMX.
    var msr = am.readMsrFeatureControl();
    if (!msr.vmx_outside_smx) {
        // Enable VMX outside SMX.
        if (msr.lock) @panic("IA32_FEATURE_CONTROL is locked while VMX outside SMX is disabled");
        msr.vmx_outside_smx = true;
        am.writeMsrFeatureControl(msr);
    }

    // Set VMXE bit in CR4.
    var cr4 = am.readCr4();
    cr4.vmxe = true;
    am.loadCr4(cr4);
}

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

    am.loadCr0(@bitCast(cr0));
    am.loadCr4(@bitCast(cr4));
}

/// Read VMCS revision identifier.
fn getVmcsRevisionId() u31 {
    const vmx_basic = am.readMsrVmxBasic();
    return vmx_basic.vmcs_revision_id;
}

/// Puts the logical processor in VMX operation with no VMCS loaded.
fn vmxon(page_allocator: Allocator) VmxError!*VmxonRegion {
    // Set up VMXON region.
    const vmxon_region = try VmxonRegion.new(page_allocator);
    vmxon_region.vmcs_revision_id = getVmcsRevisionId();
    log.debug("VMCS revision ID: 0x{X:0>8}", .{vmxon_region.vmcs_revision_id});

    const vmxon_phys = mem.virt2phys(@intFromPtr(vmxon_region));
    log.debug("VMXON region physical address: 0x{X:0>16}", .{vmxon_phys});

    am.vmxon(vmxon_phys) catch |err| {
        vmxon_region.deinit(page_allocator);
        return err;
    };

    return vmxon_region;
}

/// Clear and reset VMCS.
/// After this operation, the VMCS becomes active and current logical processor.
fn resetVmcs(vmcs_region: *VmcsRegion) VmxError!void {
    // The VMCS becomes inactive and flushed to memory.
    try am.vmclear(mem.virt2phys(@intFromPtr(vmcs_region)));
    // Load and activate the VMCS.
    try am.vmptrld(mem.virt2phys(@intFromPtr(vmcs_region)));
}

/// TODO: temporary
export fn guestDebugHandler() callconv(.Naked) noreturn {
    while (true)
        asm volatile (
            \\cli
            \\mov $0xDEADBEEF, %%rax
            \\mov $0x12345678, %%rbx
            \\mov $0xCAFEBABE, %%r15
            \\hlt
        );
}

/// Set up VM-Execution control fields.
/// cf. SDM Vol.3C 27.2.1.1, Appendix A.3.
fn setupExecCtrls() VmxError!void {
    const basic_msr = am.readMsrVmxBasic();

    // Pin-based VM-Execution control.
    const pin_exec_ctrl = try vmcs.exec_control.PinBasedExecutionControl.get();
    try adjustRegMandatoryBits(
        pin_exec_ctrl,
        if (basic_msr.true_control) am.readMsr(.vmx_true_pinbased_ctls) else am.readMsr(.vmx_pinbased_ctls),
    ).load();

    // Primary Processor-based VM-Execution control.
    var ppb_exec_ctrl = try vmcs.exec_control.PrimaryProcessorBasedExecutionControl.get();
    ppb_exec_ctrl.hlt = true; // exit on halt
    try adjustRegMandatoryBits(
        ppb_exec_ctrl,
        if (basic_msr.true_control) am.readMsr(.vmx_true_procbased_ctls) else am.readMsr(.vmx_procbased_ctls),
    ).load();
}

/// Set up VM-Exit control fields.
/// cf. SDM Vol.3C 27.2.1.2.
fn setupExitCtrls() VmxError!void {
    const basic_msr = am.readMsrVmxBasic();

    // VM-Exit control.
    var exit_ctrl = try vmcs.exit_control.PrimaryExitControls.get();
    exit_ctrl.host_addr_space_size = true;
    try adjustRegMandatoryBits(
        exit_ctrl,
        if (basic_msr.true_control) am.readMsr(.vmx_true_exit_ctls) else am.readMsr(.vmx_exit_ctls),
    ).load();
}

/// Set up VM-Entry control fields.
/// cf. SDM Vol.3C 27.2.1.3.
fn setupEntryCtrls() VmxError!void {
    const basic_msr = am.readMsrVmxBasic();

    // VM-Entry control.
    var entry_ctrl = try vmcs.entry_control.EntryControls.get();
    entry_ctrl.ia32e_mode_guest = true;
    entry_ctrl.load_ia32_efer = true;
    entry_ctrl.load_ia32_pat = true;
    try adjustRegMandatoryBits(
        entry_ctrl,
        if (basic_msr.true_control) am.readMsr(.vmx_true_entry_ctls) else am.readMsr(.vmx_entry_ctls),
    ).load();
}

/// Set up host state.
/// cf. SDM Vol.3C 27.2.2.
fn setupHostState() VmxError!void {
    // Control registers.
    try vmwrite(vmcs.Host.cr0, am.readCr0());
    try vmwrite(vmcs.Host.cr3, am.readCr3());
    try vmwrite(vmcs.Host.cr4, am.readCr4());

    // General registers.
    try vmwrite(vmcs.Host.rip, &Vcpu.asmVmExit);
    try vmwrite(vmcs.Host.rsp, @intFromPtr(&debug_temp_stack) + debug_temp_stack_size);

    // Segment registers.
    try vmwrite(vmcs.Host.cs_sel, am.readSegSelector(.cs));
    try vmwrite(vmcs.Host.ss_sel, am.readSegSelector(.ss));
    try vmwrite(vmcs.Host.ds_sel, am.readSegSelector(.ds));
    try vmwrite(vmcs.Host.es_sel, am.readSegSelector(.es));
    try vmwrite(vmcs.Host.fs_sel, am.readSegSelector(.fs));
    try vmwrite(vmcs.Host.gs_sel, am.readSegSelector(.gs));
    try vmwrite(vmcs.Host.tr_sel, am.readSegSelector(.tr));
    try vmwrite(vmcs.Host.gs_base, am.readMsr(.gs_base));
    try vmwrite(vmcs.Host.fs_base, am.readMsr(.fs_base));
    try vmwrite(vmcs.Host.tr_base, 0); // Not used in Ymir.
    try vmwrite(vmcs.Host.gdtr_base, am.sgdt().base);
    try vmwrite(vmcs.Host.idtr_base, am.sidt().base);

    // MSR.
    try vmwrite(vmcs.Host.efer, am.readMsr(.efer));
}

fn setupGuestState() VmxError!void {
    const entry_ctrl = try vmcs.entry_control.EntryControls.get();

    // Control registers.
    const cr0 = am.readCr0();
    const cr3 = am.readCr3();
    const cr4 = am.readCr4();
    try vmwrite(vmcs.Guest.cr0, cr0);
    try vmwrite(vmcs.Guest.cr3, cr3);
    try vmwrite(vmcs.Guest.cr4, cr4);

    // Segment registers.
    {
        try vmwrite(vmcs.Guest.cs_base, 0);
        try vmwrite(vmcs.Guest.ss_base, 0);
        try vmwrite(vmcs.Guest.ds_base, 0);
        try vmwrite(vmcs.Guest.es_base, 0);
        try vmwrite(vmcs.Guest.fs_base, 0);
        try vmwrite(vmcs.Guest.gs_base, 0);
        try vmwrite(vmcs.Guest.tr_base, 0);
        try vmwrite(vmcs.Guest.gdtr_base, am.sgdt().base);
        try vmwrite(vmcs.Guest.idtr_base, am.sidt().base);
        try vmwrite(vmcs.Guest.ldtr_base, 0);

        try vmwrite(vmcs.Guest.cs_limit, @as(u64, std.math.maxInt(u32)));
        try vmwrite(vmcs.Guest.ss_limit, @as(u64, std.math.maxInt(u32)));
        try vmwrite(vmcs.Guest.ds_limit, @as(u64, std.math.maxInt(u32)));
        try vmwrite(vmcs.Guest.es_limit, @as(u64, std.math.maxInt(u32)));
        try vmwrite(vmcs.Guest.fs_limit, @as(u64, std.math.maxInt(u32)));
        try vmwrite(vmcs.Guest.gs_limit, @as(u64, std.math.maxInt(u32)));
        try vmwrite(vmcs.Guest.tr_limit, 0);
        try vmwrite(vmcs.Guest.ldtr_limit, 0);
        try vmwrite(vmcs.Guest.idtr_limit, am.sidt().limit);
        try vmwrite(vmcs.Guest.gdtr_limit, am.sgdt().limit);

        const cs_right = vmcs.SegmentRights{
            .type = .CodeERA,
            .s = .CodeOrData,
            .dpl = 0,
            .g = .KByte,
            .long = true,
            .db = 0,
        };
        const ds_right = vmcs.SegmentRights{
            .type = .DataRWA,
            .s = .CodeOrData,
            .dpl = 0,
            .g = .KByte,
            .long = false,
            .db = 1,
        };
        const tr_right = vmcs.SegmentRights{
            .type = .CodeERA,
            .s = .System,
            .dpl = 0,
            .g = .Byte,
            .long = false,
            .db = 0,
            .unusable = false,
        };
        const ldtr_right = vmcs.SegmentRights{
            .type = .DataRW,
            .s = .System,
            .dpl = 0,
            .g = .Byte,
            .long = false,
            .db = 0,
            .unusable = true,
        };
        try vmwrite(vmcs.Guest.cs_rights, cs_right);
        try vmwrite(vmcs.Guest.ss_rights, ds_right);
        try vmwrite(vmcs.Guest.ds_rights, ds_right);
        try vmwrite(vmcs.Guest.es_rights, ds_right);
        try vmwrite(vmcs.Guest.fs_rights, ds_right);
        try vmwrite(vmcs.Guest.gs_rights, ds_right);
        try vmwrite(vmcs.Guest.tr_rights, tr_right);
        try vmwrite(vmcs.Guest.ldtr_rights, ldtr_right);

        try vmwrite(vmcs.Guest.cs_sel, am.readSegSelector(.cs));
        try vmwrite(vmcs.Guest.ss_sel, am.readSegSelector(.ss));
        try vmwrite(vmcs.Guest.ds_sel, am.readSegSelector(.ds));
        try vmwrite(vmcs.Guest.es_sel, am.readSegSelector(.es));
        try vmwrite(vmcs.Guest.fs_sel, am.readSegSelector(.fs));
        try vmwrite(vmcs.Guest.gs_sel, am.readSegSelector(.gs));
        try vmwrite(vmcs.Guest.tr_sel, am.readSegSelector(.tr));
        try vmwrite(vmcs.Guest.ldtr_sel, am.readSegSelector(.ldtr)); // Not used in Ymir.

        try vmwrite(vmcs.Guest.fs_base, am.readMsr(.fs_base));
        try vmwrite(vmcs.Guest.gs_base, am.readMsr(.gs_base));
    }

    // General registers.
    try vmwrite(vmcs.Guest.rip, @intFromPtr(&guestDebugHandler));
    try vmwrite(vmcs.Guest.rsp, 0xDEAD0000); // TODO
    try vmwrite(vmcs.Guest.rflags, am.readEflags());

    // MSR
    try vmwrite(vmcs.Guest.sysenter_cs, am.readMsr(.sysenter_cs));
    try vmwrite(vmcs.Guest.sysenter_esp, am.readMsr(.sysenter_esp));
    try vmwrite(vmcs.Guest.sysenter_eip, am.readMsr(.sysenter_eip));
    const efer = am.readMsr(.efer);
    try vmwrite(vmcs.Guest.efer, efer);
    const pat = am.readMsr(.pat);
    try vmwrite(vmcs.Guest.pat, pat);

    // Other crucial fields.
    try vmwrite(vmcs.Guest.vmcs_link_pointer, std.math.maxInt(u64));

    // Guest register state partial checks.
    if (cr0.pg and !cr0.pe) @panic("CR0: PE must be set when PG is set");
    if (cr4.cet and !cr0.wp) @panic("CR0: WP must be set when CR4.CET is set");
    if (entry_ctrl.ia32e_mode_guest and !(cr0.pg and cr4.pae)) @panic("CR0: PG and CR4.PAE must be set when IA-32e mode is enabled");
    if (!entry_ctrl.ia32e_mode_guest and cr4.pcide) @panic("CR4: PCIDE must be unset when IA-32e mode is disabled");
    if (cr3 >> 46 != 0) @panic("CR3: Reserved bits must be zero");
    if (entry_ctrl.load_debug_controls) @panic("Unsupported guest state: load debug controls.");
    if (entry_ctrl.load_cet_state) @panic("Unsupported guest state: load CET state.");
    if (entry_ctrl.load_perf_global_ctrl) @panic("Unsupported guest state: load perf global ctrl.");
    if (entry_ctrl.load_ia32_efer) {
        const lma = (efer >> 10) & 1 != 0;
        const lme = (efer >> 8) & 1 != 0;
        if (lma != entry_ctrl.ia32e_mode_guest) @panic("EFER and IA-32e mode mismatch");
        if (cr0.pg and (lma != lme)) @panic("EFER.LME must be identical to EFER.LMA when CR0.PG is set");
    }

    const rflags: am.FlagsRegister = @bitCast(try vmcs.vmread(vmcs.Guest.rflags));
    if (rflags._reserved != 0 or rflags._reserved2 != 0 or rflags._reserved3 != 0 or rflags._reserved4 != 0) @panic("RFLAGS: Reserved bits must be zero");
    if (rflags._reserved1 != 1) @panic("RFLAGS: Reserved bit 1 must be one");
    if (entry_ctrl.ia32e_mode_guest and rflags.vm) @panic("RFLAGS: VM must be clear when IA-32e mode is enabled");
    const intr_info = try vmread(vmcs.Ctrl.vmentry_interrupt_information_field);
    if (((intr_info >> 31) & 1 != 0) and !rflags.ief) @panic("RFLAGS: IF must be set when valid bit in VM-entry interruption-information field is set.");

    // Guest non-register state partial checks.
    const activity_state = try vmcs.vmread(vmcs.Guest.activity_state);
    if (activity_state != 0) @panic("Unsupported activity state.");
    const intr_state = try vmcs.vmread(vmcs.Guest.interrupt_status);
    if ((intr_state >> 5) != 0) @panic("Unsupported interruptability state.");
}

/// TODO: Size of temporary stack for VM-exit handler.
const debug_temp_stack_size: usize = 4096;
/// TODO: Temporary stack for VM-exit handler.
var debug_temp_stack: [debug_temp_stack_size + 0x30]u8 align(0x10) = [_]u8{0} ** (debug_temp_stack_size + 0x30);

/// TODO: temporary
fn vmexitBootstrapHandler() callconv(.Naked) noreturn {
    asm volatile (
        \\call vmexitHandler
    );
}

/// Set host stack pointer.
/// This function is called directly from assembly.
export fn setHostStack(rsp: u64) callconv(.C) void {
    vmcs.vmwrite(vmcs.Host.rsp, rsp) catch {};
}

export fn vmexitHandler() noreturn {
    log.debug("[VMEXIT handler]", .{});
    const reason = getExitReason() catch unreachable;
    log.debug("   VMEXIT reason: {?}", .{reason});

    while (true)
        am.hlt();
}

fn adjustRegMandatoryBits(control: anytype, mask: u64) @TypeOf(control) {
    var ret: u32 = @bitCast(control);
    ret |= @as(u32, @truncate(mask)); // Mandatory 1
    ret &= @as(u32, @truncate(mask >> 32)); // Mandatory 0
    return @bitCast(ret);
}

/// Get a instruction error number from VMCS.
pub fn getInstError() VmxError!InstructionError {
    return @enumFromInt(@as(u32, @truncate(try vmread(vmcs.Ro.vminstruction_error))));
}

/// Get a VM-exit reason from VMCS.
pub fn getExitReason() VmxError!ExitInformation {
    return @bitCast(@as(u32, @truncate(try vmread(vmcs.Ro.vmexit_reason))));
}

const VmxonRegion = packed struct {
    vmcs_revision_id: u31,
    zero: u1 = 0,

    pub fn new(page_allocator: Allocator) VmxError!*align(4096) VmxonRegion {
        const page = page_allocator.alloc(u8, 4096) catch return VmxError.OutOfMemory;
        if (page.len != 4096 or @intFromPtr(page.ptr) % 4096 != 0) {
            return error.OutOfMemory;
        }
        @memset(page, 0);
        return @alignCast(@ptrCast(page.ptr));
    }

    pub fn deinit(self: *VmxonRegion, page_allocator: Allocator) void {
        const ptr: [*]u8 = @ptrCast(self);
        page_allocator.free(ptr[0..4096]);
    }
};

const VmcsRegion = packed struct {
    /// VMCS revision identifier.
    vmcs_revision_id: u31,
    /// Must be zero.
    zero: u1 = 0,
    /// VMX-abort indicator.
    abort_indicator: u32,

    // VMCS data follows, but its exact layout is implementation-specific.
    // Use vmread/vmwrite with appropriate ComponentEncoding.

    pub fn new(page_allocator: Allocator) VmxError!*align(4096) VmcsRegion {
        const page = try page_allocator.alloc(u8, 4096);
        if (page.len != 4096 or @intFromPtr(page.ptr) % 4096 != 0) {
            return error.OutOfMemory;
        }
        @memset(page, 0);
        return @alignCast(@ptrCast(page.ptr));
    }

    pub fn deinit(self: *VmcsRegion, page_allocator: Allocator) void {
        const ptr: [*]u8 = @ptrCast(self);
        page_allocator.free(ptr[0..4096]);
    }
};

const GuestRegisters = packed struct {
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
};

test {
    std.testing.refAllDeclsRecursive(@This());

    std.testing.refAllDeclsRecursive(@import("vmx/vmcs.zig"));
}
