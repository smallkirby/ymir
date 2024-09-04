const std = @import("std");
const log = std.log.scoped(.vmx);
const Allocator = std.mem.Allocator;

const ymir = @import("ymir");
const mem = ymir.mem;
const Phys = mem.Phys;
const linux = ymir.linux;
const BootParams = linux.boot.BootParams;

const am = @import("asm.zig");
const apic = @import("apic.zig");
const gdt = @import("gdt.zig");
const serial = @import("serial.zig");
const vmcs = @import("vmx/vmcs.zig");
const regs = @import("vmx/regs.zig");
const qual = @import("vmx/qual.zig");
const ept = @import("vmx/ept.zig");
const cpuid = @import("vmx/cpuid.zig");
const msr = @import("vmx/msr.zig");
const cr = @import("vmx/cr.zig");

const vmwrite = vmcs.vmwrite;
const vmread = vmcs.vmread;
const isCanonical = @import("page.zig").isCanonical;

/// Size of VM-exit trampoline stack.
const vmexit_stack_size: usize = 4096;
/// VM-exit trampoline stack.
var vmexit_stack: [vmexit_stack_size + 0x30]u8 align(0x10) = [_]u8{0} ** (vmexit_stack_size + 0x30);

pub const VmxError = error{
    /// VMCS pointer is invalid. No status available.
    VmxStatusUnavailable,
    /// VMCS pointer is valid but the operation failed.
    /// If a current VMCS is active, error status is stored in VM-instruction error field.
    VmxStatusAvailable,
    /// Failed to allocate memory.
    OutOfMemory,
};

/// Read RFLAGS and checks if a VMX instruction has failed.
pub fn vmxtry(rflags: u64) VmxError!void {
    const flags: am.FlagsRegister = @bitCast(rflags);
    return if (flags.cf) VmxError.VmxStatusUnavailable else if (flags.zf) VmxError.VmxStatusAvailable;
}

/// Virtual logical CPU.
/// TODO: must be per-CPU variable. Currently, it only supports single CPU.
pub const Vcpu = struct {
    const Self = @This();

    /// ID of the logical processor.
    id: usize = 0,
    /// VMXON region.
    vmxon_region: *VmxonRegion,
    /// VMCS region.
    vmcs_region: *VmcsRegion,
    /// The first VM-entry has been done.
    launch_done: bool = false,
    /// IA-32e mode (long mode) is enabled.
    ia32_enabled: bool = false,
    /// Saved guest registers.
    guest_regs: GuestRegisters = undefined,
    /// EPT pointer.
    eptp: ept.Eptp = undefined,

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

    /// Create a new virtual CPU.
    /// This function does not virtualize the CPU.
    /// You MUST call `virtualize` to put the CPU in VMX root operation.
    pub fn new() Self {
        const id = apic.getLapicId();

        return Self{
            .id = id,
            .vmxon_region = undefined,
            .vmcs_region = undefined,
        };
    }

    /// Enable VMX operations.
    pub fn enableVmx(_: *Self) void {
        // Adjust control registers.
        adjustControlRegisters();

        // Check VMXON is allowed outside SMX.
        var msr_fctl = am.readMsrFeatureControl();
        if (!msr_fctl.vmx_outside_smx) {
            // Enable VMX outside SMX.
            if (msr_fctl.lock) @panic("IA32_FEATURE_CONTROL is locked while VMX outside SMX is disabled");
            msr_fctl.vmx_outside_smx = true;
            am.writeMsrFeatureControl(msr_fctl);
        }

        // Set VMXE bit in CR4.
        var cr4 = am.readCr4();
        cr4.vmxe = true;
        am.loadCr4(cr4);
    }

    /// Enter VMX root operation and allocate VMCS region for this LP.
    pub fn virtualize(self: *Self, page_allocator: Allocator) VmxError!void {
        // Enter VMX root operation.
        self.vmxon_region = try vmxon(page_allocator);

        // Set up VMCS region.
        const vmcs_region = try VmcsRegion.new(page_allocator);
        vmcs_region.vmcs_revision_id = getVmcsRevisionId();
        self.vmcs_region = vmcs_region;
    }

    /// Exit VMX operation.
    pub fn devirtualize(_: *Self) void {
        am.vmxoff();
    }

    /// Set up VMCS for a logical processor.
    pub fn setupVmcs(self: *Self) VmxError!void {
        // Reset VMCS.
        try resetVmcs(self.vmcs_region);

        // Initialize VMCS fields.
        try setupExecCtrls(self);
        try setupExitCtrls(self);
        try setupEntryCtrls(self);
        try setupHostState(self);
        try setupGuestState(self);
    }

    /// Maps guest physical memory to host physical memory.
    pub fn initGuestMap(self: *Self, host_pages: []u8, allocator: Allocator) !void {
        const lv4tbl = try ept.initEpt(
            0,
            ymir.mem.virt2phys(host_pages.ptr),
            host_pages.len,
            allocator,
        );
        const eptp = ept.Eptp.new(lv4tbl);
        self.eptp = eptp;

        try vmwrite(vmcs.Ctrl.eptp, eptp);
    }

    /// Start executing vCPU.
    pub fn loop(self: *Self) VmxError!void {
        while (true) {
            if (ymir.is_debug) {
                try partialCheckGuest();
            }

            self.vmentry() catch |err| {
                log.err("VM-entry failed: {?}", .{err});
                if (err == VmxError.VmxStatusAvailable) {
                    const inst_err = getInstError() catch unreachable;
                    log.err("VM Instruction error: {?}", .{inst_err});
                }
                self.abort();
            };

            try self.handleExit(try getExitReason());
        }
    }

    // Enter VMX non-root operation.
    fn vmentry(self: *Self) VmxError!void {
        const success = self.asmVmEntry() == 0;

        if (!self.launch_done and success) {
            self.launch_done = true;
        }

        if (success) {
            return;
        } else {
            const inst_err = try vmcs.vmread(vmcs.Ro.vminstruction_error);
            return if (inst_err != 0) VmxError.VmxStatusAvailable else VmxError.VmxStatusUnavailable;
        }
    }

    /// Handle the VM-exit.
    fn handleExit(self: *Self, exit_info: ExitInformation) VmxError!void {
        log.debug("VM-exit: reason={?}", .{exit_info.basic_reason});
        switch (exit_info.basic_reason) {
            .io => {
                const q = try getExitQual(qual.QualIo);
                log.debug("I/O instruction: {?}", .{q});
                unreachable;
            },
            .cr => {
                const q = try getExitQual(qual.QualCr);
                try cr.handleAccessCr(self, q);
                try self.stepNextInst();
            },
            .ept => {
                const q = try getExitQual(qual.QualEptViolation);
                log.err("EPT violation: {?}", .{q});
                self.abort();
            },
            .cpuid => {
                try cpuid.handleCpuidExit(self);
                try self.stepNextInst();
            },
            .rdmsr => {
                try msr.handleRdmsrExit(self);
                try self.stepNextInst();
            },
            .wrmsr => {
                try msr.handleWrmsrExit(self);
                try self.stepNextInst();
            },
            else => {
                log.err("Unhandled VM-exit: reason={?}", .{exit_info.basic_reason});
                self.abort();
            },
        }
    }

    fn abort(self: *Self) noreturn {
        @setCold(true);

        log.err("=== vCPU Information ===", .{});
        log.err("[Guest State]", .{});
        log.err("RIP: 0x{X:0>16}", .{vmread(vmcs.Guest.rip) catch unreachable});
        log.err("RSP: 0x{X:0>16}", .{vmread(vmcs.Guest.rsp) catch unreachable});
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
        log.err("CR0: 0x{X:0>16}", .{vmread(vmcs.Guest.cr0) catch unreachable});
        log.err("CR3: 0x{X:0>16}", .{vmread(vmcs.Guest.cr3) catch unreachable});
        log.err("CR4: 0x{X:0>16}", .{vmread(vmcs.Guest.cr4) catch unreachable});
        log.err("EFER:0x{X:0>16}", .{vmread(vmcs.Guest.efer) catch unreachable});
        log.err(
            "CS : 0x{X:0>4} 0x{X:0>16} 0x{X:0>8}",
            .{
                vmread(vmcs.Guest.cs_sel) catch unreachable,
                vmread(vmcs.Guest.cs_base) catch unreachable,
                vmread(vmcs.Guest.cs_limit) catch unreachable,
            },
        );

        unreachable;
    }

    /// Increment RIP by the length of the current instruction.
    fn stepNextInst(_: *Self) VmxError!void {
        const rip = try vmread(vmcs.Guest.rip);
        try vmwrite(vmcs.Guest.rip, rip + try vmread(vmcs.Ro.vmexit_instruction_length));
    }

    /// VMLAUNCH or VMRESUME.
    /// The function is designed to return to the caller as a normal function via asmVmExit().
    /// Returns 0 if succeeded, 1 if failed.
    fn asmVmEntry(self: *Self) callconv(.SysV) u8 {
        // Prologue pushes rbp and rax here.
        //  push %%rbp
        //  mov %%rsp, %%rbp
        //  sub $0x10, %%rsp

        // Save callee saved registers.
        asm volatile (
            \\push %%r15
            \\push %%r14
            \\push %%r13
            \\push %%r12
            \\push %%rbx
        );

        // Save a pointer to guest registers
        asm volatile (
            \\push %[guest_regs]
            :
            : [guest_regs] "{rcx}" (&self.guest_regs),
        );

        // Set host stack
        asm volatile (
            \\push %%rdi
            \\lea 8(%%rsp), %%rdi
            \\call setHostStack
            \\pop %%rdi
        );

        // Determine VMLAUNCH or VMRESUME.
        asm volatile (
            \\testb $1, %[launch_done]
            :
            : [launch_done] "{rdx}" (self.launch_done),
        );

        // Restore guest registers.
        asm volatile (std.fmt.comptimePrint(
                \\mov %%rdi, %%rax
                \\mov {[rcx]}(%%rax), %%rcx
                \\mov {[rdx]}(%%rax), %%rdx
                \\mov {[rbx]}(%%rax), %%rbx
                \\mov {[rsi]}(%%rax), %%rsi
                \\mov {[rdi]}(%%rax), %%rdi
                \\mov {[rbp]}(%%rax), %%rbp
                \\mov {[r8]}(%%rax), %%r8
                \\mov {[r9]}(%%rax), %%r9
                \\mov {[r10]}(%%rax), %%r10
                \\mov {[r11]}(%%rax), %%r11
                \\mov {[r12]}(%%rax), %%r12
                \\mov {[r13]}(%%rax), %%r13
                \\mov {[r14]}(%%rax), %%r14
                \\mov {[r15]}(%%rax), %%r15
                \\mov {[rax]}(%%rax), %%rax
            , .{
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
            }));

        // VMLAUNCH or VMRESUME.
        asm volatile (
            \\jz .L_vmlaunch
            \\vmresume
            \\.L_vmlaunch:
            \\vmlaunch
            ::: "cc", "memory");

        // Failed to launch.

        // Set return value to 1.
        asm volatile (
            \\mov $1, %%al
        );

        // Restore callee saved registers.
        asm volatile (
            \\add $0x8, %%rsp
            \\pop %%rbx
            \\pop %%r12
            \\pop %%r13
            \\pop %%r14
            \\pop %%r15
        );

        // Epilogue.
        asm volatile (
            \\
            // Discard stack frame of asmVmEntry()
            \\add $0x10, %%rsp
            // Pop saved rbp
            \\pop %%rbp
        );

        // Return to caller of asmVmEntry()
        asm volatile (
            \\ret
        );

        // Just to suppress the warning.
        return 0;
    }

    fn asmVmExit() callconv(.Naked) noreturn {
        // Save guest RAX, get &guest_regs
        asm volatile (
            \\push %%rax
            \\movq 8(%%rsp), %%rax
        );

        // Save guest registers.
        asm volatile (std.fmt.comptimePrint(
                \\
                // Save pushed RAX.
                \\pop {[rax]}(%%rax)
                // Discard pushed &guest_regs.
                \\add $0x8, %%rsp
                // Save guest registers.
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
            \\
            // Discard stack frame of asmVmEntry()
            \\add $0x10, %%rsp
            // Pop saved rbp
            \\pop %%rbp
        );

        // Return to caller of asmVmEntry()
        asm volatile (
            \\mov $0, %%rax
            \\ret
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

    const vmxon_phys = mem.virt2phys(vmxon_region);
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
    try am.vmclear(mem.virt2phys(vmcs_region));
    // Load and activate the VMCS.
    try am.vmptrld(mem.virt2phys(vmcs_region));
}

/// Set up VM-Execution control fields.
/// cf. SDM Vol.3C 27.2.1.1, Appendix A.3.
fn setupExecCtrls(_: *Vcpu) VmxError!void {
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
    ppb_exec_ctrl.unconditional_io = true;
    ppb_exec_ctrl.hlt = true;
    try adjustRegMandatoryBits(
        ppb_exec_ctrl,
        if (basic_msr.true_control) am.readMsr(.vmx_true_procbased_ctls) else am.readMsr(.vmx_procbased_ctls),
    ).load();

    // Secondary Processor-based VM-Execution control.
    var ppb_exec_ctrl2 = try vmcs.SecondaryProcExecCtrl.store();
    ppb_exec_ctrl2.ept = true;
    ppb_exec_ctrl2.unrestricted_guest = true; // TODO: should we enable this?
    try adjustRegMandatoryBits(
        ppb_exec_ctrl2,
        am.readMsr(.vmx_procbased_ctls2),
    ).load();

    // Exit on access to CR0/CR4.
    try vmwrite(vmcs.Ctrl.cr0_mask, std.math.maxInt(u64));
    try vmwrite(vmcs.Ctrl.cr4_mask, std.math.maxInt(u64));

    try vmwrite(vmcs.Ctrl.cr3_target_count, 0);
}

/// Set up VM-Exit control fields.
/// cf. SDM Vol.3C 27.2.1.2.
fn setupExitCtrls(_: *Vcpu) VmxError!void {
    const basic_msr = am.readMsrVmxBasic();

    // VM-Exit control.
    var exit_ctrl = try vmcs.PrimaryExitCtrl.store();
    exit_ctrl.host_addr_space_size = true;
    exit_ctrl.load_ia32_efer = true;
    exit_ctrl.save_ia32_efer = true;
    try adjustRegMandatoryBits(
        exit_ctrl,
        if (basic_msr.true_control) am.readMsr(.vmx_true_exit_ctls) else am.readMsr(.vmx_exit_ctls),
    ).load();

    try vmwrite(vmcs.Ctrl.vmexit_msr_load_count, 0);
    try vmwrite(vmcs.Ctrl.vmexit_msr_store_count, 0);
}

/// Set up VM-Entry control fields.
/// cf. SDM Vol.3C 27.2.1.3.
fn setupEntryCtrls(_: *Vcpu) VmxError!void {
    const basic_msr = am.readMsrVmxBasic();

    // VM-Entry control.
    var entry_ctrl = try vmcs.EntryCtrl.store();
    entry_ctrl.ia32e_mode_guest = false;
    entry_ctrl.load_ia32_efer = true;
    try adjustRegMandatoryBits(
        entry_ctrl,
        if (basic_msr.true_control) am.readMsr(.vmx_true_entry_ctls) else am.readMsr(.vmx_entry_ctls),
    ).load();

    try vmwrite(vmcs.Ctrl.vmentry_msr_load_count, 0);
}

/// Set up host state.
/// cf. SDM Vol.3C 27.2.2.
fn setupHostState(_: *Vcpu) VmxError!void {
    // Control registers.
    try vmwrite(vmcs.Host.cr0, am.readCr0());
    try vmwrite(vmcs.Host.cr3, am.readCr3());
    try vmwrite(vmcs.Host.cr4, am.readCr4());

    // General registers.
    try vmwrite(vmcs.Host.rip, &Vcpu.asmVmExit);
    try vmwrite(vmcs.Host.rsp, @intFromPtr(&vmexit_stack) + vmexit_stack_size);

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

fn setupGuestState(vcpu: *Vcpu) VmxError!void {
    // Control registers.
    var cr0 = std.mem.zeroes(am.Cr0);
    cr0.pe = true; // Protected-mode
    cr0.ne = true; // Numeric error
    cr0.et = true; // Extension type
    cr0.pg = false; // Paging
    var cr4: am.Cr4 = @bitCast(try vmread(vmcs.Guest.cr4));
    cr4.pae = false;
    cr4.vmxe = true; // TODO: Should we expose this bit to guest?? (this is requirement for successful VM-entry)
    try vmwrite(vmcs.Guest.cr0, cr0);
    try vmwrite(vmcs.Guest.cr4, cr4);

    // Segment registers.
    {
        // Base
        try vmwrite(vmcs.Guest.cs_base, 0);
        try vmwrite(vmcs.Guest.ss_base, 0);
        try vmwrite(vmcs.Guest.ds_base, 0);
        try vmwrite(vmcs.Guest.es_base, 0);
        try vmwrite(vmcs.Guest.fs_base, 0);
        try vmwrite(vmcs.Guest.gs_base, 0);
        try vmwrite(vmcs.Guest.tr_base, 0);
        try vmwrite(vmcs.Guest.gdtr_base, 0);
        try vmwrite(vmcs.Guest.idtr_base, 0);
        try vmwrite(vmcs.Guest.ldtr_base, 0xDEAD00); // Marker to indicate the guest.

        // Limit
        try vmwrite(vmcs.Guest.cs_limit, @as(u64, std.math.maxInt(u32)));
        try vmwrite(vmcs.Guest.ss_limit, @as(u64, std.math.maxInt(u32)));
        try vmwrite(vmcs.Guest.ds_limit, @as(u64, std.math.maxInt(u32)));
        try vmwrite(vmcs.Guest.es_limit, @as(u64, std.math.maxInt(u32)));
        try vmwrite(vmcs.Guest.fs_limit, @as(u64, std.math.maxInt(u32)));
        try vmwrite(vmcs.Guest.gs_limit, @as(u64, std.math.maxInt(u32)));
        try vmwrite(vmcs.Guest.tr_limit, 0);
        try vmwrite(vmcs.Guest.ldtr_limit, 0);
        try vmwrite(vmcs.Guest.idtr_limit, 0);
        try vmwrite(vmcs.Guest.gdtr_limit, 0);

        // Access Rights
        const cs_right = vmcs.SegmentRights{
            .type = .CodeERA,
            .s = .CodeOrData,
            .dpl = 0,
            .g = .KByte,
            .long = false,
            .db = 1,
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
        };
        const ldtr_right = vmcs.SegmentRights{
            .type = .DataRW,
            .s = .System,
            .dpl = 0,
            .g = .Byte,
            .long = false,
            .db = 0,
        };
        try vmwrite(vmcs.Guest.cs_rights, cs_right);
        try vmwrite(vmcs.Guest.ss_rights, ds_right);
        try vmwrite(vmcs.Guest.ds_rights, ds_right);
        try vmwrite(vmcs.Guest.es_rights, ds_right);
        try vmwrite(vmcs.Guest.fs_rights, ds_right);
        try vmwrite(vmcs.Guest.gs_rights, ds_right);
        try vmwrite(vmcs.Guest.tr_rights, tr_right);
        try vmwrite(vmcs.Guest.ldtr_rights, ldtr_right);

        // Selector
        try vmwrite(vmcs.Guest.cs_sel, 0);
        try vmwrite(vmcs.Guest.ss_sel, 0);
        try vmwrite(vmcs.Guest.ds_sel, 0);
        try vmwrite(vmcs.Guest.es_sel, 0);
        try vmwrite(vmcs.Guest.fs_sel, 0);
        try vmwrite(vmcs.Guest.gs_sel, 0);
        try vmwrite(vmcs.Guest.tr_sel, 0);
        try vmwrite(vmcs.Guest.ldtr_sel, 0);

        // FS/GS base
        try vmwrite(vmcs.Guest.fs_base, 0);
        try vmwrite(vmcs.Guest.gs_base, 0);
    }

    // MSR
    try vmwrite(vmcs.Guest.sysenter_cs, 0);
    try vmwrite(vmcs.Guest.sysenter_esp, 0);
    try vmwrite(vmcs.Guest.sysenter_eip, 0);
    try vmwrite(vmcs.Guest.efer, 0);

    // General registers.
    try vmwrite(vmcs.Guest.rflags, am.FlagsRegister.new());

    // Other crucial fields.
    try vmwrite(vmcs.Guest.vmcs_link_pointer, std.math.maxInt(u64));
    try vmwrite(vmcs.Guest.rip, linux.layout.kernel_base);
    vcpu.guest_regs.rsi = linux.layout.bootparam;
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
fn getInstError() VmxError!InstructionError {
    return @enumFromInt(@as(u32, @truncate(try vmread(vmcs.Ro.vminstruction_error))));
}

/// Get a VM-exit reason from VMCS.
fn getExitReason() VmxError!ExitInformation {
    return @bitCast(@as(u32, @truncate(try vmread(vmcs.Ro.vmexit_reason))));
}

/// Get a VM-exit qualification from VMCS.
fn getExitQual(T: anytype) VmxError!T {
    return @bitCast(@as(u64, try vmread(vmcs.Ro.exit_qual)));
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

/// Reason of failures of VMX instructions.
/// This is not updated on VM-exit.
/// cf. SDM Vol.3C 31.4.
pub const InstructionError = enum(u32) {
    error_not_available = 0,
    vmcall_in_vmxroot = 1,
    vmclear_invalid_phys = 2,
    vmclear_vmxonptr = 3,
    vmlaunch_nonclear_vmcs = 4,
    vmresume_nonlaunched_vmcs = 5,
    vmresume_after_vmxoff = 6,
    vmentry_invalid_ctrl = 7,
    vmentry_invalid_host_state = 8,
    vmptrld_invalid_phys = 9,
    vmptrld_vmxonp = 10,
    vmptrld_incorrect_rev = 11,
    vmrw_unsupported_component = 12,
    vmw_ro_component = 13,
    vmxon_in_vmxroot = 15,
    vmentry_invalid_exec_ctrl = 16,
    vmentry_nonlaunched_exec_ctrl = 17,
    vmentry_exec_vmcsptr = 18,
    vmcall_nonclear_vmcs = 19,
    vmcall_invalid_exitctl = 20,
    vmcall_incorrect_msgrev = 22,
    vmxoff_dualmonitor = 23,
    vmcall_invalid_smm = 24,
    vmentry_invalid_execctrl = 25,
    vmentry_events_blocked = 26,
    invalid_invept = 28,
};

/// Provides a basic information about VM exit.
/// cf. SDM Vol 3C 25.9.1.
pub const ExitInformation = packed struct(u32) {
    /// Basic exit reason.
    basic_reason: ExitReason,
    /// Always 0.
    _zero: u1 = 0,
    /// Undefined.
    _reserved1: u10 = 0,
    _one: u1 = 1,
    /// Pending MTF VM exit.
    pending_mtf: u1 = 0,
    /// VM exit from VMX root operation.
    exit_vmxroot: bool,
    /// Undefined.
    _reserved2: u1 = 0,
    /// If true, VM-entry failure. If false, true VM exit.
    entry_failure: bool,
};

/// Reason of every VM-exit and certain VM-entry failures.
/// cf. SDM Vol.3C Appendix C.
pub const ExitReason = enum(u16) {
    /// Exception or NMI.
    /// 1. Guest caused an exception of which the bit in the exception bitmap is set.
    /// 2. NMI was delivered to the logical processor.
    exception_nmi = 0,
    /// An external interrupt arrived.
    extintr = 1,
    /// Triple fault occurred.
    triple_fault = 2,
    /// INIT signal arrived.
    init = 3,
    /// Start-up IPI arrived.
    sipi = 4,
    /// I/O system-management interrupt.
    io_intr = 5,
    /// SMI arrived and caused an SMM VM exit.
    other_smi = 6,
    /// Interrupt window.
    intr_window = 7,
    /// NMI window.
    nmi_window = 8,
    /// Guest attempted a task switch.
    task_switch = 9,
    /// Guest attempted to execute CPUID.
    cpuid = 10,
    /// Guest attempted to execute GETSEC.
    getsec = 11,
    /// Guest attempted to execute HLT.
    hlt = 12,
    /// Guest attempted to execute INVD.
    invd = 13,
    /// Guest attempted to execute INVLPG.
    invlpg = 14,
    /// Guest attempted to execute RDPMC.
    rdpmc = 15,
    /// Guest attempted to execute RDTSC.
    rdtsc = 16,
    /// Guest attempted to execute RSM in SMM.
    rsm = 17,
    /// Guest attempted to execute VMCALL.
    vmcall = 18,
    /// Guest attempted to execute VMCLEAR.
    vmclear = 19,
    /// Guest attempted to execute VMLAUNCH.
    vmlaunch = 20,
    /// Guest attempted to execute VMPTRLD.
    vmptrld = 21,
    /// Guest attempted to execute VMPTRST.
    vmptrst = 22,
    /// Guest attempted to execute VMREAD.
    vmread = 23,
    /// Guest attempted to execute VMRESUME.
    vmresume = 24,
    /// Guest attempted to execute VMWRITE.
    vmwrite = 25,
    /// Guest attempted to execute VMXOFF.
    vmxoff = 26,
    /// Guest attempted to execute VMXON.
    vmxon = 27,
    /// Control-register access.
    cr = 28,
    /// Debug-register access.
    dr = 29,
    /// I/O instruction.
    io = 30,
    /// Guest attempted to execute RDMSR.
    rdmsr = 31,
    /// Guest attempted to execute WRMSR.
    wrmsr = 32,
    /// VM-entry failure due to invalid guest state.
    entry_fail_guest = 33,
    /// VM-entry failure due to MSR loading.
    entry_fail_msr = 34,

    /// Guest attempted to execute MWAIT.
    mwait = 36,
    /// Monitor trap flag.
    monitor_trap = 37,

    /// Guest attempted to execute MONITOR.
    monitor = 39,
    /// Guest attempted to execute PAUSE.
    pause = 40,
    /// VM-entry failure due to machine-check event.
    entry_fail_mce = 41,

    /// TPR below threshold.
    tpr_threshold = 43,
    /// Guest attempted to access memory at a physical address on the API-access page.
    apic = 44,
    /// EOI virtualization was performed for a virtual interrupt whose vector indexed a bit set in the EOI-exit bitmap.
    veoi = 45,
    /// Access to GDTR or IDTR.
    gdtr_idtr = 46,
    /// Access to LDTR or TR.
    ldtr_tr = 47,
    /// EPT violation.
    ept = 48,
    /// EPT misconfiguration.
    ept_misconfig = 49,
    /// Guest attempted to execute INVEPT.
    invept = 50,
    /// Guest attempted to execute RDTSCP.
    rdtscp = 51,
    /// Preemption timer counted down to zero.
    preemption_timer = 52,
    /// Guest attempted to execute INVVPID.
    invvpid = 53,
    /// Guest attempted to execute WBINVD or WBNOINVD.
    wbinvd_wbnoinvd = 54,
    /// Guest attempted to execute XSETBV.
    xsetbv = 55,
    /// Guest completed a write to the virtual-APIC page that must be virtualized.
    apic_write = 56,
    /// Guest attempted to execute RDRAND.
    rdrand = 57,
    /// Guest attempted to execute INVPCID.
    invpcid = 58,
    /// Guest invoked a VM function with the VMFUNC.
    vmfunc = 59,
    /// Guest attempted to execute ENCLS.
    encls = 60,
    /// Guest attempted to execute RDSEED.
    rdseed = 61,
    /// Processor attempted to create a page-modification log entry but the PML index exceeded range 0-511.
    page_log_full = 62,
    /// Guest attempted to execute XSAVES.
    xsaves = 63,
    /// Guest attempted to execute XRSTORS.
    xrstors = 64,
    /// Guest attempted to execute PCONFIG.
    pconfig = 65,
    /// SPP-related event.
    spp = 66,
    /// Guest attempted to execute UMWAIT.
    umwait = 67,
    /// Guest attempted to execute TPAUSE.
    tpause = 68,
    /// Guest attempted to execute LOADIWKEY.
    loadiwkey = 69,
    /// Guest attempted to execute ENCLV.
    enclv = 70,

    /// ENQCMD PASID translation failure.
    enqcmd_pasid_fail = 72,
    /// ENQCMDS PASID translation failure.
    enqcmds_pasid_fail = 73,
    /// Bus lock.
    bus_lock = 74,
    /// Certain operations prevented the processor from reaching an instruction boundary within timeout.
    timeout = 75,
    /// Guest attempted to execute SEAMCALL.
    seamcall = 76,
    /// Guest attempted to execute SEAMOP.
    tdcall = 77,
};

// =====================================================

/// Partially checks the validity of guest state.
fn partialCheckGuest() VmxError!void {
    if (!ymir.is_debug) @compileError("partialCheckGuest() is only for debug build");

    const cr0: am.Cr0 = @bitCast(try vmcs.vmread(vmcs.Guest.cr0));
    const cr3 = try vmcs.vmread(vmcs.Guest.cr3);
    const cr4: am.Cr4 = @bitCast(try vmcs.vmread(vmcs.Guest.cr4));
    const entry_ctrl = try vmcs.EntryCtrl.store();
    const exec_ctrl = try vmcs.PrimaryProcExecCtrl.store();
    const exec_ctrl2 = try vmcs.SecondaryProcExecCtrl.store();
    const efer: am.Efer = @bitCast(try vmcs.vmread(vmcs.Guest.efer));

    // == Checks on Guest Control Registers, Debug Registers, and MSRs.
    // cf. SDM Vol 3C 27.3.1.1.
    {
        const vmx_cr0_fixed0 = am.readMsr(.vmx_cr0_fixed0);
        const vmx_cr0_fixed1 = am.readMsr(.vmx_cr0_fixed1);
        const vmx_cr4_fixed0 = am.readMsr(.vmx_cr4_fixed0);
        const vmx_cr4_fixed1 = am.readMsr(.vmx_cr4_fixed1);
        if (!(exec_ctrl.activate_secondary_controls and exec_ctrl2.unrestricted_guest)) {
            if (@as(u64, @bitCast(cr0)) & vmx_cr0_fixed0 != vmx_cr0_fixed0) @panic("CR0: Fixed0 bits must be 1");
            if (@as(u64, @bitCast(cr0)) & ~vmx_cr0_fixed1 != 0) @panic("CR0: Fixed1 bits must be 0");
        }
        if (@as(u64, @bitCast(cr4)) & vmx_cr4_fixed0 != vmx_cr4_fixed0) @panic("CR4: Fixed0 bits must be 1");
        if (@as(u64, @bitCast(cr4)) & ~vmx_cr4_fixed1 != 0) @panic("CR4: Fixed1 bits must be 0");
    }
    if (cr0.pg and !cr0.pe) @panic("CR0: PE must be set when PG is set");
    // TODO: CR4 field must not set any bit to a value not supported in VMX operation.
    if (cr4.cet and !cr0.wp) @panic("CR0: WP must be set when CR4.CET is set");
    // TODO: If "load debug controls" is 1, bits reserved in IA32_DEBUGCTL MSR must be 0.
    if (entry_ctrl.ia32e_mode_guest and !(cr0.pg and cr4.pae)) @panic("CR0: PG and CR4.PAE must be set when IA-32e mode is enabled");
    if (!entry_ctrl.ia32e_mode_guest and cr4.pcide) @panic("CR4: PCIDE must be unset when IA-32e mode is disabled");
    if (cr3 >> 46 != 0) @panic("CR3: Reserved bits must be zero");
    if (!isCanonical(try vmcs.vmread(vmcs.Guest.sysenter_esp))) @panic("IA32_SYSENTER_ESP must be canonical");
    if (!isCanonical(try vmcs.vmread(vmcs.Guest.sysenter_eip))) @panic("IA32_SYSENTER_EIP must be canonical");
    if (entry_ctrl.load_cet_state) @panic("Unimplemented: Load CET state");
    if (entry_ctrl.load_debug_controls) @panic("Unimplemented: Load debug controls.");
    if (entry_ctrl.load_perf_global_ctrl) @panic("Unimplemented: Load perf global ctrl.");
    if (entry_ctrl.load_ia32_pat) {
        const pat = try vmcs.vmread(vmcs.Guest.pat);
        for (0..8) |i| {
            const iu6: u6 = @truncate(i);
            const val = (pat >> (iu6 * 3));
            if (val != 0 and val != 1 and val != 4 and val != 6 and val != 7) @panic("PAT: invalid value");
        }
    }
    if (entry_ctrl.load_ia32_efer) {
        // TODO: Bits reserved in IA32_EFER_MSR must be 0.
        if (efer.lma != entry_ctrl.ia32e_mode_guest) @panic("EFER and IA-32e mode mismatch");
        if (cr0.pg and (efer.lma != efer.lme)) @panic("EFER.LME must be identical to EFER.LMA when CR0.PG is set");
    }
    if (entry_ctrl.load_ia32_bndcfgs) @panic("Unimplemented: Load IA32_BNDCFGS");
    if (entry_ctrl.load_rtit_ctl) @panic("Unimplemented: Load RTIT control");
    if (entry_ctrl.load_guest_lbr_ctl) @panic("Unimplemented: Load guest LBR control");
    if (entry_ctrl.load_pkrs) @panic("Unimplemented: Load PKRS");
    if (entry_ctrl.load_uinv) @panic("Unimplemented: Load UINV");

    // == Checks on Guest Segment Registers.
    // cf. SDM Vol 3C 28.3.1.2.
    // Selector.
    const cs_sel = gdt.SegmentSelector.from(try vmcs.vmread(vmcs.Guest.cs_sel));
    const tr_sel = gdt.SegmentSelector.from(try vmcs.vmread(vmcs.Guest.tr_sel));
    const ldtr_sel = gdt.SegmentSelector.from(try vmcs.vmread(vmcs.Guest.ldtr_sel));
    const ss_sel = gdt.SegmentSelector.from(try vmcs.vmread(vmcs.Guest.ss_sel));
    if (tr_sel.ti != 0) @panic("TR.sel: TI flag must be 0");
    {
        const ldtr_ar: vmcs.SegmentRights = @bitCast(@as(u32, @truncate(try vmcs.vmread(vmcs.Guest.ldtr_rights))));
        if (!ldtr_ar.unusable and ldtr_sel.ti != 0) @panic("LDTR.sel: TI flag must be 0");
    }
    if (cs_sel.rpl != ss_sel.rpl) @panic("CS.sel.RPL must be equal to SS.sel.RPL");

    // Base.
    if (!isCanonical(try vmcs.vmread(vmcs.Guest.tr_base))) @panic("TR.base must be canonical");
    if (!isCanonical(try vmcs.vmread(vmcs.Guest.fs_base))) @panic("FS.base must be canonical");
    if (!isCanonical(try vmcs.vmread(vmcs.Guest.gs_base))) @panic("GS.base must be canonical");
    if (!isCanonical(try vmcs.vmread(vmcs.Guest.ldtr_base))) @panic("LDTR.base must be canonical");
    if ((try vmcs.vmread(vmcs.Guest.cs_base)) >> 32 != 0) @panic("CS.base[63:32] must be zero");
    if ((try vmcs.vmread(vmcs.Guest.ss_base)) >> 32 != 0) @panic("SS.base[63:32] must be zero");
    if ((try vmcs.vmread(vmcs.Guest.ds_base)) >> 32 != 0) @panic("DS.base[63:32] must be zero");
    if ((try vmcs.vmread(vmcs.Guest.es_base)) >> 32 != 0) @panic("ES.base[63:32] must be zero");

    // Access Rights.
    const cs_ar = vmcs.SegmentRights.from(try vmcs.vmread(vmcs.Guest.cs_rights));
    const ss_ar = vmcs.SegmentRights.from(try vmcs.vmread(vmcs.Guest.ss_rights));
    const ds_ar = vmcs.SegmentRights.from(try vmcs.vmread(vmcs.Guest.ds_rights));
    const es_ar = vmcs.SegmentRights.from(try vmcs.vmread(vmcs.Guest.es_rights));
    const fs_ar = vmcs.SegmentRights.from(try vmcs.vmread(vmcs.Guest.fs_rights));
    const gs_ar = vmcs.SegmentRights.from(try vmcs.vmread(vmcs.Guest.gs_rights));
    const ds_sel = gdt.SegmentSelector.from(try vmcs.vmread(vmcs.Guest.ds_sel));
    const es_sel = gdt.SegmentSelector.from(try vmcs.vmread(vmcs.Guest.es_sel));
    const fs_sel = gdt.SegmentSelector.from(try vmcs.vmread(vmcs.Guest.fs_sel));
    const gs_sel = gdt.SegmentSelector.from(try vmcs.vmread(vmcs.Guest.gs_sel));
    const cs_limit = try vmcs.vmread(vmcs.Guest.cs_limit);
    const ss_limit = try vmcs.vmread(vmcs.Guest.ss_limit);
    const ds_limit = try vmcs.vmread(vmcs.Guest.ds_limit);
    const es_limit = try vmcs.vmread(vmcs.Guest.es_limit);
    const fs_limit = try vmcs.vmread(vmcs.Guest.fs_limit);
    const gs_limit = try vmcs.vmread(vmcs.Guest.gs_limit);
    //  type
    if (cs_ar.type != .CodeEA and cs_ar.type != .CodeERA and cs_ar.type != .CodeECA and cs_ar.type != .CodeERCA) @panic("CS.rights: Invalid value");
    if (!ss_ar.unusable and (ss_ar.type != .DataRWA and ss_ar.type != .DataRWAE)) @panic("SS.rights: Invalid value");
    if (!ds_ar.unusable and @intFromEnum(ds_ar.type) & 1 == 0) @panic("DS.rights: Invalid value (accessed)");
    if (!es_ar.unusable and @intFromEnum(es_ar.type) & 1 == 0) @panic("ES.rights: Invalid value (accessed)");
    if (!fs_ar.unusable and @intFromEnum(fs_ar.type) & 1 == 0) @panic("FS.rights: Invalid value (accessed)");
    if (!gs_ar.unusable and @intFromEnum(gs_ar.type) & 1 == 0) @panic("GS.rights: Invalid value (accessed)");
    if (!ds_ar.unusable and (@intFromEnum(ds_ar.type) & 0b1000 != 0 and @intFromEnum(ds_ar.type) & 0b10 == 0)) @panic("DS.rights: Invalid value (code)");
    if (!es_ar.unusable and (@intFromEnum(es_ar.type) & 0b1000 != 0 and @intFromEnum(es_ar.type) & 0b10 == 0)) @panic("ES.rights: Invalid value (code)");
    if (!fs_ar.unusable and (@intFromEnum(fs_ar.type) & 0b1000 != 0 and @intFromEnum(fs_ar.type) & 0b10 == 0)) @panic("FS.rights: Invalid value (code)");
    if (!gs_ar.unusable and (@intFromEnum(gs_ar.type) & 0b1000 != 0 and @intFromEnum(gs_ar.type) & 0b10 == 0)) @panic("GS.rights: Invalid value (code)");
    //  s
    if (cs_ar.s != .CodeOrData) @panic("CS.rights: Invalid value (code)");
    if (!ss_ar.unusable and ss_ar.s != .CodeOrData) @panic("SS.rights: Invalid value (code)");
    if (!ds_ar.unusable and ds_ar.s != .CodeOrData) @panic("DS.rights: Invalid value (code)");
    if (!es_ar.unusable and es_ar.s != .CodeOrData) @panic("ES.rights: Invalid value (code)");
    if (!fs_ar.unusable and fs_ar.s != .CodeOrData) @panic("FS.rights: Invalid value (code)");
    if (!gs_ar.unusable and gs_ar.s != .CodeOrData) @panic("GS.rights: Invalid value (code)");
    // DPL
    if (cs_ar.type == .DataRWA and cs_ar.dpl != 0) @panic("CS.rights: Invalid value (DPL)");
    if ((cs_ar.type == .CodeEA or cs_ar.type == .CodeERA) and cs_ar.dpl != ss_ar.dpl) @panic("CS.rights: Invalid value (DPL)");
    if ((cs_ar.type == .CodeECA or cs_ar.type == .CodeERCA) and cs_ar.dpl > ss_ar.dpl) @panic("CS.rights: Invalid value (DPL)");
    if (ss_ar.dpl != ss_sel.rpl) @panic("SS.rights: DPL must be equal to RPL");
    // TODO: The DPL of SS must be 0 either if ...
    if (ds_ar.dpl < ds_sel.rpl) @panic("DS.rights: Invalid value (DPL)");
    if (es_ar.dpl < es_sel.rpl) @panic("ES.rights: Invalid value (DPL)");
    if (fs_ar.dpl < fs_sel.rpl) @panic("FS.rights: Invalid value (DPL)");
    if (gs_ar.dpl < gs_sel.rpl) @panic("GS.rights: Invalid value (DPL)");
    // P
    if (!cs_ar.p) @panic("CS.rights: P must be set");
    if (!ss_ar.unusable and !ss_ar.p) @panic("SS.rights: P must be set");
    if (!ds_ar.unusable and !ds_ar.p) @panic("DS.rights: P must be set");
    if (!es_ar.unusable and !es_ar.p) @panic("ES.rights: P must be set");
    if (!fs_ar.unusable and !fs_ar.p) @panic("FS.rights: P must be set");
    if (!gs_ar.unusable and !gs_ar.p) @panic("GS.rights: P must be set");
    // TODO: Reserved bits must be zero.
    // D/B
    if ((entry_ctrl.ia32e_mode_guest and cs_ar.long) and cs_ar.db != 0) @panic("CS.rights: D/B must be zero when IA-32e mode is enabled");
    // G.
    if (cs_limit & 0xFFF != 0xFFF and cs_ar.g != .Byte) @panic("CS.rights: G must be clear when CS.limit is not page-aligned");
    if (!ss_ar.unusable and ss_limit & 0xFFF != 0xFFF and ss_ar.g != .Byte) @panic("SS.rights: G must be clear when SS.limit is not page-aligned");
    if (!ds_ar.unusable and ds_limit & 0xFFF != 0xFFF and ds_ar.g != .Byte) @panic("DS.rights: G must be clear when DS.limit is not page-aligned");
    if (!es_ar.unusable and es_limit & 0xFFF != 0xFFF and es_ar.g != .Byte) @panic("ES.rights: G must be clear when ES.limit is not page-aligned");
    if (!fs_ar.unusable and fs_limit & 0xFFF != 0xFFF and fs_ar.g != .Byte) @panic("FS.rights: G must be clear when FS.limit is not page-aligned");
    if (!gs_ar.unusable and gs_limit & 0xFFF != 0xFFF and gs_ar.g != .Byte) @panic("GS.rights: G must be clear when GS.limit is not page-aligned");
    if (cs_limit >> 20 != 0 and cs_ar.g != .KByte) @panic("CS.rights: G must be set.");
    if (!ss_ar.unusable and ss_limit >> 20 != 0 and ss_ar.g != .KByte) @panic("SS.rights: G must be set.");
    if (!ds_ar.unusable and ds_limit >> 20 != 0 and ds_ar.g != .KByte) @panic("DS.rights: G must be set.");
    if (!es_ar.unusable and es_limit >> 20 != 0 and es_ar.g != .KByte) @panic("ES.rights: G must be set.");
    if (!fs_ar.unusable and fs_limit >> 20 != 0 and fs_ar.g != .KByte) @panic("FS.rights: G must be set.");
    if (!gs_ar.unusable and gs_limit >> 20 != 0 and gs_ar.g != .KByte) @panic("GS.rights: G must be set.");
    // TODO: Reserved bits must be zero.

    // TODO: TR
    // TODO: LDTR

    // == Checks on Guest Descriptor-Table Registers.
    // cf. SDM Vol 3C 27.3.1.3.
    if (!isCanonical(try vmcs.vmread(vmcs.Guest.gdtr_base))) @panic("GDTR.base must be canonical");
    if (!isCanonical(try vmcs.vmread(vmcs.Guest.idtr_base))) @panic("IDTR.base must be canonical");
    if (try vmcs.vmread(vmcs.Guest.gdtr_limit) >> 16 != 0) @panic("GDTR.limit[15:0] must be zero");
    if (try vmcs.vmread(vmcs.Guest.idtr_limit) >> 16 != 0) @panic("IDTR.limit[15:0] must be zero");

    // == Checks on Guest RIP, RFLAGS, and SSP
    // cf. SDM Vol 3C 27.3.1.4.
    const rip = try vmcs.vmread(vmcs.Guest.rip);
    const intr_info = try vmread(vmcs.Ctrl.vmentry_interrupt_information_field);
    const rflags: am.FlagsRegister = @bitCast(try vmcs.vmread(vmcs.Guest.rflags));

    if ((entry_ctrl.ia32e_mode_guest or cs_ar.long) and (rip >> 32) != 0) @panic("RIP: Upper address must be all zeros");
    // TODO: If the processor supports N < 64 linear-address bits, ...

    if (rflags._reserved4 != 0 or rflags._reserved1 != 0 or rflags._reserved2 != 0 or rflags._reserved3 != 0) @panic("RFLAGS: Reserved bits must be zero");
    if (rflags._reservedO != 1) @panic("RFLAGS: Reserved bit 1 must be one");
    if ((entry_ctrl.ia32e_mode_guest or !cr0.pe) and rflags.vm) @panic("RFLAGS: VM must be clear when IA-32e mode is enabled");
    if (((intr_info >> 31) & 1 != 0) and !rflags.ief) @panic("RFLAGS: IF must be set when valid bit in VM-entry interruption-information field is set.");

    // == Checks on Guest Non-Register State.
    // cf. SDM Vol 3C 27.3.1.5.
    // Activity state.
    const activity_state = try vmcs.vmread(vmcs.Guest.activity_state);
    if (activity_state != 0) @panic("Unsupported activity state.");
    const intr_state = try vmcs.vmread(vmcs.Guest.interrupt_status);
    if ((intr_state >> 5) != 0) @panic("Unsupported interruptability state.");
    // TODO: other checks

    // Interruptibility state.
    // TODO

    // Pending debug exceptions.
    // TODO

    // VMCS link pointer.
    if (try vmcs.vmread(vmcs.Guest.vmcs_link_pointer) != std.math.maxInt(u64)) @panic("Unsupported VMCS link pointer other than FFFFFFFF_FFFFFFFFh");

    // == Checks on Guest Page-Directory-Pointer-Table Entries.
    // cf. SDM Vol 3C 27.3.1.6.
    const is_pae_paging = (cr0.pg and cr4.pae and !entry_ctrl.ia32e_mode_guest); // When PAE paging, CR3 references level-4 table.
    if (is_pae_paging) {
        // TODO
        @panic("Unimplemented: PAE paging");
    }
}

// =====================================================

test {
    std.testing.refAllDeclsRecursive(@This());
    std.testing.refAllDeclsRecursive(@import("vmx/vmcs.zig"));
}
