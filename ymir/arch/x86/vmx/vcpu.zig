const std = @import("std");
const log = std.log.scoped(.vmx);
const Allocator = std.mem.Allocator;

const ymir = @import("ymir");
const bits = ymir.bits;
const mem = ymir.mem;
const Phys = mem.Phys;
const linux = ymir.linux;
const BootParams = linux.boot.BootParams;

const arch = @import("arch.zig");
const am = arch.am;
const apic = arch.apic;
const gdt = arch.gdt;
const serial = arch.serial;
const intr = arch.intr;
const isr = arch.isr;
const pg = arch.pg;
const pic = arch.pic;

const vmcs = @import("vmcs.zig");
const vmam = @import("asm.zig");
const ept = @import("ept.zig");
const cpuid = @import("cpuid.zig");
const msr = @import("msr.zig");
const cr = @import("cr.zig");
const io = @import("io.zig");
const vmc = @import("vmc.zig");
const vmx = @import("common.zig");
const dbg = @import("dbg.zig");
const qual = vmx.qual;

const vmwrite = vmx.vmwrite;
const vmread = vmx.vmread;
const IrqLine = pic.IrqLine;

pub const VmxError = vmx.VmxError;

/// Virtual logical CPU.
/// TODO: must be per-CPU variable. Currently, it only supports single CPU.
pub const Vcpu = struct {
    const Self = @This();

    /// ID of the logical processor.
    id: usize = 0,
    /// VPID of the virtual machine.
    vpid: u16 = 1,
    /// VMXON region.
    vmxon_region: *VmxonRegion = undefined,
    /// VMCS region.
    vmcs_region: *VmcsRegion = undefined,
    /// The first VM-entry has been done.
    launch_done: bool = false,
    /// IA-32e mode (long mode) is enabled.
    ia32_enabled: bool = false,
    /// Saved guest registers.
    guest_regs: vmx.GuestRegisters = undefined,
    /// EPT pointer.
    eptp: ept.Eptp = undefined,
    /// Host physical address where the guest is mapped.
    guest_base: Phys = undefined,
    /// Host saved MSRs.
    host_msr: msr.ShadowMsr = undefined,
    /// Guest saved MSRs.
    guest_msr: msr.ShadowMsr = undefined,
    /// PIC.
    pic: io.Pic = io.Pic.new(),
    /// 8250 serial port.
    serial: io.Serial = io.Serial.new(),
    /// Pending IRQ.
    pending_irq: u16 = 0,
    /// I/O bitmap.
    io_bitmap: vmx.IoBitmap = undefined,

    /// Create a new virtual CPU.
    /// This function does not virtualize the CPU.
    /// You MUST call `virtualize` to put the CPU in VMX root operation.
    pub fn new(vpid: u16) Self {
        const id = apic.getLapicId();

        return Self{
            .id = id,
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
        try registerMsrs(self, allocator);
        try setupExecCtrls(self, allocator);
        try setupExitCtrls(self);
        try setupEntryCtrls(self);
        try setupHostState(self);
        try setupGuestState(self);
    }

    /// Set EPTP to the vCPU.
    pub fn setEptp(self: *Self, eptp: ept.Eptp, host_start: [*]u8) VmxError!void {
        self.eptp = eptp;
        self.guest_base = ymir.mem.virt2phys(host_start);
        try vmwrite(vmcs.ctrl.eptp, eptp);
    }

    /// Start executing vCPU.
    pub fn loop(self: *Self) VmxError!void {
        // Subscribe to interrupts.
        intr.subscribe(self, intrSubscriberCallback) catch return error.InterruptFull;

        // Start endless VM-entry / VM-exit loop.
        while (true) {
            if (ymir.is_debug) {
                try dbg.partialCheckGuest();
            }

            // Save MSR.
            try updateMsrs(self);

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
            .exception_nmi => {
                const ii = try vmx.ExitIntrInfo.load(.exit);
                if (!ii.valid) {
                    log.err("Invalid VM-exit interrupt information.", .{});
                    self.abort();
                }
                switch (ii.vector) {
                    // General protection fault
                    13 => { // general protection fault
                        log.err("General protection fault in the guest.", .{});
                        self.abort();
                    },
                    // Other exceptions
                    else => |vec| {
                        log.err("Unhandled guest exception: vector={d}", .{vec});
                        self.abort();
                    },
                }
            },
            .hlt => {
                // Wait until the external interrupt is generated.
                while (!try self.injectExtIntr()) {
                    asm volatile (
                        \\sti
                        \\hlt
                        \\cli
                    );
                }

                try vmwrite(vmcs.guest.activity_state, 0);
                try vmwrite(vmcs.guest.interruptibility_state, 0);
                try self.stepNextInst();
            },
            .io => {
                const q = try getExitQual(qual.QualIo);
                try io.handleIo(self, q);
                try self.stepNextInst();
            },
            .cr => {
                const q = try getExitQual(qual.QualCr);
                try cr.handleAccessCr(self, q);
                try self.stepNextInst();
            },
            .ept => {
                const q = try getExitQual(qual.QualEptViolation);
                log.err("EPT violation: {?}", .{q});
                const lin = try vmread(vmcs.ro.guest_linear_address);
                const phys = try vmread(vmcs.ro.guest_physical_address);
                log.err("Guest linear address  : 0x{X:0>16}", .{lin});
                log.err("Guest physical address: 0x{X:0>16}", .{phys});
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
            .extintr => {
                // Consume the interrupt by Ymir.
                // At the same time, interrupt subscriber sets the pending IRQ.
                asm volatile (
                    \\sti
                    \\nop
                    \\cli
                );
                // Give the external interrupt to guest.
                _ = try self.injectExtIntr();
            },
            .vmcall => {
                try vmc.handleVmcall(self);
                try self.stepNextInst();
            },
            else => {
                log.err("Unhandled VM-exit: reason={?}", .{exit_info.basic_reason});
                self.abort();
            },
        }
    }

    /// Print guest state and stack trace, and abort.
    pub fn abort(self: *Self) noreturn {
        @branchHint(.cold);
        self.dump() catch log.err("Failed to dump VM information.", .{});
        ymir.endlessHalt();
    }

    /// Dump guest state and guest stack trace.
    pub fn dump(self: *Self) VmxError!void {
        try self.printGuestState();
        try self.printGuestStacktrace();
    }

    fn printGuestStacktrace(self: *Self) VmxError!void {
        log.err("=== Guest Stack Trace ===", .{});

        var rbp = self.guest_regs.rbp;
        var rip = try vmread(vmcs.guest.rip);
        var i: usize = 0;
        const cr3 = try vmread(vmcs.guest.cr3);

        while (true) : (i += 1) {
            log.err("#{d:0>2}: 0x{X:0>16}", .{ i, rip });

            if (pg.guestTranslateWalk(rbp, cr3, self.guest_base)) |rbp_gpa| {
                if (ept.translate(rbp_gpa, self.eptp.getLv4())) |rbp_host_addr| {
                    const rbp_gva: [*]u64 = @ptrFromInt(mem.phys2virt(rbp_host_addr));
                    rbp = rbp_gva[0];
                    rip = rbp_gva[1];
                } else break;
            } else {
                log.err("Failed to translate RBP to GPA.", .{});
                return;
            }
        }
    }

    fn printGuestState(self: *Self) VmxError!void {
        log.err("=== vCPU Information ===", .{});
        log.err("[Guest State]", .{});
        log.err("IA32-e: {}", .{self.ia32_enabled});
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
        log.err("Guest physical base: 0x{X:0>16}", .{self.guest_base});
    }

    /// Increment RIP by the length of the current instruction.
    fn stepNextInst(_: *Self) VmxError!void {
        const rip = try vmread(vmcs.guest.rip);
        try vmwrite(vmcs.guest.rip, rip + try vmread(vmcs.ro.exit_inst_len));
    }

    /// Inject external interrupt to the guest if possible.
    /// Returns true if the interrupt is injected, otherwise false.
    /// It's the totally Ymir's responsibility to send an EOI to the PIC
    /// because Ymir blocks EOI commands from the guest.
    fn injectExtIntr(self: *Self) VmxError!bool {
        const pending = self.pending_irq;
        const is_secondary_masked = bits.isset(self.pic.primary_mask, IrqLine.secondary);

        // No interrupts to inject.
        if (pending == 0) return false;
        // PIC is not initialized.
        if (self.pic.primary_phase != .initialized) return false;

        // Guest is blocking interrupts.
        const eflags: am.FlagsRegister = @bitCast(try vmread(vmcs.guest.rflags));
        if (!eflags.ief) return false;

        // Iterate all possible IRQs and inject one if possible.
        for (0..15) |i| {
            if (is_secondary_masked and i >= 8) break;

            const irq: IrqLine = @enumFromInt(i);
            const irq_bit = bits.tobit(u16, irq);
            // The IRQ is not pending.
            if (pending & irq_bit == 0) continue;

            // Check if the IRQ is masked.
            const is_masked = if (irq.isPrimary()) b: {
                break :b bits.isset(self.pic.primary_mask, irq.delta());
            } else b: {
                const is_irq_masked = bits.isset(self.pic.secondary_mask, irq.delta());
                break :b is_secondary_masked or is_irq_masked;
            };
            if (is_masked) continue;

            // Inject the interrupt.
            const intr_info = vmx.EntryIntrInfo{
                .vector = irq.delta() + if (irq.isPrimary()) self.pic.primary_base else self.pic.secondary_base,
                .type = .external,
                .ec_available = false,
                .valid = true,
            };
            try vmwrite(vmcs.ctrl.entry_intr_info, intr_info);

            // Clear the pending IRQ.
            self.pending_irq &= ~irq_bit;
            return true;
        }

        return false;
    }

    /// Callback function for interrupts.
    /// This function is to "share" IRQs between Ymir and the guest.
    /// This function is called before Ymir's interrupt handler and mark the incoming IRQ as pending.
    /// After that, Ymir's interrupt handler consumes the IRQ and send EOI to the PIC.
    fn intrSubscriberCallback(self_: *anyopaque, ctx: *isr.Context) void {
        const self: *Self = @alignCast(@ptrCast(self_));
        const vector = ctx.vector;

        if (ymir.intr.user_intr_base <= vector and vector < ymir.intr.user_intr_base + 16) {
            self.pending_irq |= bits.tobit(u16, vector - ymir.intr.user_intr_base);
        }
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
inline fn getVmcsRevisionId() u31 {
    return am.readMsrVmxBasic().vmcs_revision_id;
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

/// Clear and reset VMCS.
/// After this operation, the VMCS becomes active and current logical processor.
fn resetVmcs(vmcs_region: *VmcsRegion) VmxError!void {
    // The VMCS becomes inactive and flushed to memory.
    try am.vmclear(mem.virt2phys(vmcs_region));
    // Load and activate the VMCS.
    try am.vmptrld(mem.virt2phys(vmcs_region));
}

/// Save current host MSR values to MSR page, then update MSR counts.
fn updateMsrs(vcpu: *Vcpu) VmxError!void {
    // Save host MSRs.
    for (vcpu.host_msr.savedEnts()) |ent| {
        vcpu.host_msr.setByIndex(ent.index, am.readMsr(@enumFromInt(ent.index)));
    }

    // Update MSR counts.
    try vmwrite(vmcs.ctrl.vexit_msr_load_count, vcpu.host_msr.num_ents);
    try vmwrite(vmcs.ctrl.exit_msr_store_count, vcpu.guest_msr.num_ents);
    try vmwrite(vmcs.ctrl.entry_msr_load_count, vcpu.guest_msr.num_ents);
}

/// Register host-saved and guest-saved MSRs.
fn registerMsrs(vcpu: *Vcpu, allocator: Allocator) !void {
    vcpu.host_msr = try msr.ShadowMsr.init(allocator);
    vcpu.guest_msr = try msr.ShadowMsr.init(allocator);

    const hm = &vcpu.host_msr;
    const gm = &vcpu.guest_msr;

    // Host MSRs.
    hm.set(.tsc_aux, am.readMsr(.tsc_aux));
    hm.set(.star, am.readMsr(.star));
    hm.set(.lstar, am.readMsr(.lstar));
    hm.set(.cstar, am.readMsr(.cstar));
    hm.set(.fmask, am.readMsr(.fmask));
    hm.set(.kernel_gs_base, am.readMsr(.kernel_gs_base));

    // Guest MSRs.
    gm.set(.tsc_aux, 0);
    gm.set(.star, 0);
    gm.set(.lstar, 0);
    gm.set(.cstar, 0);
    gm.set(.fmask, 0);
    gm.set(.kernel_gs_base, 0);

    // Init MSR data in VMCS.
    try vmwrite(vmcs.ctrl.exit_msr_load_address, hm.phys());
    try vmwrite(vmcs.ctrl.exit_msr_store_address, gm.phys());
    try vmwrite(vmcs.ctrl.entry_msr_load_address, gm.phys());
}

/// Set up VM-Execution control fields.
/// cf. SDM Vol.3C 27.2.1.1, Appendix A.3.
fn setupExecCtrls(vcpu: *Vcpu, allocator: Allocator) VmxError!void {
    const basic_msr = am.readMsrVmxBasic();

    // Pin-based VM-Execution control.
    var pin_exec_ctrl = try vmcs.PinExecCtrl.store();
    pin_exec_ctrl.external_interrupt = true;
    try adjustRegMandatoryBits(
        pin_exec_ctrl,
        if (basic_msr.true_control) am.readMsr(.vmx_true_pinbased_ctls) else am.readMsr(.vmx_pinbased_ctls),
    ).load();

    // Primary Processor-based VM-Execution control.
    var ppb_exec_ctrl = try vmcs.PrimaryProcExecCtrl.store();
    ppb_exec_ctrl.activate_secondary_controls = true;
    ppb_exec_ctrl.unconditional_io = false;
    ppb_exec_ctrl.use_io_bitmap = true;
    ppb_exec_ctrl.hlt = true;
    ppb_exec_ctrl.use_tpr_shadow = true;
    ppb_exec_ctrl.tsc_offsetting = false;
    ppb_exec_ctrl.cr3load = true;
    ppb_exec_ctrl.cr3store = true;
    ppb_exec_ctrl.invlpg = false;
    try adjustRegMandatoryBits(
        ppb_exec_ctrl,
        if (basic_msr.true_control) am.readMsr(.vmx_true_procbased_ctls) else am.readMsr(.vmx_procbased_ctls),
    ).load();

    // Init I/O bitmap
    vcpu.io_bitmap = try vmx.IoBitmap.new(allocator);
    for (0x40..0x48) |port| {
        vcpu.io_bitmap.set(@intCast(port), false);
    }

    // Secondary Processor-based VM-Execution control.
    var ppb_exec_ctrl2 = try vmcs.SecondaryProcExecCtrl.store();
    ppb_exec_ctrl2.ept = true;
    ppb_exec_ctrl2.unrestricted_guest = true; // This control must be enabled to allow real-mode or non-paging mode.
    ppb_exec_ctrl2.enable_xsaves_xrstors = true;
    ppb_exec_ctrl2.enable_invpcid = true;
    ppb_exec_ctrl2.apic_register_virtualization = true;
    ppb_exec_ctrl2.virtualize_apic_accesses = true;
    ppb_exec_ctrl2.virtualize_x2apic_mode = false;
    ppb_exec_ctrl2.virtual_interrupt_delivery = true;
    ppb_exec_ctrl2.vpid = isVpidSupported();
    try adjustRegMandatoryBits(
        ppb_exec_ctrl2,
        am.readMsr(.vmx_procbased_ctls2),
    ).load();
    try vmwrite(vmcs.ctrl.xss_exiting_bitmap, 0); // Don't exit on XSAVES/XRSTORS.

    // Exit on access to CR0/CR4.
    try vmwrite(vmcs.ctrl.cr0_mask, std.math.maxInt(u64));
    try vmwrite(vmcs.ctrl.cr4_mask, std.math.maxInt(u64));
    try vmwrite(vmcs.ctrl.cr3_target_count, 0);

    // Exception bitmap
    var exception_bitmap: u32 = 0;
    exception_bitmap |= 1 << 13; // General protection fault
    try vmwrite(vmcs.ctrl.exception_bitmap, exception_bitmap);

    // VPID
    if (isVpidSupported()) {
        log.debug("INVVPID is supported.", .{});
        try vmwrite(vmcs.ctrl.vpid, vcpu.vpid);
    } else {
        log.err("INVVPID is not supported.", .{});
    }
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
    exit_ctrl.load_ia32_pat = true;
    exit_ctrl.save_ia32_pat = true;
    exit_ctrl.ack_interrupt_onexit = false; // Ymir wants to handle interrupt by herself.
    try adjustRegMandatoryBits(
        exit_ctrl,
        if (basic_msr.true_control) am.readMsr(.vmx_true_exit_ctls) else am.readMsr(.vmx_exit_ctls),
    ).load();

    try vmwrite(vmcs.ctrl.vexit_msr_load_count, 0);
    try vmwrite(vmcs.ctrl.exit_msr_store_count, 0);
}

/// Set up VM-Entry control fields.
/// cf. SDM Vol.3C 27.2.1.3.
fn setupEntryCtrls(_: *Vcpu) VmxError!void {
    const basic_msr = am.readMsrVmxBasic();

    // VM-Entry control.
    var entry_ctrl = try vmcs.EntryCtrl.store();
    entry_ctrl.ia32e_mode_guest = false;
    entry_ctrl.load_ia32_efer = true;
    entry_ctrl.load_ia32_pat = true;
    try adjustRegMandatoryBits(
        entry_ctrl,
        if (basic_msr.true_control) am.readMsr(.vmx_true_entry_ctls) else am.readMsr(.vmx_entry_ctls),
    ).load();

    try vmwrite(vmcs.ctrl.entry_msr_load_count, 0);
}

/// Set up host state.
/// cf. SDM Vol.3C 27.2.2.
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

fn setupGuestState(vcpu: *Vcpu) VmxError!void {
    // Control registers.
    var cr0 = std.mem.zeroes(am.Cr0);
    cr0.pe = true; // Protected-mode
    cr0.ne = true; // Numeric error
    cr0.et = true; // Extension type
    cr0.pg = false; // Paging
    var cr4: am.Cr4 = @bitCast(try vmread(vmcs.guest.cr4));
    cr4.pae = false;
    cr4.vmxe = true; // TODO: Should we expose this bit to guest?? (this is requirement for successful VM-entry)
    try vmwrite(vmcs.guest.cr0, cr0);
    try vmwrite(vmcs.ctrl.cr0_read_shadow, cr0);
    try vmwrite(vmcs.guest.cr4, cr4);
    try vmwrite(vmcs.ctrl.cr4_read_shadow, cr4);

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
            .long = false,
            .db = 1,
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
        try vmwrite(vmcs.guest.cs_sel, 0);
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
    try vmwrite(vmcs.guest.sysenter_cs, 0);
    try vmwrite(vmcs.guest.sysenter_esp, 0);
    try vmwrite(vmcs.guest.sysenter_eip, 0);
    try vmwrite(vmcs.guest.efer, 0);

    // General registers.
    try vmwrite(vmcs.guest.rflags, am.FlagsRegister.new());

    // Other crucial fields.
    try vmwrite(vmcs.guest.vmcs_link_pointer, std.math.maxInt(u64));
    try vmwrite(vmcs.guest.rip, linux.layout.kernel_base);
    vcpu.guest_regs.rsi = linux.layout.bootparam;
}

/// Set host stack pointer.
/// This function is called directly from assembly.
export fn setHostStack(rsp: u64) callconv(.c) void {
    vmwrite(vmcs.host.rsp, rsp) catch {};
}

/// Adjust mandatory bits of a control field.
/// Upper 32 bits of `mask` is mandatory 1, and lower 32 bits is mandatory 0.
fn adjustRegMandatoryBits(control: anytype, mask: u64) @TypeOf(control) {
    var ret: u32 = @bitCast(control);
    ret |= @as(u32, @truncate(mask)); // Mandatory 1
    ret &= @as(u32, @truncate(mask >> 32)); // Mandatory 0
    return @bitCast(ret);
}

/// Get a VM-exit qualification from VMCS.
fn getExitQual(T: anytype) VmxError!T {
    return @bitCast(@as(u64, try vmread(vmcs.ro.exit_qual)));
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
        const ptr: [*]u8 = @ptrCast(self);
        page_allocator.free(ptr[0..mem.page_size]);
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
    pub fn new(page_allocator: Allocator) VmxError!*align(4096) VmcsRegion {
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

test {
    std.testing.refAllDeclsRecursive(@This());
}
