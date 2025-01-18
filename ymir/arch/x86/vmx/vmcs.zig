const std = @import("std");

const vmx = @import("common.zig");

const VmxError = vmx.VmxError;

/// Guest state area encodings.
/// cf. SDM Vol.3C 25.4, Appendix B.
pub const guest = enum(u32) {
    // Natural-width fields.
    cr0 = eg(0, .full, .natural),
    cr3 = eg(1, .full, .natural),
    cr4 = eg(2, .full, .natural),
    es_base = eg(3, .full, .natural),
    cs_base = eg(4, .full, .natural),
    ss_base = eg(5, .full, .natural),
    ds_base = eg(6, .full, .natural),
    fs_base = eg(7, .full, .natural),
    gs_base = eg(8, .full, .natural),
    ldtr_base = eg(9, .full, .natural),
    tr_base = eg(10, .full, .natural),
    gdtr_base = eg(11, .full, .natural),
    idtr_base = eg(12, .full, .natural),
    dr7 = eg(13, .full, .natural),
    rsp = eg(14, .full, .natural),
    rip = eg(15, .full, .natural),
    rflags = eg(16, .full, .natural),
    pending_debug_exceptions = eg(17, .full, .natural),
    sysenter_esp = eg(18, .full, .natural),
    sysenter_eip = eg(19, .full, .natural),
    s_cet = eg(20, .full, .natural),
    ssp = eg(21, .full, .natural),
    intr_ssp_table_addr = eg(22, .full, .natural),
    // 16-bit fields.
    es_sel = eg(0, .full, .word),
    cs_sel = eg(1, .full, .word),
    ss_sel = eg(2, .full, .word),
    ds_sel = eg(3, .full, .word),
    fs_sel = eg(4, .full, .word),
    gs_sel = eg(5, .full, .word),
    ldtr_sel = eg(6, .full, .word),
    tr_sel = eg(7, .full, .word),
    intr_status = eg(8, .full, .word),
    pml_index = eg(9, .full, .word),
    uinv = eg(10, .full, .word),
    // 32-bit fields.
    es_limit = eg(0, .full, .dword),
    cs_limit = eg(1, .full, .dword),
    ss_limit = eg(2, .full, .dword),
    ds_limit = eg(3, .full, .dword),
    fs_limit = eg(4, .full, .dword),
    gs_limit = eg(5, .full, .dword),
    ldtr_limit = eg(6, .full, .dword),
    tr_limit = eg(7, .full, .dword),
    gdtr_limit = eg(8, .full, .dword),
    idtr_limit = eg(9, .full, .dword),
    es_rights = eg(10, .full, .dword),
    cs_rights = eg(11, .full, .dword),
    ss_rights = eg(12, .full, .dword),
    ds_rights = eg(13, .full, .dword),
    fs_rights = eg(14, .full, .dword),
    gs_rights = eg(15, .full, .dword),
    ldtr_rights = eg(16, .full, .dword),
    tr_rights = eg(17, .full, .dword),
    interruptibility_state = eg(18, .full, .dword),
    activity_state = eg(19, .full, .dword),
    smbase = eg(20, .full, .dword),
    sysenter_cs = eg(21, .full, .dword),
    preemp_timer = eg(22, .full, .dword),
    // 64-bit fields.
    vmcs_link_pointer = eg(0, .full, .qword),
    dbgctl = eg(1, .full, .qword),
    pat = eg(2, .full, .qword),
    efer = eg(3, .full, .qword),
    perf_global_ctrl = eg(4, .full, .qword),
    pdpte0 = eg(5, .full, .qword),
    pdpte1 = eg(6, .full, .qword),
    pdpte2 = eg(7, .full, .qword),
    pdpte3 = eg(8, .full, .qword),
    bndcfgs = eg(9, .full, .qword),
    rtit_ctl = eg(10, .full, .qword),
    lbr_ctl = eg(11, .full, .qword),
    pkrs = eg(12, .full, .qword),
};

/// Host state area encodings.
/// cf. SDM Vol.3C 25.4, Appendix B.
pub const host = enum(u32) {
    // Natural-width fields.
    cr0 = eh(0, .full, .natural),
    cr3 = eh(1, .full, .natural),
    cr4 = eh(2, .full, .natural),
    fs_base = eh(3, .full, .natural),
    gs_base = eh(4, .full, .natural),
    tr_base = eh(5, .full, .natural),
    gdtr_base = eh(6, .full, .natural),
    idtr_base = eh(7, .full, .natural),
    sysenter_esp = eh(8, .full, .natural),
    sysenter_eip = eh(9, .full, .natural),
    rsp = eh(10, .full, .natural),
    rip = eh(11, .full, .natural),
    s_cet = eh(12, .full, .natural),
    ssp = eh(13, .full, .natural),
    intr_ssp_table_addr = eh(14, .full, .natural),
    // 16-bit fields.
    es_sel = eh(0, .full, .word),
    cs_sel = eh(1, .full, .word),
    ss_sel = eh(2, .full, .word),
    ds_sel = eh(3, .full, .word),
    fs_sel = eh(4, .full, .word),
    gs_sel = eh(5, .full, .word),
    tr_sel = eh(6, .full, .word),
    // 32-bit fields.
    sysenter_cs = eh(0, .full, .dword),
    // 64-bit fields.
    pat = eh(0, .full, .qword),
    efer = eh(1, .full, .qword),
    perf_global_ctrl = eh(2, .full, .qword),
    pkrs = eh(3, .full, .qword),
};

/// Control area encodings.
/// cf. SDM Vol.3C 25.4, Appendix B.
pub const ctrl = enum(u32) {
    // Natural-width fields.
    cr0_mask = ec(0, .full, .natural),
    cr4_mask = ec(1, .full, .natural),
    cr0_read_shadow = ec(2, .full, .natural),
    cr4_read_shadow = ec(3, .full, .natural),
    cr3_target0 = ec(4, .full, .natural),
    cr3_target1 = ec(5, .full, .natural),
    cr3_target2 = ec(6, .full, .natural),
    cr3_target3 = ec(7, .full, .natural),
    // 16-bit fields.
    vpid = ec(0, .full, .word),
    posted_intr_notif_vector = ec(1, .full, .word),
    eptp_index = ec(2, .full, .word),
    hlat_prefix_size = ec(3, .full, .word),
    pid_pointer_index = ec(4, .full, .word),
    // 32-bit fields.
    pin_exec_ctrl = ec(0, .full, .dword),
    proc_exec_ctrl = ec(1, .full, .dword),
    exception_bitmap = ec(2, .full, .dword),
    pf_ec_mask = ec(3, .full, .dword),
    pf_ec_match = ec(4, .full, .dword),
    cr3_target_count = ec(5, .full, .dword),
    primary_exit_ctrl = ec(6, .full, .dword),
    exit_msr_store_count = ec(7, .full, .dword),
    vexit_msr_load_count = ec(8, .full, .dword),
    entry_ctrl = ec(9, .full, .dword),
    entry_msr_load_count = ec(10, .full, .dword),
    entry_intr_info = ec(11, .full, .dword),
    entry_exception_ec = ec(12, .full, .dword),
    entry_inst_len = ec(13, .full, .dword),
    tpr_threshold = ec(14, .full, .dword),
    secondary_proc_exec_ctrl = ec(15, .full, .dword),
    ple_gap = ec(16, .full, .dword),
    ple_window = ec(17, .full, .dword),
    instruction_timeouts = ec(18, .full, .dword),
    // 64-bit fields.
    io_bitmap_a = ec(0, .full, .qword),
    io_bitmap_b = ec(1, .full, .qword),
    msr_bitmap = ec(2, .full, .qword),
    exit_msr_store_address = ec(3, .full, .qword),
    exit_msr_load_address = ec(4, .full, .qword),
    entry_msr_load_address = ec(5, .full, .qword),
    executive_vmcs_pointer = ec(6, .full, .qword),
    pml_address = ec(7, .full, .qword),
    tsc_offset = ec(8, .full, .qword),
    virtual_apic_address = ec(9, .full, .qword),
    apic_access_address = ec(10, .full, .qword),
    posted_intr_desc_addr = ec(11, .full, .qword),
    vm_function_controls = ec(12, .full, .qword),
    eptp = ec(13, .full, .qword),
    eoi_exit_bitmap0 = ec(14, .full, .qword),
    eoi_exit_bitmap1 = ec(15, .full, .qword),
    eoi_exit_bitmap2 = ec(16, .full, .qword),
    eoi_exit_bitmap3 = ec(17, .full, .qword),
    eptp_list_address = ec(18, .full, .qword),
    vmread_bitmap = ec(19, .full, .qword),
    vmwrite_bitmap = ec(20, .full, .qword),
    vexception_information_address = ec(21, .full, .qword),
    xss_exiting_bitmap = ec(22, .full, .qword),
    encls_exiting_bitmap = ec(23, .full, .qword),
    sub_page_permission_table_pointer = ec(24, .full, .qword),
    tsc_multiplier = ec(25, .full, .qword),
    tertiary_proc_exec_ctrl = ec(26, .full, .qword),
    enclv_exiting_bitmap = ec(27, .full, .qword),
    low_pasid_directory = ec(28, .full, .qword),
    high_pasid_directory = ec(29, .full, .qword),
    shared_eptp = ec(30, .full, .qword),
    pconfig_exiting_bitmap = ec(31, .full, .qword),
    hlatp = ec(32, .full, .qword),
    pid_pointer_table = ec(33, .full, .qword),
    secondary_exit_ctrl = ec(34, .full, .qword),
    spec_ctrl_mask = ec(37, .full, .qword),
    spec_ctrl_shadow = ec(38, .full, .qword),
};

/// Read-only area encodings.
/// cf. SDM Vol.3C 25.4, Appendix B.
pub const ro = enum(u32) {
    // Natural-width fields.
    exit_qual = er(0, .full, .natural),
    io_rcx = er(1, .full, .natural),
    io_rsi = er(2, .full, .natural),
    io_rdi = er(3, .full, .natural),
    io_rip = er(4, .full, .natural),
    guest_linear_address = er(5, .full, .natural),
    // 32-bit fields.
    vminstruction_error = er(0, .full, .dword),
    vmexit_reason = er(1, .full, .dword),
    exit_intr_info = er(2, .full, .dword),
    exit_intr_ec = er(3, .full, .dword),
    idt_vectoring_info = er(4, .full, .dword),
    idt_vectoring_ec = er(5, .full, .dword),
    exit_inst_len = er(6, .full, .dword),
    exit_inst_info = er(7, .full, .dword),
    // 64-bit fields.
    guest_physical_address = er(0, .full, .qword),
};

/// Encodes a VMCS field.
fn encode(
    comptime field_type: FieldType,
    comptime index: u9,
    comptime access_type: AccessType,
    comptime width: Width,
) u32 {
    return @bitCast(ComponentEncoding{
        .access_type = access_type,
        .index = index,
        .field_type = field_type,
        .width = width,
    });
}

/// Encodes a VMCS field for guest state area.
fn eg(
    comptime index: u9,
    comptime access_type: AccessType,
    comptime width: Width,
) u32 {
    return encode(.guest_state, index, access_type, width);
}

/// Encodes a VMCS field for host state area.
fn eh(
    comptime index: u9,
    comptime access_type: AccessType,
    comptime width: Width,
) u32 {
    return encode(.host_state, index, access_type, width);
}

/// Encodes a VMCS field for control area.
fn ec(
    comptime index: u9,
    comptime access_type: AccessType,
    comptime width: Width,
) u32 {
    return encode(.control, index, access_type, width);
}

/// Encodes a VMCS field for read-only area.
fn er(
    comptime index: u9,
    comptime access_type: AccessType,
    comptime width: Width,
) u32 {
    return encode(.vmexit, index, access_type, width);
}

/// Access type for VMCS fields.
/// cf. SDM Vol.3C 25.11.2
const AccessType = enum(u1) {
    /// Full access.
    /// Must use this for 8, 16, 32 bit fields.
    full = 0,
    /// High 32 bits of a 64-bit field.
    high = 1,
};

/// Access width for VMCS fields.
/// cf. SDM Vol.3C 25.11.2
const Width = enum(u2) {
    /// 16-bit
    word = 0,
    /// 64-bit
    qword = 1,
    /// 32-bit
    dword = 2,
    /// Natural width
    /// 64-bit on processors that support Intel 64 architecture.
    natural = 3,
};

/// Type of VMCS field.
/// cf. SDM Vol.3C 25.11.2
const FieldType = enum(u2) {
    control = 0,
    vmexit = 1,
    guest_state = 2,
    host_state = 3,
};

/// Structure of VMCS component encoding.
/// cf. SDM Vol.3C Table 25-21.
const ComponentEncoding = packed struct(u32) {
    access_type: AccessType,
    index: u9,
    field_type: FieldType,
    _reserved1: u1 = 0,
    width: Width,
    _reserved2: u17 = 0,
};

/// Pin-Based VM-Execution Controls.
/// Governs the handling of asynchronous events (e.g., interrupts).
/// cf: SDM Vol3C 25.6.
pub const PinExecCtrl = packed struct(u32) {
    const Self = @This();

    /// If set to true, external interrupts cause VM exits.
    /// If set to false, they're delivered normally through the guest IDT.
    external_interrupt: bool,
    /// Reserved.
    /// You MUST consult IA32_VMX_PINBASED_CTLS and IA32_VMX_TRUE_PINBASED_CTLS
    /// to determine how to set reserved bits.
    _reserved1: u2,
    /// If set to true, NMIs cause VM exits.
    nmi: bool,
    /// Reserved.
    /// You MUST consult IA32_VMX_PINBASED_CTLS and IA32_VMX_TRUE_PINBASED_CTLS
    /// to determine how to set reserved bits.
    _reserved2: u1,
    /// If set to true, NMIs are never blocked.
    virtual_nmi: bool,
    /// If set to true, the VMX-preemption timer counts down in VMX non-root operation.
    /// When the timer counts down to zero, a VM exit occurs.
    activate_vmx_preemption_timer: bool,
    /// If set to true, the processor treats interrupts with the posted-interrupt notificatin vector.
    process_posted_interrupts: bool,
    /// Reserved.
    /// You MUST consult IA32_VMX_PINBASED_CTLS and IA32_VMX_TRUE_PINBASED_CTLS
    /// to determine how to set reserved bits.
    _reserved3: u24,

    pub fn new() Self {
        return std.mem.zeroes(Self);
    }

    pub fn load(self: PinExecCtrl) VmxError!void {
        const val: u32 = @bitCast(self);
        try vmx.vmwrite(ctrl.pin_exec_ctrl, val);
    }

    pub fn store() VmxError!Self {
        const val: u32 = @truncate(try vmx.vmread(ctrl.pin_exec_ctrl));
        return @bitCast(val);
    }
};

/// Primary processor-based VM-execution controls.
/// Governs the handling of synchronous events (e.g., instructions).
/// cf. SDM Vol3C 25.6.2.
pub const PrimaryProcExecCtrl = packed struct(u32) {
    const Self = @This();

    /// Reserved.
    /// You MUST consult IA32_VMX_PROCBASED_CTLS and IA32_VMX_TRUE_PROCBASED_CTLS
    /// to determine how to set reserved bits.
    _reserved1: u2,
    /// VM-Exit at the beginning of any instruction if RFLAGS.IF = 1 and there're no blocking of interrupts.
    interrupt_window: bool,
    /// If set to true, RDTSC/RDTSCP/RDMSR that read from IA32_TIME_STAMP_COUNTER_MSR
    /// return a value modified by the TSC offset field.
    tsc_offsetting: bool,
    /// Reserved.
    _reserved2: u3,
    /// HLT
    hlt: bool,
    /// Reserved.
    _reserved3: u1,
    /// INVLPG
    invlpg: bool,
    /// MWAIT
    mwait: bool,
    /// RDPMC
    rdpmc: bool,
    /// RDTSC / RDTSCP
    rdtsc: bool,
    /// Reserved.
    _reserved4: u2,
    /// MOV to CR3 in conjuction with CR3-target controls.
    cr3load: bool,
    /// MOV from CR3.
    cr3store: bool,
    /// If set to false, the logical processor operates as if all the teritary processor-based VM-execution controls were also 0.
    activate_teritary_controls: bool,
    /// Reserved.
    _reserved: u1,
    /// MOV to CR8.
    cr8load: bool,
    /// MOV from CR8.
    cr8store: bool,
    /// If set to true, TPR virtualization and other APIC-virtualization features are enabled.
    use_tpr_shadow: bool,
    /// If set to true, VM-exit at the beginning of any instruction if there's no virtual-NMI blocking.
    nmi_window: bool,
    /// MOV DR
    mov_dr: bool,
    /// I/O instructions
    unconditional_io: bool,
    /// If set to true, I/O bitmaps are used to control I/O access.
    /// If set to true, unconditional_io bit is ignored.
    use_io_bitmap: bool,
    /// Reserved.
    _reserved5: u1,
    /// If set to true, monitor trap flag debugging feature is enabled.
    monitor_trap: bool,
    /// If set to true, MSR bitmaps are used to control MSR access.
    /// If set to false, all executions of RDMSR / WRMSR cause VM exits.
    use_msr_bitmap: bool,
    /// MONITOR
    monitor: bool,
    /// PAUSE
    pause: bool,
    /// If set to true, secondary processor-based VM-execution controls are used.
    activate_secondary_controls: bool,

    pub fn new() Self {
        return std.mem.zeroes(Self);
    }

    pub fn load(self: Self) VmxError!void {
        const val: u32 = @bitCast(self);
        try vmx.vmwrite(ctrl.proc_exec_ctrl, val);
    }

    pub fn store() VmxError!Self {
        const val: u32 = @truncate(try vmx.vmread(ctrl.proc_exec_ctrl));
        return @bitCast(val);
    }
};

/// Secondary processor-based VM-execution controls.
/// Governs the handling of synchronous events (e.g., instructions).
/// cf. SDM Vol3C 25.6.2.
pub const SecondaryProcExecCtrl = packed struct(u32) {
    const Self = @This();

    /// If set to true, the logical processor treats specially accesses to the page with APIC access address.
    virtualize_apic_accesses: bool,
    /// If set to true, EPT is enabled.
    ept: bool,
    /// LGDT / LIDT / LLDT / LTR / SGDT / SIDT / SLDT / STR
    descriptor_table: bool,
    /// RDTSCP (#UD)
    rdtscp: bool,
    /// If set to true, the logical processor treats specially RDMSR/WRMSR to APIC MSRs.
    virtualize_x2apic_mode: bool,
    /// If set to true, cached translations of virtual addresses are associated with VPID.
    vpid: bool,
    /// WBINVD / NBNOINVD
    wbinvd: bool,
    /// Determines whether guest may run in unpaged protected mode or in real address mode.
    unrestricted_guest: bool,
    /// If set to true, certain APIC accesses are virtualized.
    apic_register_virtualization: bool,
    /// If set to true, it enables the evaluation and delivery of pending virtual interrupts.
    virtual_interrupt_delivery: bool,
    /// Series of PAUSE
    pause_loop: bool,
    /// RDRAND
    rdrand: bool,
    /// If set to false, INVPCID causes #UD.
    enable_invpcid: bool,
    /// Enable VMFUNC.
    enable_vmfunc: bool,
    /// If set to true, VMREAD / VMWRITE in VMX non-root may access a shadow VMCS.
    vmcs_shadowing: bool,
    /// If set to true, ENCLS causes VM exits depending on ENCLS-exiting bitmap.
    enable_encls: bool,
    /// RDSEED.
    rdseed: bool,
    /// If set to true, first access to GPA that sets EPT dirty bit adds an entry to the page-modification log.
    enable_pml: bool,
    /// If set to true, EPT violations cause #VE instead of VM exits.
    ept_violation: bool,
    ///
    conceal_vmx_from_pt: bool,
    /// If set to false, XSAVES or XRSTORS cause #UD.
    enable_xsaves_xrstors: bool,
    /// If set to true, PASID translation is performed for executions of ENQCMD / ENQCMDS.
    pasid_translation: bool,
    /// If set to true, EPT permissions are based on if whether the accessed VA is supervisor/user mode.
    mode_based_control_ept: bool,
    /// If set to true, EPT write permissions are specified at the granualrity of 128 bytes.
    subpage_write_eptr: bool,
    ///
    pt_guest_pa: bool,
    /// Determines whether RDTSC / RDTSCP / RDMSR that read from IA32_TIME_STAMP_COUNTER MSR
    /// return a value modified by the TSC multiplier field.
    tsc_scaling: bool,
    /// If set to false, TPAUSE / UMONITOR / UMWAIT cause #UD.
    enable_user_wait_pause: bool,
    /// PCONFIG (#UD)
    enable_pconfig: bool,
    ///
    enable_enclv: bool,
    /// Reserved.
    /// You MUST consult IA32_VMX_PROCBASED_CTLS2 to determine how to set reserved bits.
    _reserved1: u1,
    /// Determines whether assertion of a bus lock cause VM exits.
    vmm_buslock_detect: bool,
    ///
    instruction_timeout: bool,

    pub fn new() Self {
        return std.mem.zeroes(Self);
    }

    pub fn load(self: Self) VmxError!void {
        const val: u32 = @bitCast(self);
        try vmx.vmwrite(ctrl.secondary_proc_exec_ctrl, val);
    }

    pub fn store() VmxError!Self {
        const val: u32 = @truncate(try vmx.vmread(ctrl.secondary_proc_exec_ctrl));
        return @bitCast(val);
    }
};

/// Governs the handling of exceptions.
/// If the gorresponding bit is set to true, the exception causes a VM exit.
/// Otherwise, the exception is delivered normally to the guest.
/// Page faults are judged by this bitmap
/// in addition to two more VMCS fields: pagefault_error_code_mask and pagefault_error_code_match.
/// cf. SDM Vol3C 25.6.3.
pub const ExceptionBitmap = packed struct(u32) {
    divide_by_zero: bool,
    debug: bool,
    non_maskable_interrupt: bool,
    breakpoint: bool,
    overflow: bool,
    bound_range_exceeded: bool,
    invalid_opcode: bool,
    device_not_available: bool,
    double_fault: bool,
    coprocessor_segment_overrun: bool,
    invalid_tss: bool,
    segment_not_present: bool,
    stack_segment_fault: bool,
    general_protection_fault: bool,
    page_fault: bool,
    floating_point_exception: bool,
    alignment_check: bool,
    machine_check: bool,
    simd_exception: bool,
    virtualization_exception: bool,
    control_protection_excepton: bool,
    _reserved: u11,
};

/// Primary VM-Exit Controls.
pub const PrimaryExitCtrl = packed struct(u32) {
    const Self = @This();

    /// Reserved.
    /// You MUST consult IA32_VMX_EXIT_CTLS and IA32_VMX_TRUE_EXIT_CTLS
    /// to determine how to set reserved bits.
    _reserved1: u2,
    /// If set to true, DR7 and IA32_DEBUGCTL MSR are saved on VM exit.
    save_debug: bool,
    /// Reserved.
    _reserved2: u6,
    /// If set to true, a processor is in 64-bit mode after the next VM exit.
    /// Its value is loaded into CS.L, IA32_EFER.LME, and IA32_EFER.LMA on every VM exit.
    host_addr_space_size: bool,
    /// Reserved.
    _reserved3: u2,
    /// If set to true, IA32_PERF_GLOBAL_CTRL MSR is loaded on VM exit.
    load_perf_global_ctrl: bool,
    /// Reserved.
    _reserved4: u2,
    /// If set to true, the logical processor acks the interrupt controller and acquires the vector.
    ack_interrupt_onexit: bool,
    /// Reserved.
    _reserved5: u2,
    /// If set to true, IA32_PAT_MSR is saved on VM exit.
    save_ia32_pat: bool,
    /// If set to true, IA32_PAT MSR is loaded on VM entry.
    load_ia32_pat: bool,
    /// If set to true, IA32_EFER MSR is saved on VM exit.
    save_ia32_efer: bool,
    /// If set to true, IA32_EFER MSR is loaded on VM entry.
    load_ia32_efer: bool,
    /// If set to true, the value of VMX-preemption timer is saved on VM exit.
    save_vmx_preemption_timer: bool,
    /// If set to true, IA32_BNDCFGS MSR is cleared on VM exit.
    clear_ia32_bndcfgs: bool,
    ///
    conceal_vmx_from_pt: bool,
    ///
    clear_ia32_rtit_ctl: bool,
    ///
    clear_ia32_lbr_ctl: bool,
    /// If set to true, UINV is cleared on VM exit.
    clear_uinv: bool,
    /// If set to true, CET-related MSRs and SSP are loaded on VM entry.
    load_cet_state: bool,
    /// If set to true, IA32_PKRS MSR is loaded on VM entry.
    load_pkrs: bool,
    /// If set to true, IA32_PERF_GLOBAL_CTL MSR is saved on VM exit.
    save_perf_global_ctl: bool,
    /// If set to true, the secondary VM-exit controls are used.
    activate_secondary_controls: bool,

    pub fn new() Self {
        return std.mem.zeroes(Self);
    }

    pub fn load(self: Self) VmxError!void {
        const val: u32 = @bitCast(self);
        try vmx.vmwrite(ctrl.primary_exit_ctrl, val);
    }

    pub fn store() VmxError!Self {
        const val: u32 = @truncate(try vmx.vmread(ctrl.primary_exit_ctrl));
        return @bitCast(val);
    }
};

/// Secondary VM-Exit Controls.
pub const SecondaryExitCtrl = packed struct(u64) {
    const Self = @This();

    /// Reserved.
    /// You MUST consult IA32_VMX_EXIT_CTLS2 to determine how to set reserved bits.
    _reserved1: u3,
    ///
    prematurely_busy_shadow_stack: bool,
    /// Reserved.
    _reserved2: u60,

    pub fn new() Self {
        return std.mem.zeroes(Self);
    }
};

/// VM-Entry Controls.
pub const EntryCtrl = packed struct(u32) {
    pub const Self = @This();

    /// Reserved.
    /// You MUST consult IA32_VMX_ENTRY_CTLS and IA32_VMX_TRUE_ENTRY_CTLS
    /// to determine how to set reserved bits.
    _reserved1: u2,
    /// Whether DR7 and IA32_DEBUGCTL MSR are loaded on VM entry.
    load_debug_controls: bool,
    /// Reserved.
    _reserved2: u6,
    /// Whether the logical processor is in IA-32e mode after VM entry.
    ia32e_mode_guest: bool,
    /// Whether the logical processor is in SMM after VM entry.
    entry_smm: bool,
    ///
    deactivate_dualmonitor: bool,
    /// Reserved.
    _reserved3: u1,
    /// Whether IA32_PERF_GLOBAL_CTRL MSR is loaded on VM entry.
    load_perf_global_ctrl: bool,
    /// Whether IA32_PAT MSR is loaded on VM entry.
    load_ia32_pat: bool,
    /// Whether IA32_EFER MSR is loaded on VM entry.
    load_ia32_efer: bool,
    /// Whether IA32_BNDCFGS MSR is loaded on VM entry.
    load_ia32_bndcfgs: bool,
    ///
    conceal_vmx_from_pt: bool,
    ///
    load_rtit_ctl: bool,
    /// Whether UINV is loaded on VM entry.
    load_uinv: bool,
    /// Whether CET-related MSRs and SSP are loaded on VM entry.
    load_cet_state: bool,
    /// Whether IA32_LBR_CTL MSR is loaded on VM entry.
    load_guest_lbr_ctl: bool,
    /// Whether IA32_PKRS MSR is loaded on VM entry.
    load_pkrs: bool,
    /// Reserved.
    _reserved4: u9,

    pub fn new() Self {
        return std.mem.zeroes(Self);
    }

    pub fn load(self: Self) VmxError!void {
        const val: u32 = @bitCast(self);
        try vmx.vmwrite(ctrl.entry_ctrl, val);
    }

    pub fn store() VmxError!Self {
        const val: u32 = @truncate(try vmx.vmread(ctrl.entry_ctrl));
        return @bitCast(val);
    }
};
