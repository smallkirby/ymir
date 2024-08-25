const std = @import("std");

const am = @import("../asm.zig");
const vmx = @import("../vmx.zig");
const vmcs = @import("vmcs.zig");
const VmxError = vmx.VmxError;
const err = vmx.vmxtry;

/// VMREAD.
/// `field` is a encoded VMCS field.
/// If the operation succeeds, the value of the field is returned.
/// Regardless of the field length, this function returns a 64-bit value.
/// If the operation fails, an error is returned.
pub fn vmread(field: anytype) VmxError!u64 {
    var rflags: u64 = undefined;
    const ret = asm volatile (
        \\vmread %[field], %[ret]
        \\pushf
        \\popq %[rflags]
        : [ret] "={rax}" (-> u64),
          [rflags] "=r" (rflags),
        : [field] "r" (@as(u64, @intFromEnum(field))),
    );
    try err(rflags);
    return ret;
}

/// VMWRITE.
/// `field` is a encoded VMCS field.
/// `value` is a value to write to the field.
/// `value` can be either of the following types:
///     - integer (including comptime value)
///     - pointer
///     - structure (up to 8 bytes)
/// `value` is automatically casted to an appropriate-width integer.
/// If the operation fails, an error is returned.
pub fn vmwrite(field: anytype, value: anytype) VmxError!void {
    const value_int = switch (@typeInfo(@TypeOf(value))) {
        .Int, .ComptimeInt => @as(u64, value),
        .Struct => switch (@sizeOf(@TypeOf(value))) {
            1 => @as(u8, @bitCast(value)),
            2 => @as(u16, @bitCast(value)),
            4 => @as(u32, @bitCast(value)),
            8 => @as(u64, @bitCast(value)),
            else => @compileError("Unsupported structure size for vmwrite"),
        },
        .Pointer => @as(u64, @intFromPtr(value)),
        else => @compileError("Unsupported type for vmwrite"),
    };

    const rflags = asm volatile (
        \\vmwrite %[value], %[field]
        \\pushf
        \\popq %[rflags]
        : [rflags] "=r" (-> u64),
        : [field] "r" (@as(u64, @intFromEnum(field))),
          [value] "r" (@as(u64, value_int)),
    );
    try err(rflags);
}

/// Guest state area encodings.
/// cf. SDM Vol.3C 25.4, Appendix B.
pub const Guest = enum(u32) {
    // Natural-width fields.
    cr0 = encode(.guest_state, 0, .full, .natural),
    cr3 = encode(.guest_state, 1, .full, .natural),
    cr4 = encode(.guest_state, 2, .full, .natural),
    es_base = encode(.guest_state, 3, .full, .natural),
    cs_base = encode(.guest_state, 4, .full, .natural),
    ss_base = encode(.guest_state, 5, .full, .natural),
    ds_base = encode(.guest_state, 6, .full, .natural),
    fs_base = encode(.guest_state, 7, .full, .natural),
    gs_base = encode(.guest_state, 8, .full, .natural),
    ldtr_base = encode(.guest_state, 9, .full, .natural),
    tr_base = encode(.guest_state, 10, .full, .natural),
    gdtr_base = encode(.guest_state, 11, .full, .natural),
    idtr_base = encode(.guest_state, 12, .full, .natural),
    dr7 = encode(.guest_state, 13, .full, .natural),
    rsp = encode(.guest_state, 14, .full, .natural),
    rip = encode(.guest_state, 15, .full, .natural),
    rflags = encode(.guest_state, 16, .full, .natural),
    pending_debug_exceptions = encode(.guest_state, 17, .full, .natural),
    sysenter_esp = encode(.guest_state, 18, .full, .natural),
    sysenter_eip = encode(.guest_state, 19, .full, .natural),
    s_cet = encode(.guest_state, 20, .full, .natural),
    ssp = encode(.guest_state, 21, .full, .natural),
    interrupt_ssp_table_addr = encode(.guest_state, 22, .full, .natural),
    // 16-bit fields.
    es_sel = encode(.guest_state, 0, .full, .word),
    cs_sel = encode(.guest_state, 1, .full, .word),
    ss_sel = encode(.guest_state, 2, .full, .word),
    ds_sel = encode(.guest_state, 3, .full, .word),
    fs_sel = encode(.guest_state, 4, .full, .word),
    gs_sel = encode(.guest_state, 5, .full, .word),
    ldtr_sel = encode(.guest_state, 6, .full, .word),
    tr_sel = encode(.guest_state, 7, .full, .word),
    interrupt_status = encode(.guest_state, 8, .full, .word),
    pml_index = encode(.guest_state, 9, .full, .word),
    uinv = encode(.guest_state, 10, .full, .word),
    // 32-bit fields.
    es_limit = encode(.guest_state, 0, .full, .dword),
    cs_limit = encode(.guest_state, 1, .full, .dword),
    ss_limit = encode(.guest_state, 2, .full, .dword),
    ds_limit = encode(.guest_state, 3, .full, .dword),
    fs_limit = encode(.guest_state, 4, .full, .dword),
    gs_limit = encode(.guest_state, 5, .full, .dword),
    ldtr_limit = encode(.guest_state, 6, .full, .dword),
    tr_limit = encode(.guest_state, 7, .full, .dword),
    gdtr_limit = encode(.guest_state, 8, .full, .dword),
    idtr_limit = encode(.guest_state, 9, .full, .dword),
    es_rights = encode(.guest_state, 10, .full, .dword),
    cs_rights = encode(.guest_state, 11, .full, .dword),
    ss_rights = encode(.guest_state, 12, .full, .dword),
    ds_rights = encode(.guest_state, 13, .full, .dword),
    fs_rights = encode(.guest_state, 14, .full, .dword),
    gs_rights = encode(.guest_state, 15, .full, .dword),
    ldtr_rights = encode(.guest_state, 16, .full, .dword),
    tr_rights = encode(.guest_state, 17, .full, .dword),
    interruptibility_state = encode(.guest_state, 18, .full, .dword),
    activity_state = encode(.guest_state, 19, .full, .dword),
    smbase = encode(.guest_state, 20, .full, .dword),
    sysenter_cs = encode(.guest_state, 21, .full, .dword),
    preemp_timer = encode(.guest_state, 22, .full, .dword),
    // 64-bit fields.
    vmcs_link_pointer = encode(.guest_state, 0, .full, .qword),
    dbgctl = encode(.guest_state, 1, .full, .qword),
    pat = encode(.guest_state, 2, .full, .qword),
    efer = encode(.guest_state, 3, .full, .qword),
    perf_global_ctrl = encode(.guest_state, 4, .full, .qword),
    pdpte0 = encode(.guest_state, 5, .full, .qword),
    pdpte1 = encode(.guest_state, 6, .full, .qword),
    pdpte2 = encode(.guest_state, 7, .full, .qword),
    pdpte3 = encode(.guest_state, 8, .full, .qword),
    bndcfgs = encode(.guest_state, 9, .full, .qword),
    rtit_ctl = encode(.guest_state, 10, .full, .qword),
    lbr_ctl = encode(.guest_state, 11, .full, .qword),
    pkrs = encode(.guest_state, 12, .full, .qword),
};

/// Host state area encodings.
/// cf. SDM Vol.3C 25.4, Appendix B.
pub const Host = enum(u32) {
    // Natural-width fields.
    cr0 = encode(.host_state, 0, .full, .natural),
    cr3 = encode(.host_state, 1, .full, .natural),
    cr4 = encode(.host_state, 2, .full, .natural),
    fs_base = encode(.host_state, 3, .full, .natural),
    gs_base = encode(.host_state, 4, .full, .natural),
    tr_base = encode(.host_state, 5, .full, .natural),
    gdtr_base = encode(.host_state, 6, .full, .natural),
    idtr_base = encode(.host_state, 7, .full, .natural),
    sysenter_esp = encode(.host_state, 8, .full, .natural),
    sysenter_eip = encode(.host_state, 9, .full, .natural),
    rsp = encode(.host_state, 10, .full, .natural),
    rip = encode(.host_state, 11, .full, .natural),
    s_cet = encode(.host_state, 12, .full, .natural),
    ssp = encode(.host_state, 13, .full, .natural),
    interrupt_ssp_table_addr = encode(.host_state, 14, .full, .natural),
    // 16-bit fields.
    es_sel = encode(.host_state, 0, .full, .word),
    cs_sel = encode(.host_state, 1, .full, .word),
    ss_sel = encode(.host_state, 2, .full, .word),
    ds_sel = encode(.host_state, 3, .full, .word),
    fs_sel = encode(.host_state, 4, .full, .word),
    gs_sel = encode(.host_state, 5, .full, .word),
    tr_sel = encode(.host_state, 6, .full, .word),
    // 32-bit fields.
    sysenter_cs = encode(.host_state, 0, .full, .dword),
    // 64-bit fields.
    pat = encode(.host_state, 0, .full, .qword),
    efer = encode(.host_state, 1, .full, .qword),
    perf_global_ctrl = encode(.host_state, 2, .full, .qword),
    pkrs = encode(.host_state, 3, .full, .qword),
};

/// Control area encodings.
/// cf. SDM Vol.3C 25.4, Appendix B.
pub const Ctrl = enum(u32) {
    // Natural-width fields.
    cr0_mask = encode(.control, 0, .full, .natural),
    cr4_mask = encode(.control, 1, .full, .natural),
    cr0_read_shadow = encode(.control, 2, .full, .natural),
    cr4_read_shadow = encode(.control, 3, .full, .natural),
    cr3_target0 = encode(.control, 4, .full, .natural),
    cr3_target1 = encode(.control, 5, .full, .natural),
    cr3_target2 = encode(.control, 6, .full, .natural),
    cr3_target3 = encode(.control, 7, .full, .natural),
    // 16-bit fields.
    vpid = encode(.control, 0, .full, .word),
    posted_interrupt_notification_vector = encode(.control, 1, .full, .word),
    eptp_index = encode(.control, 2, .full, .word),
    hlat_prefix_size = encode(.control, 3, .full, .word),
    pid_pointer_index = encode(.control, 4, .full, .word),
    // 32-bit fields.
    pinbased_vmexec_controls = encode(.control, 0, .full, .dword),
    procbased_vmexec_controls = encode(.control, 1, .full, .dword),
    exception_bitmap = encode(.control, 2, .full, .dword),
    pagefault_error_code_mask = encode(.control, 3, .full, .dword),
    pagefault_error_code_match = encode(.control, 4, .full, .dword),
    cr3_target_count = encode(.control, 5, .full, .dword),
    primary_vmexit_controls = encode(.control, 6, .full, .dword),
    vmexit_msr_store_count = encode(.control, 7, .full, .dword),
    vmexit_msr_load_count = encode(.control, 8, .full, .dword),
    vmentry_controls = encode(.control, 9, .full, .dword),
    vmentry_msr_load_count = encode(.control, 10, .full, .dword),
    vmentry_interrupt_information_field = encode(.control, 11, .full, .dword),
    vmentry_exception_error_code = encode(.control, 12, .full, .dword),
    vmentry_instruction_length = encode(.control, 13, .full, .dword),
    tpr_threshold = encode(.control, 14, .full, .dword),
    secondary_procbased_vmexec_controls = encode(.control, 15, .full, .dword),
    ple_gap = encode(.control, 16, .full, .dword),
    ple_window = encode(.control, 17, .full, .dword),
    instruction_timeouts = encode(.control, 18, .full, .dword),
    // 64-bit fields.
    io_bitmap_a = encode(.control, 0, .full, .qword),
    io_bitmap_b = encode(.control, 1, .full, .qword),
    msr_bitmap = encode(.control, 2, .full, .qword),
    vmexit_msr_store_address = encode(.control, 3, .full, .qword),
    vmexit_msr_load_address = encode(.control, 4, .full, .qword),
    vmentry_msr_load_address = encode(.control, 5, .full, .qword),
    executive_vmcs_pointer = encode(.control, 6, .full, .qword),
    pml_address = encode(.control, 7, .full, .qword),
    tsc_offset = encode(.control, 8, .full, .qword),
    virtual_apic_address = encode(.control, 9, .full, .qword),
    apic_access_address = encode(.control, 10, .full, .qword),
    posted_interrupt_descriptor_address = encode(.control, 11, .full, .qword),
    vm_function_controls = encode(.control, 12, .full, .qword),
    eptp = encode(.control, 13, .full, .qword),
    eoi_exit_bitmap0 = encode(.control, 14, .full, .qword),
    eoi_exit_bitmap1 = encode(.control, 15, .full, .qword),
    eoi_exit_bitmap2 = encode(.control, 16, .full, .qword),
    eoi_exit_bitmap3 = encode(.control, 17, .full, .qword),
    eptp_list_address = encode(.control, 18, .full, .qword),
    vmread_bitmap = encode(.control, 19, .full, .qword),
    vmwrite_bitmap = encode(.control, 20, .full, .qword),
    vexception_information_address = encode(.control, 21, .full, .qword),
    xss_exiting_bitmap = encode(.control, 22, .full, .qword),
    encls_exiting_bitmap = encode(.control, 23, .full, .qword),
    sub_page_permission_table_pointer = encode(.control, 24, .full, .qword),
    tsc_multiplier = encode(.control, 25, .full, .qword),
    tertiary_processor_based_vmexec_controls = encode(.control, 26, .full, .qword),
    enclv_exiting_bitmap = encode(.control, 27, .full, .qword),
    low_pasid_directory = encode(.control, 28, .full, .qword),
    high_pasid_directory = encode(.control, 29, .full, .qword),
    shared_eptp = encode(.control, 30, .full, .qword),
    pconfig_exiting_bitmap = encode(.control, 31, .full, .qword),
    hlatp = encode(.control, 32, .full, .qword),
    pid_pointer_table = encode(.control, 33, .full, .qword),
    secondary_vmexit_controls = encode(.control, 34, .full, .qword),
    spec_ctrl_mask = encode(.control, 37, .full, .qword),
    spec_ctrl_shadow = encode(.control, 38, .full, .qword),
};

/// Read-only area encodings.
/// cf. SDM Vol.3C 25.4, Appendix B.
pub const Ro = enum(u32) {
    // Natural-width fields.
    exit_qual = encode(.vmexit, 0, .full, .natural),
    io_rcx = encode(.vmexit, 1, .full, .natural),
    io_rsi = encode(.vmexit, 2, .full, .natural),
    io_rdi = encode(.vmexit, 3, .full, .natural),
    io_rip = encode(.vmexit, 4, .full, .natural),
    guest_linear_address = encode(.vmexit, 5, .full, .natural),
    // 32-bit fields.
    vminstruction_error = encode(.vmexit, 0, .full, .dword),
    vmexit_reason = encode(.vmexit, 1, .full, .dword),
    vmexit_interruption_information = encode(.vmexit, 2, .full, .dword),
    vmexit_interruption_error_code = encode(.vmexit, 3, .full, .dword),
    idt_vectoring_information = encode(.vmexit, 4, .full, .dword),
    idt_vectoring_error_code = encode(.vmexit, 5, .full, .dword),
    vmexit_instruction_length = encode(.vmexit, 6, .full, .dword),
    vmexit_instruction_information = encode(.vmexit, 7, .full, .dword),
    // 64-bit fields.
    guest_physical_address = encode(.vmexit, 0, .full, .qword),
};

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

/// VM-Execution Control Fields.
/// cf: SDM Vol3C 25.6.
pub const exec_control = struct {
    /// Pin-Based VM-Execution Controls.
    /// Governs the handling of asynchronous events (e.g., interrupts).
    pub const PinBasedExecutionControl = packed struct(u32) {
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

        pub fn new() PinBasedExecutionControl {
            return std.mem.zeroes(PinBasedExecutionControl);
        }

        pub fn load(self: PinBasedExecutionControl) VmxError!void {
            const val: u32 = @bitCast(self);
            try vmcs.vmwrite(vmcs.Ctrl.pinbased_vmexec_controls, val);
        }

        pub fn get() VmxError!PinBasedExecutionControl {
            const val: u32 = @truncate(try vmcs.vmread(vmcs.Ctrl.pinbased_vmexec_controls));
            return @bitCast(val);
        }
    };

    /// Primary processor-based VM-execution controls.
    /// Governs the handling of synchronous events (e.g., instructions).
    /// cf. SDM Vol3C 25.6.2.
    pub const PrimaryProcessorBasedExecutionControl = packed struct(u32) {
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

        pub fn new() PrimaryProcessorBasedExecutionControl {
            return std.mem.zeroes(PrimaryProcessorBasedExecutionControl);
        }

        pub fn load(self: PrimaryProcessorBasedExecutionControl) VmxError!void {
            const val: u32 = @bitCast(self);
            try vmcs.vmwrite(vmcs.Ctrl.procbased_vmexec_controls, val);
        }

        pub fn get() VmxError!PrimaryProcessorBasedExecutionControl {
            const val: u32 = @truncate(try vmcs.vmread(vmcs.Ctrl.procbased_vmexec_controls));
            return @bitCast(val);
        }
    };

    /// Secondary processor-based VM-execution controls.
    /// Governs the handling of synchronous events (e.g., instructions).
    /// cf. SDM Vol3C 25.6.2.
    pub const SecondaryProcessorBasedExecutionControl = packed struct(u32) {
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

        pub fn new() SecondaryProcessorBasedExecutionControl {
            return std.mem.zeroes(SecondaryProcessorBasedExecutionControl);
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
};

/// VM-Exit Control Fields.
/// cf: SDM Vol3C 25.7.
pub const exit_control = struct {
    /// Primary VM-Exit Controls.
    pub const PrimaryExitControls = packed struct(u32) {
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

        pub fn new() PrimaryExitControls {
            return std.mem.zeroes(PrimaryExitControls);
        }

        pub fn load(self: PrimaryExitControls) VmxError!void {
            const val: u32 = @bitCast(self);
            try vmcs.vmwrite(vmcs.Ctrl.primary_vmexit_controls, val);
        }

        pub fn get() VmxError!PrimaryExitControls {
            const val: u32 = @truncate(try vmcs.vmread(vmcs.Ctrl.primary_vmexit_controls));
            return @bitCast(val);
        }
    };

    /// Secondary VM-Exit Controls.
    pub const SecondaryExitControls = packed struct(u64) {
        /// Reserved.
        /// You MUST consult IA32_VMX_EXIT_CTLS2 to determine how to set reserved bits.
        _reserved1: u3,
        ///
        prematurely_busy_shadow_stack: bool,
        /// Reserved.
        _reserved2: u60,

        pub fn new() SecondaryExitControls {
            return std.mem.zeroes(SecondaryExitControls);
        }
    };
};

/// VM-Entry Control Fields.
/// cf: SDM Vol3C 25.8.
pub const entry_control = struct {
    /// VM-Entry Controls.
    pub const EntryControls = packed struct(u32) {
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

        pub fn new() EntryControls {
            return std.mem.zeroes(EntryControls);
        }

        pub fn load(self: EntryControls) VmxError!void {
            const val: u32 = @bitCast(self);
            try vmcs.vmwrite(vmcs.Ctrl.vmentry_controls, val);
        }

        pub fn get() VmxError!EntryControls {
            const val: u32 = @truncate(try vmcs.vmread(vmcs.Ctrl.vmentry_controls));
            return @bitCast(val);
        }
    };
};

/// Segment rights that can be set in guest-state area.
pub const SegmentRights = packed struct(u32) {
    const gdt = @import("../gdt.zig");

    /// Segment type.
    type: gdt.SegmentType,
    /// Descriptor type.
    s: gdt.DescriptorType,
    /// DPL.
    dpl: u2,
    /// Present.
    p: bool = true,
    /// Reserved.
    _reserved1: u4 = 0,
    /// AVL.
    avl: bool = false,
    /// Long mode.
    long: bool = false,
    /// D/B
    db: u1,
    /// Granularity.
    g: gdt.Granularity,
    /// Unusable.
    unusable: bool = false,
    /// Reserved.
    _reserved2: u15 = 0,
};

test {
    std.testing.refAllDeclsRecursive(@This());
}
