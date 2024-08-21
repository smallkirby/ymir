const std = @import("std");

const am = @import("../asm.zig");
const vmx = @import("../vmx.zig");
const vmcs = @import("vmcs.zig");
const VmxError = vmx.VmxError;
const err = vmx.vmxtry;

pub fn vmread(field: ComponentEncoding) VmxError!u64 {
    const field_u64: u32 = @bitCast(field);
    var rflags: u64 = undefined;
    const ret = asm volatile (
        \\vmread %[field], %[ret]
        \\pushf
        \\popq %[rflags]
        : [ret] "={rax}" (-> u64),
          [rflags] "=r" (rflags),
        : [field] "r" (@as(u64, @intCast(field_u64))),
    );
    try err(rflags);
    return ret;
}

pub fn vmwrite(field: ComponentEncoding, value: u64) VmxError!void {
    const field_u64: u32 = @bitCast(field);
    var rflags: u64 = undefined;
    asm volatile (
        \\vmwrite %[value], %[field]
        : [rflags] "=r" (rflags),
        : [field] "r" (@as(u64, @intCast(field_u64))),
          [value] "r" (value),
    );
    try err(rflags);
}

// === Guest State Area. cf. SDM Vol.3C 25.4, Appendix B. ================
// Natural-width fields.
pub const guest_cr0 = encode(.guest_state, 0, .full, .natural);
pub const guest_cr3 = encode(.guest_state, 1, .full, .natural);
pub const guest_cr4 = encode(.guest_state, 2, .full, .natural);
pub const guest_es_base = encode(.guest_state, 3, .full, .natural);
pub const guest_cs_base = encode(.guest_state, 4, .full, .natural);
pub const guest_ss_base = encode(.guest_state, 5, .full, .natural);
pub const guest_ds_base = encode(.guest_state, 6, .full, .natural);
pub const guest_fs_base = encode(.guest_state, 7, .full, .natural);
pub const guest_gs_base = encode(.guest_state, 8, .full, .natural);
pub const guest_ldtr_base = encode(.guest_state, 9, .full, .natural);
pub const guest_tr_base = encode(.guest_state, 10, .full, .natural);
pub const guest_gdtr_base = encode(.guest_state, 11, .full, .natural);
pub const guest_idtr_base = encode(.guest_state, 12, .full, .natural);
pub const guest_dr7 = encode(.guest_state, 13, .full, .natural);
pub const guest_rsp = encode(.guest_state, 14, .full, .natural);
pub const guest_rip = encode(.guest_state, 15, .full, .natural);
pub const guest_rflags = encode(.guest_state, 16, .full, .natural);
pub const guest_pending_debug_exceptions = encode(.guest_state, 17, .full, .natural);
pub const guest_sysenter_esp = encode(.guest_state, 18, .full, .natural);
pub const guest_sysenter_eip = encode(.guest_state, 19, .full, .natural);
pub const guest_s_cet = encode(.guest_state, 20, .full, .natural);
pub const guest_ssp = encode(.guest_state, 21, .full, .natural);
pub const guest_interrupt_ssp_table_addr = encode(.guest_state, 22, .full, .natural);
// 16-bit fields.
pub const guest_es_selector = encode(.guest_state, 0, .full, .word);
pub const guest_cs_selector = encode(.guest_state, 1, .full, .word);
pub const guest_ss_selector = encode(.guest_state, 2, .full, .word);
pub const guest_ds_selector = encode(.guest_state, 3, .full, .word);
pub const guest_fs_selector = encode(.guest_state, 4, .full, .word);
pub const guest_gs_selector = encode(.guest_state, 5, .full, .word);
pub const guest_ldtr_selector = encode(.guest_state, 6, .full, .word);
pub const guest_tr_selector = encode(.guest_state, 7, .full, .word);
pub const guest_interrupt_status = encode(.guest_state, 8, .full, .word);
pub const guest_pml_index = encode(.guest_state, 9, .full, .word);
pub const guest_uinv = encode(.guest_state, 10, .full, .word);
// 32-bit fields.
pub const guest_es_limit = encode(.guest_state, 0, .full, .dword);
pub const guest_cs_limit = encode(.guest_state, 1, .full, .dword);
pub const guest_ss_limit = encode(.guest_state, 2, .full, .dword);
pub const guest_ds_limit = encode(.guest_state, 3, .full, .dword);
pub const guest_fs_limit = encode(.guest_state, 4, .full, .dword);
pub const guest_gs_limit = encode(.guest_state, 5, .full, .dword);
pub const guest_ldtr_limit = encode(.guest_state, 6, .full, .dword);
pub const guest_tr_limit = encode(.guest_state, 7, .full, .dword);
pub const guest_gdtr_limit = encode(.guest_state, 8, .full, .dword);
pub const guest_idtr_limit = encode(.guest_state, 9, .full, .dword);
pub const guest_es_access_rights = encode(.guest_state, 10, .full, .dword);
pub const guest_cs_access_rights = encode(.guest_state, 11, .full, .dword);
pub const guest_ss_access_rights = encode(.guest_state, 12, .full, .dword);
pub const guest_ds_access_rights = encode(.guest_state, 13, .full, .dword);
pub const guest_fs_access_rights = encode(.guest_state, 14, .full, .dword);
pub const guest_gs_access_rights = encode(.guest_state, 15, .full, .dword);
pub const guest_ldtr_access_rights = encode(.guest_state, 16, .full, .dword);
pub const guest_tr_access_rights = encode(.guest_state, 17, .full, .dword);
pub const guest_interruptibility_state = encode(.guest_state, 18, .full, .dword);
pub const guest_activity_state = encode(.guest_state, 19, .full, .dword);
pub const guest_smbase = encode(.guest_state, 20, .full, .dword);
pub const guest_sysenter_cs = encode(.guest_state, 21, .full, .dword);
pub const guest_vmx_preemption_timer_value = encode(.guest_state, 22, .full, .dword);
// 64-bit fields.
pub const guest_vmcs_link_pointer = encode(.guest_state, 0, .full, .qword);
pub const guest_debugctl = encode(.guest_state, 1, .full, .qword);
pub const guest_pat = encode(.guest_state, 2, .full, .qword);
pub const guest_efer = encode(.guest_state, 3, .full, .qword);
pub const guest_perf_global_ctrl = encode(.guest_state, 4, .full, .qword);
pub const guest_pdpte0 = encode(.guest_state, 5, .full, .qword);
pub const guest_pdpte1 = encode(.guest_state, 6, .full, .qword);
pub const guest_pdpte2 = encode(.guest_state, 7, .full, .qword);
pub const guest_pdpte3 = encode(.guest_state, 8, .full, .qword);
pub const guest_bndcfgs = encode(.guest_state, 9, .full, .qword);
pub const guest_rtit_ctl = encode(.guest_state, 10, .full, .qword);
pub const guest_lbr_ctl = encode(.guest_state, 11, .full, .qword);
pub const guest_pkrs = encode(.guest_state, 12, .full, .qword);

// === Host State Area. cf. SDM Vol.3C 25.4, Appendix B. ================
// Natural-width fields.
pub const host_cr0 = encode(.host_state, 0, .full, .natural);
pub const host_cr3 = encode(.host_state, 1, .full, .natural);
pub const host_cr4 = encode(.host_state, 2, .full, .natural);
pub const host_fs_base = encode(.host_state, 3, .full, .natural);
pub const host_gs_base = encode(.host_state, 4, .full, .natural);
pub const host_tr_base = encode(.host_state, 5, .full, .natural);
pub const host_gdtr_base = encode(.host_state, 6, .full, .natural);
pub const host_idtr_base = encode(.host_state, 7, .full, .natural);
pub const host_sysenter_esp = encode(.host_state, 8, .full, .natural);
pub const host_sysenter_eip = encode(.host_state, 9, .full, .natural);
pub const host_rsp = encode(.host_state, 10, .full, .natural);
pub const host_rip = encode(.host_state, 11, .full, .natural);
pub const host_s_cet = encode(.host_state, 12, .full, .natural);
pub const host_ssp = encode(.host_state, 13, .full, .natural);
pub const host_interrupt_ssp_table_addr = encode(.host_state, 14, .full, .natural);
// 16-bit fields.
pub const host_es_selector = encode(.host_state, 0, .full, .word);
pub const host_cs_selector = encode(.host_state, 1, .full, .word);
pub const host_ss_selector = encode(.host_state, 2, .full, .word);
pub const host_ds_selector = encode(.host_state, 3, .full, .word);
pub const host_fs_selector = encode(.host_state, 4, .full, .word);
pub const host_gs_selector = encode(.host_state, 5, .full, .word);
pub const host_tr_selector = encode(.host_state, 6, .full, .word);
// 32-bit fields.
pub const host_sysenter_cs = encode(.host_state, 0, .full, .dword);
// 64-bit fields.
pub const host_pat = encode(.host_state, 0, .full, .qword);
pub const host_efer = encode(.host_state, 1, .full, .qword);
pub const host_perf_global_ctrl = encode(.host_state, 2, .full, .qword);
pub const host_pkrs = encode(.host_state, 3, .full, .qword);

// === Control cf. SDM Vol.3C 25.4, Appendix B. ================
// Natural-width fields.
pub const control_cr0_mask = encode(.control, 0, .full, .natural);
pub const control_cr4_mask = encode(.control, 1, .full, .natural);
pub const control_cr0_read_shadow = encode(.control, 2, .full, .natural);
pub const control_cr4_read_shadow = encode(.control, 3, .full, .natural);
pub const control_cr3_target_value0 = encode(.control, 4, .full, .natural);
pub const control_cr3_target_value1 = encode(.control, 5, .full, .natural);
pub const control_cr3_target_value2 = encode(.control, 6, .full, .natural);
pub const control_cr3_target_value3 = encode(.control, 7, .full, .natural);
// 16-bit fields.
pub const control_vpid = encode(.control, 0, .full, .word);
pub const control_posted_interrupt_notification_vector = encode(.control, 1, .full, .word);
pub const control_eptp_index = encode(.control, 2, .full, .word);
pub const control_hlat_prefix_size = encode(.control, 3, .full, .word);
pub const control_pid_pointer_index = encode(.control, 4, .full, .word);
// 32-bit fields.
pub const control_pinbased_vmexec_controls = encode(.control, 0, .full, .dword);
pub const control_procbased_vmexec_controls = encode(.control, 1, .full, .dword);
pub const control_exception_bitmap = encode(.control, 2, .full, .dword);
pub const control_pagefault_error_code_mask = encode(.control, 3, .full, .dword);
pub const control_pagefault_error_code_match = encode(.control, 4, .full, .dword);
pub const control_cr3_target_count = encode(.control, 5, .full, .dword);
pub const control_primary_vmexit_controls = encode(.control, 6, .full, .dword);
pub const control_vmexit_msr_store_count = encode(.control, 7, .full, .dword);
pub const control_vmexit_msr_load_count = encode(.control, 8, .full, .dword);
pub const control_vmentry_controls = encode(.control, 9, .full, .dword);
pub const control_vmentry_msr_load_count = encode(.control, 10, .full, .dword);
pub const control_vmentry_interrupt_information_field = encode(.control, 11, .full, .dword);
pub const control_vmentry_exception_error_code = encode(.control, 12, .full, .dword);
pub const control_vmentry_instruction_length = encode(.control, 13, .full, .dword);
pub const control_tpr_threshold = encode(.control, 14, .full, .dword);
pub const control_secondary_procbased_vmexec_controls = encode(.control, 15, .full, .dword);
pub const control_ple_gap = encode(.control, 16, .full, .dword);
pub const control_ple_window = encode(.control, 17, .full, .dword);
pub const control_instruction_timeouts = encode(.control, 18, .full, .dword);
// 64-bit fields.
pub const control_io_bitmap_a = encode(.control, 0, .full, .qword);
pub const control_io_bitmap_b = encode(.control, 1, .full, .qword);
pub const control_msr_bitmap = encode(.control, 2, .full, .qword);
pub const control_vmexit_msr_store_address = encode(.control, 3, .full, .qword);
pub const control_vmexit_msr_load_address = encode(.control, 4, .full, .qword);
pub const control_vmentry_msr_load_address = encode(.control, 5, .full, .qword);
pub const control_executive_vmcs_pointer = encode(.control, 6, .full, .qword);
pub const control_pml_address = encode(.control, 7, .full, .qword);
pub const control_tsc_offset = encode(.control, 8, .full, .qword);
pub const control_virtual_apic_address = encode(.control, 9, .full, .qword);
pub const control_apic_access_address = encode(.control, 10, .full, .qword);
pub const control_posted_interrupt_descriptor_address = encode(.control, 11, .full, .qword);
pub const control_vm_function_controls = encode(.control, 12, .full, .qword);
pub const control_eptp = encode(.control, 13, .full, .qword);
pub const control_eoi_exit_bitmap0 = encode(.control, 14, .full, .qword);
pub const control_eoi_exit_bitmap1 = encode(.control, 15, .full, .qword);
pub const control_eoi_exit_bitmap2 = encode(.control, 16, .full, .qword);
pub const control_eoi_exit_bitmap3 = encode(.control, 17, .full, .qword);
pub const control_eptp_list_address = encode(.control, 18, .full, .qword);
pub const control_vmread_bitmap = encode(.control, 19, .full, .qword);
pub const control_vmwrite_bitmap = encode(.control, 20, .full, .qword);
pub const control_vexception_information_address = encode(.control, 21, .full, .qword);
pub const control_xss_exiting_bitmap = encode(.control, 22, .full, .qword);
pub const control_encls_exiting_bitmap = encode(.control, 23, .full, .qword);
pub const control_sub_page_permission_table_pointer = encode(.control, 24, .full, .qword);
pub const control_tsc_multiplier = encode(.control, 25, .full, .qword);
pub const control_tertiary_processor_based_vmexec_controls = encode(.control, 26, .full, .qword);
pub const enclv_exiting_bitmap = encode(.control, 27, .full, .qword);
pub const control_low_pasid_directory = encode(.control, 28, .full, .qword);
pub const control_high_pasid_directory = encode(.control, 29, .full, .qword);
pub const control_shared_eptp = encode(.control, 30, .full, .qword);
pub const control_pconfig_exiting_bitmap = encode(.control, 31, .full, .qword);
pub const control_hlatp = encode(.control, 32, .full, .qword);
pub const control_pid_pointer_table = encode(.control, 33, .full, .qword);
pub const control_secondary_vmexit_controls = encode(.control, 34, .full, .qword);
pub const control_spec_ctrl_mask = encode(.control, 37, .full, .qword);
pub const control_spec_ctrl_shadow = encode(.control, 38, .full, .qword);

// === Read-Only cf. SDM Vol.3C 25.4, Appendix B. ================
// Natural-width fields.
pub const ro_exit_qual = encode(.vmexit, 0, .full, .natural);
pub const ro_io_rcx = encode(.vmexit, 1, .full, .natural);
pub const ro_io_rsi = encode(.vmexit, 2, .full, .natural);
pub const ro_io_rdi = encode(.vmexit, 3, .full, .natural);
pub const ro_io_rip = encode(.vmexit, 4, .full, .natural);
pub const ro_guest_linear_address = encode(.vmexit, 5, .full, .natural);
// 32-bit fields.
pub const ro_vminstruction_error = encode(.vmexit, 0, .full, .dword);
pub const ro_vmexit_reason = encode(.vmexit, 1, .full, .dword);
pub const ro_vmexit_interruption_information = encode(.vmexit, 2, .full, .dword);
pub const ro_vmexit_interruption_error_code = encode(.vmexit, 3, .full, .dword);
pub const ro_idt_vectoring_information = encode(.vmexit, 4, .full, .dword);
pub const ro_idt_vectoring_error_code = encode(.vmexit, 5, .full, .dword);
pub const ro_vmexit_instruction_length = encode(.vmexit, 6, .full, .dword);
pub const ro_vmexit_instruction_information = encode(.vmexit, 7, .full, .dword);
// 64-bit fields.
pub const ro_guest_physical_address = encode(.vmexit, 0, .full, .qword);

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

fn encode(field_type: FieldType, index: u9, access_type: AccessType, width: Width) ComponentEncoding {
    return ComponentEncoding{
        .access_type = access_type,
        .index = index,
        .field_type = field_type,
        .width = width,
    };
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
            try vmcs.vmwrite(vmcs.control_pinbased_vmexec_controls, val);
        }

        pub fn get() VmxError!PinBasedExecutionControl {
            const val: u32 = @truncate(try vmcs.vmread(vmcs.control_pinbased_vmexec_controls));
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
            try vmcs.vmwrite(vmcs.control_procbased_vmexec_controls, val);
        }

        pub fn get() VmxError!PrimaryProcessorBasedExecutionControl {
            const val: u32 = @truncate(try vmcs.vmread(vmcs.control_procbased_vmexec_controls));
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
            try vmcs.vmwrite(vmcs.control_primary_vmexit_controls, val);
        }

        pub fn get() VmxError!PrimaryExitControls {
            const val: u32 = @truncate(try vmcs.vmread(vmcs.control_primary_vmexit_controls));
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
            try vmcs.vmwrite(vmcs.control_vmentry_controls, val);
        }

        pub fn get() VmxError!EntryControls {
            const val: u32 = @truncate(try vmcs.vmread(vmcs.control_vmentry_controls));
            return @bitCast(val);
        }
    };
};

test {
    std.testing.refAllDeclsRecursive(@This());
}
