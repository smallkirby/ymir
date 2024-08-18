const std = @import("std");

const am = @import("asm.zig");

pub fn vmread(field: ComponentEncoding) u64 {
    const field_u64: u32 = @bitCast(field);
    return asm volatile (
        \\vmread %[field], %[ret]
        : [ret] "={rax}" (-> u64),
        : [field] "r" (@as(u64, @intCast(field_u64))),
    );
}

pub fn vmwrite(field: ComponentEncoding, value: u64) void {
    const field_u64: u32 = @bitCast(field);
    asm volatile (
        \\vmwrite %[value], %[field]
        :
        : [field] "r" (@as(u64, @intCast(field_u64))),
          [value] "r" (value),
    );
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
pub const guest_dr4 = encode(.guest_state, 16, .full, .natural);
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
pub const control_secondary_vmexec_controls = encode(.control, 15, .full, .dword);
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
