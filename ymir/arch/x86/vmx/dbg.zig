const std = @import("std");
const log = std.log.scoped(.vmdbg);

const ymir = @import("ymir");
const mem = ymir.mem;

const arch = @import("arch.zig");
const am = arch.am;
const gdt = arch.gdt;

const vmcs = @import("vmcs.zig");
const vmx = @import("common.zig");

const VmxError = vmx.VmxError;

/// Partially checks the validity of guest state.
pub fn partialCheckGuest() VmxError!void {
    if (!ymir.is_debug) @compileError("partialCheckGuest() is only for debug build");

    const cr0: am.Cr0 = @bitCast(try vmx.vmread(vmcs.guest.cr0));
    const cr3 = try vmx.vmread(vmcs.guest.cr3);
    const cr4: am.Cr4 = @bitCast(try vmx.vmread(vmcs.guest.cr4));
    const entry_ctrl = try vmcs.EntryCtrl.store();
    const exec_ctrl = try vmcs.PrimaryProcExecCtrl.store();
    const exec_ctrl2 = try vmcs.SecondaryProcExecCtrl.store();
    const efer: am.Efer = @bitCast(try vmx.vmread(vmcs.guest.efer));

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
    // TODO: CR4 field must not set any bit not supported in VMX operation.
    if (cr4.cet and !cr0.wp) @panic("CR0: WP must be set when CR4.CET is set");
    // TODO: If "load debug controls" is 1, bits reserved in IA32_DEBUGCTL MSR must be 0.
    if (entry_ctrl.ia32e_mode_guest and !(cr0.pg and cr4.pae)) @panic("CR0: PG and CR4.PAE must be set when IA-32e mode is enabled");
    if (!entry_ctrl.ia32e_mode_guest and cr4.pcide) @panic("CR4: PCIDE must be unset when IA-32e mode is disabled");
    if (cr3 >> 46 != 0) {
        log.err("CR3: {X:0>16}", .{cr3});
        @panic("CR3: Reserved bits must be zero");
    }
    if (!mem.isCanonical(try vmx.vmread(vmcs.guest.sysenter_esp))) @panic("IA32_SYSENTER_ESP must be canonical");
    if (!mem.isCanonical(try vmx.vmread(vmcs.guest.sysenter_eip))) @panic("IA32_SYSENTER_EIP must be canonical");
    if (entry_ctrl.load_cet_state) @panic("Unimplemented: Load CET state");
    if (entry_ctrl.load_debug_controls) @panic("Unimplemented: Load debug controls.");
    if (entry_ctrl.load_perf_global_ctrl) @panic("Unimplemented: Load perf global ctrl.");
    if (entry_ctrl.load_ia32_pat) {
        const pat = try vmx.vmread(vmcs.guest.pat);
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
    const cs_sel = gdt.SegmentSelector.from(try vmx.vmread(vmcs.guest.cs_sel));
    const tr_sel = gdt.SegmentSelector.from(try vmx.vmread(vmcs.guest.tr_sel));
    const ldtr_sel = gdt.SegmentSelector.from(try vmx.vmread(vmcs.guest.ldtr_sel));
    const ss_sel = gdt.SegmentSelector.from(try vmx.vmread(vmcs.guest.ss_sel));
    if (tr_sel.ti != 0) @panic("TR.sel: TI flag must be 0");
    {
        const ldtr_ar: vmx.SegmentRights = @bitCast(@as(u32, @truncate(try vmx.vmread(vmcs.guest.ldtr_rights))));
        if (!ldtr_ar.unusable and ldtr_sel.ti != 0) @panic("LDTR.sel: TI flag must be 0");
    }
    if (cs_sel.rpl != ss_sel.rpl) @panic("CS.sel.RPL must be equal to SS.sel.RPL");

    // Base.
    if (!mem.isCanonical(try vmx.vmread(vmcs.guest.tr_base))) @panic("TR.base must be canonical");
    if (!mem.isCanonical(try vmx.vmread(vmcs.guest.fs_base))) @panic("FS.base must be canonical");
    if (!mem.isCanonical(try vmx.vmread(vmcs.guest.gs_base))) @panic("GS.base must be canonical");
    if (!mem.isCanonical(try vmx.vmread(vmcs.guest.ldtr_base))) @panic("LDTR.base must be canonical");
    if ((try vmx.vmread(vmcs.guest.cs_base)) >> 32 != 0) @panic("CS.base[63:32] must be zero");
    if ((try vmx.vmread(vmcs.guest.ss_base)) >> 32 != 0) @panic("SS.base[63:32] must be zero");
    if ((try vmx.vmread(vmcs.guest.ds_base)) >> 32 != 0) @panic("DS.base[63:32] must be zero");
    if ((try vmx.vmread(vmcs.guest.es_base)) >> 32 != 0) @panic("ES.base[63:32] must be zero");

    // Access Rights.
    const cs_ar = vmx.SegmentRights.from(try vmx.vmread(vmcs.guest.cs_rights));
    const ss_ar = vmx.SegmentRights.from(try vmx.vmread(vmcs.guest.ss_rights));
    const ds_ar = vmx.SegmentRights.from(try vmx.vmread(vmcs.guest.ds_rights));
    const es_ar = vmx.SegmentRights.from(try vmx.vmread(vmcs.guest.es_rights));
    const fs_ar = vmx.SegmentRights.from(try vmx.vmread(vmcs.guest.fs_rights));
    const gs_ar = vmx.SegmentRights.from(try vmx.vmread(vmcs.guest.gs_rights));
    const ds_sel = gdt.SegmentSelector.from(try vmx.vmread(vmcs.guest.ds_sel));
    const es_sel = gdt.SegmentSelector.from(try vmx.vmread(vmcs.guest.es_sel));
    const fs_sel = gdt.SegmentSelector.from(try vmx.vmread(vmcs.guest.fs_sel));
    const gs_sel = gdt.SegmentSelector.from(try vmx.vmread(vmcs.guest.gs_sel));
    const cs_limit = try vmx.vmread(vmcs.guest.cs_limit);
    const ss_limit = try vmx.vmread(vmcs.guest.ss_limit);
    const ds_limit = try vmx.vmread(vmcs.guest.ds_limit);
    const es_limit = try vmx.vmread(vmcs.guest.es_limit);
    const fs_limit = try vmx.vmread(vmcs.guest.fs_limit);
    const gs_limit = try vmx.vmread(vmcs.guest.gs_limit);
    //  type
    if (!cs_ar.accessed or !cs_ar.executable) @panic("CS.rights: CS must be accessed and executable");
    if (!ss_ar.unusable and (!ss_ar.rw or ss_ar.executable)) @panic("SS.rights: Invalid value");
    if (!ds_ar.unusable and !ds_ar.accessed) @panic("DS.rights: Invalid value (accessed)");
    if (!es_ar.unusable and !es_ar.accessed) @panic("ES.rights: Invalid value (accessed)");
    if (!fs_ar.unusable and !fs_ar.accessed) @panic("FS.rights: Invalid value (accessed)");
    if (!gs_ar.unusable and !gs_ar.accessed) @panic("GS.rights: Invalid value (accessed)");
    if (!ds_ar.unusable and (ds_ar.executable and !ds_ar.rw)) @panic("DS.rights: Invalid value (code)");
    if (!es_ar.unusable and (es_ar.executable and !es_ar.rw)) @panic("ES.rights: Invalid value (code)");
    if (!fs_ar.unusable and (fs_ar.executable and !fs_ar.rw)) @panic("FS.rights: Invalid value (code)");
    if (!gs_ar.unusable and (gs_ar.executable and !gs_ar.rw)) @panic("GS.rights: Invalid value (code)");
    //  s
    if (cs_ar.desc_type != .code_data) @panic("CS.rights: Invalid value (code)");
    if (!ss_ar.unusable and ss_ar.desc_type != .code_data) @panic("SS.rights: Invalid value (code)");
    if (!ds_ar.unusable and ds_ar.desc_type != .code_data) @panic("DS.rights: Invalid value (code)");
    if (!es_ar.unusable and es_ar.desc_type != .code_data) @panic("ES.rights: Invalid value (code)");
    if (!fs_ar.unusable and fs_ar.desc_type != .code_data) @panic("FS.rights: Invalid value (code)");
    if (!gs_ar.unusable and gs_ar.desc_type != .code_data) @panic("GS.rights: Invalid value (code)");
    // DPL
    if ((cs_ar.accessed and cs_ar.rw and !cs_ar.dc and !cs_ar.executable) and cs_ar.dpl != 0) @panic("CS.rights: Invalid value (DPL)");
    if ((cs_ar.accessed and !cs_ar.dc and cs_ar.executable) and cs_ar.dpl != ss_ar.dpl) @panic("CS.rights: Invalid value (DPL)");
    if ((cs_ar.accessed and cs_ar.dc and cs_ar.executable) and cs_ar.dpl > ss_ar.dpl) @panic("CS.rights: Invalid value (DPL)");
    if (ss_ar.dpl != ss_sel.rpl) @panic("SS.rights: DPL must be equal to RPL");
    // TODO: The DPL of SS must be 0 either if ...
    if (ds_ar.dpl < ds_sel.rpl) @panic("DS.rights: Invalid value (DPL)");
    if (es_ar.dpl < es_sel.rpl) @panic("ES.rights: Invalid value (DPL)");
    if (fs_ar.dpl < fs_sel.rpl) @panic("FS.rights: Invalid value (DPL)");
    if (gs_ar.dpl < gs_sel.rpl) @panic("GS.rights: Invalid value (DPL)");
    // P
    if (!cs_ar.present) @panic("CS.rights: P must be set");
    if (!ss_ar.unusable and !ss_ar.present) @panic("SS.rights: P must be set");
    if (!ds_ar.unusable and !ds_ar.present) @panic("DS.rights: P must be set");
    if (!es_ar.unusable and !es_ar.present) @panic("ES.rights: P must be set");
    if (!fs_ar.unusable and !fs_ar.present) @panic("FS.rights: P must be set");
    if (!gs_ar.unusable and !gs_ar.present) @panic("GS.rights: P must be set");
    // TODO: Reserved bits must be zero.
    // D/B
    if ((entry_ctrl.ia32e_mode_guest and cs_ar.long) and cs_ar.db != 0) @panic("CS.rights: D/B must be zero when IA-32e mode is enabled");
    // G.
    if (cs_limit & 0xFFF != 0xFFF and cs_ar.granularity != .byte) @panic("CS.rights: G must be clear when CS.limit is not page-aligned");
    if (!ss_ar.unusable and ss_limit & 0xFFF != 0xFFF and ss_ar.granularity != .byte) @panic("SS.rights: G must be clear when SS.limit is not page-aligned");
    if (!ds_ar.unusable and ds_limit & 0xFFF != 0xFFF and ds_ar.granularity != .byte) @panic("DS.rights: G must be clear when DS.limit is not page-aligned");
    if (!es_ar.unusable and es_limit & 0xFFF != 0xFFF and es_ar.granularity != .byte) @panic("ES.rights: G must be clear when ES.limit is not page-aligned");
    if (!fs_ar.unusable and fs_limit & 0xFFF != 0xFFF and fs_ar.granularity != .byte) @panic("FS.rights: G must be clear when FS.limit is not page-aligned");
    if (!gs_ar.unusable and gs_limit & 0xFFF != 0xFFF and gs_ar.granularity != .byte) @panic("GS.rights: G must be clear when GS.limit is not page-aligned");
    if (cs_limit >> 20 != 0 and cs_ar.granularity != .kbyte) @panic("CS.rights: G must be set.");
    if (!ss_ar.unusable and ss_limit >> 20 != 0 and ss_ar.granularity != .kbyte) @panic("SS.rights: G must be set.");
    if (!ds_ar.unusable and ds_limit >> 20 != 0 and ds_ar.granularity != .kbyte) @panic("DS.rights: G must be set.");
    if (!es_ar.unusable and es_limit >> 20 != 0 and es_ar.granularity != .kbyte) @panic("ES.rights: G must be set.");
    if (!fs_ar.unusable and fs_limit >> 20 != 0 and fs_ar.granularity != .kbyte) @panic("FS.rights: G must be set.");
    if (!gs_ar.unusable and gs_limit >> 20 != 0 and gs_ar.granularity != .kbyte) @panic("GS.rights: G must be set.");
    // TODO: Reserved bits must be zero.
    // TODO: TR
    // LDTR
    const ldtr_ar = vmx.SegmentRights.from(try vmx.vmread(vmcs.guest.ldtr_rights));
    if (!ldtr_ar.unusable) {
        if (ldtr_ar.accessed or !ldtr_ar.rw or ldtr_ar.dc or ldtr_ar.executable)
            @panic("LDTR.rights: Invalid value: {}");
        if (ldtr_ar.desc_type != .system) @panic("LDTR.rights: Invalid descriptor type");
        if (!ldtr_ar.present) @panic("LDTR.rights: P must be set");
        if (ldtr_ar._reserved1 != 0) @panic("LDTR.rights: Reserved bits must be zero");
    }

    // == Checks on Guest Descriptor-Table Registers.
    // cf. SDM Vol 3C 27.3.1.3.
    if (!mem.isCanonical(try vmx.vmread(vmcs.guest.gdtr_base))) @panic("GDTR.base must be canonical");
    if (!mem.isCanonical(try vmx.vmread(vmcs.guest.idtr_base))) @panic("IDTR.base must be canonical");
    if (try vmx.vmread(vmcs.guest.gdtr_limit) >> 16 != 0) @panic("GDTR.limit[15:0] must be zero");
    if (try vmx.vmread(vmcs.guest.idtr_limit) >> 16 != 0) @panic("IDTR.limit[15:0] must be zero");

    // == Checks on Guest RIP, RFLAGS, and SSP
    // cf. SDM Vol 3C 27.3.1.4.
    const rip = try vmx.vmread(vmcs.guest.rip);
    const intr_info: vmx.EntryIntrInfo = @bitCast(@as(u32, @truncate(try vmx.vmread(vmcs.ctrl.entry_intr_info))));
    const rflags: am.FlagsRegister = @bitCast(try vmx.vmread(vmcs.guest.rflags));

    if ((!entry_ctrl.ia32e_mode_guest or !cs_ar.long) and (rip >> 32) != 0) @panic("RIP: Upper address must be all zeros");
    // TODO: If the processor supports N < 64 linear-address bits, ...

    if (rflags._reserved4 != 0 or rflags._reserved1 != 0 or rflags._reserved2 != 0 or rflags._reserved3 != 0) @panic("RFLAGS: Reserved bits must be zero");
    if (rflags._reservedO != 1) @panic("RFLAGS: Reserved bit 1 must be one");
    if ((entry_ctrl.ia32e_mode_guest or !cr0.pe) and rflags.vm) @panic("RFLAGS: VM must be clear when IA-32e mode is enabled");
    if (intr_info.valid and !rflags.ief) @panic("RFLAGS: IF must be set when valid bit in VM-entry interruption-information field is set.");

    // == Checks on Guest Non-Register State.
    // cf. SDM Vol 3C 27.3.1.5.
    // Activity state.
    const activity_state = try vmx.vmread(vmcs.guest.activity_state);
    if (activity_state != 0) @panic("Unsupported activity state.");
    const intr_state = try vmx.vmread(vmcs.guest.intr_status);
    if ((intr_state >> 5) != 0) @panic("Unsupported interruptability state.");
    // TODO: other checks

    // Interruptibility state.
    const is = try vmx.InterruptibilityState.load();
    const eflags: am.FlagsRegister = @bitCast(try vmx.vmread(vmcs.guest.rflags));
    const pin_exec_ctrl = try vmcs.PinExecCtrl.store();
    if (is._reserved != 0) {
        log.err("Interruptibility State: 0b{b:0>27}", .{is._reserved});
        @panic("Interruptibility State: Reserved bits must be zero");
    }
    if (is.blocking_by_sti and is.blocking_by_movss) @panic("Interruptibility State: STI and MOV SS must not be set simultaneously");
    if (!eflags.ief and is.blocking_by_sti) @panic("Interruptibility State: Blocking by STI must be clear when RFLAGS.IF is clear");
    if (intr_info.valid and (intr_info.type == .external or intr_info.type == .nmi))
        if (is.blocking_by_sti or is.blocking_by_movss) @panic("Interruptibility State: Blocking by STI or MOV SS must be clear when external interrupt or NMI is pending");
    if (is.blocking_by_smi) @panic("Interruptibility State: Blocking by SMI must be clear (unsupported)");
    if (pin_exec_ctrl.virtual_nmi and intr_info.valid and intr_info.type == .nmi)
        if (is.blocking_by_nmi) @panic("Interruptibility State: Blocking by NMI must be clear for virtual-NMI");

    // Pending debug exceptions.
    // TODO

    // VMCS link pointer.
    if (try vmx.vmread(vmcs.guest.vmcs_link_pointer) != std.math.maxInt(u64)) @panic("Unsupported VMCS link pointer other than FFFFFFFF_FFFFFFFFh");

    // == Checks on Guest Page-Directory-Pointer-Table Entries.
    // cf. SDM Vol 3C 27.3.1.6.
    const is_pae_paging = (cr0.pg and cr4.pae and !entry_ctrl.ia32e_mode_guest); // When PAE paging, CR3 references level-4 table.
    if (is_pae_paging) {
        // TODO
        @panic("Unimplemented: PAE paging");
    }

    // == Checks on Control Fields
    // cf. SDM Vol 3C 27.2.1.1
    // vAPIC
    const ppb_exec_ctrl = try vmcs.PrimaryProcExecCtrl.store();
    const ppb_exec_ctrl2 = try vmcs.SecondaryProcExecCtrl.store();
    const apic_access_addr = try vmx.vmread(vmcs.ctrl.apic_access_address);
    if (apic_access_addr & mem.page_mask_4k != 0) @panic("APIC-access address must be page-aligned");
    if (apic_access_addr >> 32 != 0) @panic("APIC-access address must be within the supported physical-address width");
    if (!ppb_exec_ctrl.use_tpr_shadow) {
        if (!ppb_exec_ctrl2.virtualize_x2apic_mode or !ppb_exec_ctrl2.apic_register_virtualization or !ppb_exec_ctrl2.virtual_interrupt_delivery) {
            @panic("TPR shadow must be enabled when APIC virtualization is enabled");
        }
    }
}
