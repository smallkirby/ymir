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

pub const VmxError = error{
    /// VMCS pointer is invalid. No status available.
    FailureInvalidVmcsPointer,
    /// VMCS pointer is valid but the operation failed.
    /// If a current VMCS is active, error status is stored in VM-instruction error field.
    FailureStatusAvailable,
    /// Failed to allocate memory.
    OutOfMemory,
};
