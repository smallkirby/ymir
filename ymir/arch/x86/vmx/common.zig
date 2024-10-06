const std = @import("std");
const Allocator = std.mem.Allocator;

const ymir = @import("ymir");
const mem = ymir.mem;

const am = @import("../asm.zig");
const vmcs = @import("vmcs.zig");

pub const VmxError = error{
    /// VMCS pointer is invalid. No status available.
    VmxStatusUnavailable,
    /// VMCS pointer is valid but the operation failed.
    /// If a current VMCS is active, error status is stored in VM-instruction error field.
    VmxStatusAvailable,
    /// Failed to allocate memory.
    OutOfMemory,
    /// Failed to subscribe to interrupts.
    InterruptFull,
};

/// Read RFLAGS and checks if a VMX instruction has failed.
pub fn vmxtry(rflags: u64) VmxError!void {
    const flags: am.FlagsRegister = @bitCast(rflags);
    return if (flags.cf) VmxError.VmxStatusUnavailable else if (flags.zf) VmxError.VmxStatusAvailable;
}

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
    try vmxtry(rflags);
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
    try vmxtry(rflags);
}

/// Access rights of segments that can be set in guest-state area.
pub const SegmentRights = packed struct(u32) {
    const gdt = @import("../gdt.zig");

    /// Segment is accessed.
    accessed: bool = true,
    /// Readable / Writable.
    rw: bool,
    /// Direction / Conforming.
    dc: bool,
    /// Executable.
    executable: bool,
    /// Descriptor type.
    desc_type: gdt.DescriptorType,
    /// Descriptor privilege level.
    dpl: u2,
    /// Present.
    present: bool = true,
    /// Reserved.
    _reserved1: u4 = 0,
    /// Available for use by system software.
    avl: bool = false,
    /// Long mode.
    long: bool = false,
    /// Size flag.
    db: u1,
    /// Granularity.
    granularity: gdt.Granularity,
    /// Unusable.
    unusable: bool = false,
    /// Reserved.
    _reserved2: u15 = 0,

    pub fn from(val: anytype) SegmentRights {
        return @bitCast(@as(u32, @truncate(val)));
    }
};

/// Guest registers to save and restore on VM-entry and VM-exit.
pub const GuestRegisters = extern struct {
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
    // Align to 16 bytes, otherwise movaps would cause #GP.
    xmm0: u128 align(16),
    xmm1: u128 align(16),
    xmm2: u128 align(16),
    xmm3: u128 align(16),
    xmm4: u128 align(16),
    xmm5: u128 align(16),
    xmm6: u128 align(16),
    xmm7: u128 align(16),
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

    /// Get a instruction error number from VMCS.
    pub fn load() VmxError!InstructionError {
        return @enumFromInt(@as(u32, @truncate(try vmread(vmcs.ro.vminstruction_error))));
    }
};

/// Provides a basic information about VM exit.
/// cf. SDM Vol 3C 25.9.1.
pub const ExitInfo = packed struct(u32) {
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

    /// Get a VM-exit information from VMCS.
    pub fn load() VmxError!ExitInfo {
        return @bitCast(@as(u32, @truncate(try vmread(vmcs.ro.vmexit_reason))));
    }
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

/// VM-exit interruption information.
/// cf. SDM Vol.3C. 28.2.2. Table 25-19.
pub const InterruptInfo = packed struct(u32) {
    /// Vector of interrupt or exception.
    vector: u8,
    /// Interruption type.
    type: Type,
    /// Error code valid.
    ec_valid: bool,
    /// NMI unblocking due to IRET.
    nmi_unblocking: bool,
    /// Not currently defined.
    _notused: u18 = 0,
    /// Valid.
    valid: bool,

    const Type = enum(u3) {
        external = 0,
        _unused1 = 1,
        nmi = 2,
        hw = 3,
        _unused2 = 4,
        priviledged_sw = 5,
        exception = 6,
        _unused3 = 7,
    };

    const Kind = enum {
        entry,
        exit,
    };

    /// Get a VM-entry or VM-exit interrupt information from VMCS.
    pub fn load(kind: Kind) VmxError!InterruptInfo {
        return @bitCast(@as(u32, @truncate(switch (kind) {
            .entry => try vmread(vmcs.ctrl.entry_intr_info),
            .exit => try vmread(vmcs.ro.exit_intr_info),
        })));
    }
};

/// SDM Vol.3C. 25.4.2. Table 25-3.
pub const InterruptibilityState = packed struct(u32) {
    blocking_by_sti: bool,
    blocking_by_movss: bool,
    blocking_by_smi: bool,
    blocking_by_nmi: bool,
    enclave: bool,
    /// Reserved.
    _reserved: u27 = 0,

    /// Get a interruptibility state from VMCS.
    pub fn load() VmxError!InterruptibilityState {
        return @bitCast(@as(u32, @truncate(try vmread(vmcs.guest.interruptibility_state))));
    }
};

/// I/O bitmap.
pub const IoBitmap = struct {
    /// The first one maps 0x0000 to 0x7FFF. The second one maps 0x8000 to 0xFFFF.
    map_a: []u8,
    map_b: []u8,

    /// Initialize I/O bitmap.
    /// All bits are set to true, meaning that all I/O accesses causes a VM-exit.
    pub fn new(allocator: Allocator) VmxError!IoBitmap {
        const map_a = allocator.alignedAlloc(u8, mem.page_size_4k, mem.page_size_4k) catch return error.OutOfMemory;
        const map_b = allocator.alignedAlloc(u8, mem.page_size_4k, mem.page_size_4k) catch return error.OutOfMemory;
        @memset(map_a, 0xFF);
        @memset(map_b, 0xFF);

        try vmwrite(vmcs.ctrl.io_bitmap_a, mem.virt2phys(map_a.ptr));
        try vmwrite(vmcs.ctrl.io_bitmap_b, mem.virt2phys(map_b.ptr));

        return IoBitmap{
            .map_a = map_a,
            .map_b = map_b,
        };
    }

    pub fn set(self: *IoBitmap, port: u32, exit: bool) void {
        const idx = if (port < 0x8000) port / 8 else (port - 0x8000) / 8;
        const bit: u3 = @intCast(port % 8);
        const map = if (port < 0x8000) self.map_a else self.map_b;
        if (exit) {
            map[idx] |= @as(u8, 1) << bit;
        } else {
            map[idx] &= ~(@as(u8, 1) << bit);
        }
    }
};
