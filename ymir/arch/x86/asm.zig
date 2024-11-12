const std = @import("std");

const ymir = @import("ymir");
const bits = ymir.bits;
const mem = ymir.mem;

const vmx = @import("vmx/common.zig");
const VmxError = vmx.VmxError;
const vmxerr = vmx.vmxtry;

pub inline fn inb(port: u16) u8 {
    return asm volatile (
        \\inb %[port], %[ret]
        : [ret] "={al}" (-> u8),
        : [port] "{dx}" (port),
    );
}

pub inline fn inw(port: u16) u16 {
    return asm volatile (
        \\inw %[port], %[ret]
        : [ret] "={ax}" (-> u16),
        : [port] "{dx}" (port),
    );
}

pub inline fn inl(port: u16) u32 {
    return asm volatile (
        \\inl %[port], %[ret]
        : [ret] "={eax}" (-> u32),
        : [port] "{dx}" (port),
    );
}

pub inline fn outb(value: u8, port: u16) void {
    asm volatile (
        \\outb %[value], %[port]
        :
        : [value] "{al}" (value),
          [port] "{dx}" (port),
    );
}

pub inline fn outw(value: u16, port: u16) void {
    asm volatile (
        \\outw %[value], %[port]
        :
        : [value] "{ax}" (value),
          [port] "{dx}" (port),
    );
}

pub inline fn outl(value: u32, port: u16) void {
    asm volatile (
        \\outl %[value], %[port]
        :
        : [value] "{eax}" (value),
          [port] "{dx}" (port),
    );
}

pub inline fn lgdt(gdtr: u64) void {
    asm volatile (
        \\lgdt (%[gdtr])
        :
        : [gdtr] "r" (gdtr),
    );
}

pub inline fn lidt(idtr: u64) void {
    asm volatile (
        \\lidt (%[idtr])
        :
        : [idtr] "r" (idtr),
    );
}

pub inline fn loadCr3(cr3: u64) void {
    asm volatile (
        \\mov %[cr3], %%cr3
        :
        : [cr3] "r" (cr3),
    );
}

pub inline fn readCr3() u64 {
    return asm volatile (
        \\mov %%cr3, %[cr3]
        : [cr3] "=r" (-> u64),
    );
}

pub inline fn cli() void {
    asm volatile ("cli");
}

pub inline fn sti() void {
    asm volatile ("sti");
}

pub inline fn hlt() void {
    asm volatile ("hlt");
}

/// Pause the CPU for a short period of time.
pub fn relax() void {
    asm volatile ("rep; nop");
}

pub inline fn loadCr0(cr0: anytype) void {
    asm volatile (
        \\mov %[cr0], %%cr0
        :
        : [cr0] "r" (@as(u64, @bitCast(cr0))),
    );
}

pub inline fn readCr0() Cr0 {
    var cr0: u64 = undefined;
    asm volatile (
        \\mov %%cr0, %[cr0]
        : [cr0] "=r" (cr0),
    );
    return @bitCast(cr0);
}

pub inline fn loadCr4(cr4: anytype) void {
    asm volatile (
        \\mov %[cr4], %%cr4
        :
        : [cr4] "r" (@as(u64, @bitCast(cr4))),
    );
}

pub inline fn readCr4() Cr4 {
    var cr4: u64 = undefined;
    asm volatile (
        \\mov %%cr4, %[cr4]
        : [cr4] "=r" (cr4),
    );
    return @bitCast(cr4);
}

pub fn readMsr(msr: Msr) u64 {
    var eax: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile (
        \\rdmsr
        : [eax] "={eax}" (eax),
          [edx] "={edx}" (edx),
        : [msr] "{ecx}" (@intFromEnum(msr)),
    );

    return bits.concat(u64, edx, eax);
}

pub fn writeMsr(msr: Msr, value: u64) void {
    asm volatile (
        \\wrmsr
        :
        : [msr] "{ecx}" (@intFromEnum(msr)),
          [eax] "{eax}" (@as(u32, @truncate(value))),
          [edx] "{edx}" (@as(u32, @truncate(value >> 32))),
    );
}

pub fn readMsrVmxBasic() MsrVmxBasic {
    const val = readMsr(.vmx_basic);
    return @bitCast(val);
}

const Segment = enum {
    cs,
    ss,
    ds,
    es,
    fs,
    gs,
    tr,
    ldtr,
};

pub fn readSegSelector(segment: Segment) u16 {
    return switch (segment) {
        .cs => asm volatile ("mov %%cs, %[ret]"
            : [ret] "=r" (-> u16),
        ),
        .ss => asm volatile ("mov %%ss, %[ret]"
            : [ret] "=r" (-> u16),
        ),
        .ds => asm volatile ("mov %%ds, %[ret]"
            : [ret] "=r" (-> u16),
        ),
        .es => asm volatile ("mov %%es, %[ret]"
            : [ret] "=r" (-> u16),
        ),
        .fs => asm volatile ("mov %%fs, %[ret]"
            : [ret] "=r" (-> u16),
        ),
        .gs => asm volatile ("mov %%gs, %[ret]"
            : [ret] "=r" (-> u16),
        ),
        .tr => asm volatile ("str %[ret]"
            : [ret] "=r" (-> u16),
        ),
        .ldtr => asm volatile ("sldt %[ret]"
            : [ret] "=r" (-> u16),
        ),
    };
}

const SgdtRet = packed struct {
    limit: u16,
    base: u64,
};

pub inline fn sgdt() SgdtRet {
    var gdtr: SgdtRet = undefined;
    asm volatile (
        \\sgdt %[ret]
        : [ret] "=m" (gdtr),
    );
    return gdtr;
}

const SidtRet = packed struct {
    limit: u16,
    base: u64,
};

pub inline fn sidt() SidtRet {
    var idtr: SidtRet = undefined;
    asm volatile (
        \\sidt %[ret]
        : [ret] "=m" (idtr),
    );
    return idtr;
}

pub inline fn vmxon(vmxon_region: mem.Phys) VmxError!void {
    var rflags: u64 = undefined;
    asm volatile (
        \\vmxon (%[vmxon_phys])
        \\pushf
        \\popq %[rflags]
        : [rflags] "=r" (rflags),
        : [vmxon_phys] "r" (&vmxon_region),
        : "cc", "memory"
    );
    try vmxerr(rflags);
}

pub inline fn vmxoff() void {
    asm volatile ("vmxoff");
}

pub inline fn vmclear(vmcs_region: mem.Phys) VmxError!void {
    var rflags: u64 = undefined;
    asm volatile (
        \\vmclear (%[vmcs_phys])
        \\pushf
        \\popq %[rflags]
        : [rflags] "=r" (rflags),
        : [vmcs_phys] "r" (&vmcs_region),
        : "cc", "memory"
    );
    try vmxerr(rflags);
}

pub inline fn vmptrld(vmcs_region: mem.Phys) VmxError!void {
    var rflags: u64 = undefined;
    asm volatile (
        \\vmptrld (%[vmcs_phys])
        \\pushf
        \\popq %[rflags]
        : [rflags] "=r" (rflags),
        : [vmcs_phys] "r" (&vmcs_region),
        : "cc", "memory"
    );
    try vmxerr(rflags);
}

const InvvpidType = enum(u64) {
    individual_address = 0,
    single_context = 1,
    all_context = 2,
    single_global = 3,
};

pub inline fn invvpid(comptime inv_type: InvvpidType, vpid: u16) void {
    const descriptor: packed struct(u128) {
        vpid: u16,
        _reserved: u48 = 0,
        linear_addr: u64 = 0,
    } align(128) = .{ .vpid = vpid };
    asm volatile (
        \\invvpid (%[descriptor]), %[inv_type]
        :
        : [inv_type] "r" (@intFromEnum(inv_type)),
          [descriptor] "r" (&descriptor),
        : "memory"
    );
}

/// EFLAGS register.
pub const FlagsRegister = packed struct(u64) {
    /// Carry flag.
    cf: bool,
    /// Reserved. Must be 1.
    _reservedO: u1 = 1,
    /// Parity flag.
    pf: bool,
    /// Reserved. Must be 0.
    _reserved1: u1 = 0,
    /// Auxiliary carry flag.
    af: bool,
    /// Reserved. Must be 0.
    _reserved2: u1 = 0,
    /// Zero flag.
    zf: bool,
    /// Sign flag.
    sf: bool,
    /// Trap flag.
    tf: bool,
    /// Interrupt enable flag.
    ief: bool,
    /// Direction flag.
    df: bool,
    /// Overflow flag.
    of: bool,
    /// IOPL (I/O privilege level).
    iopl: u2,
    /// Nested task flag.
    nt: bool,
    /// Reserved. Must be 0.
    md: u1 = 0,
    /// Resume flag.
    rf: bool,
    /// Virtual 8086 mode flag.
    vm: bool,
    // Alignment check.
    ac: bool,
    /// Virtual interrupt flag.
    vif: bool,
    /// Virtual interrupt pending.
    vip: bool,
    /// CPUID support.
    id: bool,
    /// Reserved.
    _reserved3: u8,
    /// Reserved.
    aes: bool,
    /// Alternate instruction set enabled.
    ai: bool,
    /// Reserved. Must be 0.
    _reserved4: u32 = 0,

    pub fn new() FlagsRegister {
        var ret = std.mem.zeroes(FlagsRegister);
        ret._reservedO = 1;
        return ret;
    }
};

/// CR0 register.
pub const Cr0 = packed struct(u64) {
    /// Protected mode enable.
    pe: bool,
    /// Monitor co-processor.
    mp: bool,
    /// Emulation.
    em: bool,
    /// Task switched.
    ts: bool,
    /// Extension type.
    et: bool,
    /// Numeric error.
    ne: bool,
    /// Reserved.
    _reserved1: u10 = 0,
    /// Write protect.
    wp: bool,
    /// Reserved.
    _reserved2: u1 = 0,
    /// Alignment mask.
    am: bool,
    /// Reserved.
    _reserved3: u10 = 0,
    /// Not-Write Through.
    nw: bool,
    /// Cache disable.
    cd: bool,
    /// Paging.
    pg: bool,
    /// Reserved.
    _reserved4: u32 = 0,
};

/// CR4 register.
pub const Cr4 = packed struct(u64) {
    /// Virtual-8086 mode extensions.
    vme: bool,
    /// Protected mode virtual interrupts.
    pvi: bool,
    /// Time stamp disable.
    tsd: bool,
    /// Debugging extensions.
    de: bool,
    /// Page size extension.
    pse: bool,
    /// Physical address extension. If unset, 32-bit paging.
    pae: bool,
    /// Machine check exception.
    mce: bool,
    /// Page global enable.
    pge: bool,
    /// Performance monitoring counter enable.
    pce: bool,
    /// Operating system support for FXSAVE and FXRSTOR instructions.
    osfxsr: bool,
    /// Operating system support for unmasked SIMD floating-point exceptions.
    osxmmexcpt: bool,
    /// Virtual machine extensions.
    umip: bool,
    /// 57-bit linear addresses. If set, CPU uses 5-level paging.
    la57: bool = false,
    /// Virtual machine extensions enable.
    vmxe: bool,
    /// Safer mode extensions enable.
    smxe: bool,
    /// Reserved.
    _reserved2: u1 = 0,
    /// Enables the instructions RDFSBASE, RDGSBASE, WRFSBASE, and WRGSBASE.
    fsgsbase: bool,
    /// PCID enable.
    pcide: bool,
    /// XSAVE and processor extended states enable.
    osxsave: bool,
    /// Reserved.
    _reserved3: u1 = 0,
    /// Supervisor mode execution protection enable.
    smep: bool,
    /// Supervisor mode access protection enable.
    smap: bool,
    /// Protection key enable.
    pke: bool,
    /// Control-flow Enforcement Technology enable.
    cet: bool,
    /// Protection keys for supervisor-mode pages enable.
    pks: bool,
    /// Reserved.
    _reserved4: u39 = 0,
};

/// MSR addresses.
pub const Msr = enum(u32) {
    /// IA32_APIC_BASE MSR.
    apic_base = 0x001B,
    /// IA32_FEATURE_CONTROL MSR.
    feature_control = 0x003A,
    /// IA32_TSC MSR.
    tsc_adjust = 0x003B,
    /// IA32_SPEC_CTRL MSR.
    spec_ctrl = 0x0048,
    /// IA32_BIOS_SIGN_ID MSR. SDM Vol.3A Table 2-3.
    bios_sign_id = 0x8B,
    /// IA32_MTRRCAP MSR.
    mtrrcap = 0xFE,
    /// IA32_ARCH_CAPABILITIES MSR. SDM Vol.3A Table 2-2.
    arch_cap = 0x10A,
    /// IA32_SYSENTER_CS MSR. SDM Vol.3A Table 2-3.
    sysenter_cs = 0x174,
    /// IA32_SYSENTER_ESP MSR. SDM Vol.3A Table 2-3.
    sysenter_esp = 0x175,
    /// IA32_SYSENTER_EIP MSR. SDM Vol.3A Table 2-3.
    sysenter_eip = 0x176,
    /// IA32_MCG_CAP MSR.
    mcg_cap = 0x179,
    /// IA32_MISC_ENABLE MSR.
    misc_enable = 0x1A0,
    /// IA32_DEBUGCTL MSR. SDM Vol.4 Table 2-3.
    debugctl = 0x01D9,
    /// IA32_MTRR_PHYSBASE0 MSR.
    mtrr_physbase0 = 0x200,
    /// IA32_MTRR_PHYSMASK0 MSR.
    mtrr_physmask0 = 0x201,
    /// IA32_MTRR_PHYSBASE1 MSR.
    mtrr_physbase1 = 0x202,
    /// IA32_MTRR_PHYSMASK1 MSR.
    mtrr_physmask1 = 0x203,
    /// IA32_MTRR_PHYSBASE2 MSR.
    mtrr_physbase2 = 0x204,
    /// IA32_MTRR_PHYSMASK2 MSR.
    mtrr_physmask2 = 0x205,
    /// IA32_MTRR_PHYSBASE3 MSR.
    mtrr_physbase3 = 0x206,
    /// IA32_MTRR_PHYSMASK3 MSR.
    mtrr_physmask3 = 0x207,
    /// IA32_MTRR_PHYSBASE4 MSR.
    mtrr_physbase4 = 0x208,
    /// IA32_MTRR_PHYSMASK4 MSR.
    mtrr_physmask4 = 0x209,
    /// IA32_MTRR_PHYSBASE5 MSR.
    mtrr_physbase5 = 0x20A,
    /// IA32_MTRR_PHYSMASK5 MSR.
    mtrr_physmask5 = 0x20B,
    /// IA32_MTRR_PHYSBASE6 MSR.
    mtrr_physbase6 = 0x20C,
    /// IA32_MTRR_PHYSMASK6 MSR.
    mtrr_physmask6 = 0x20D,
    /// IA32_MTRR_PHYSBASE7 MSR.
    mtrr_physbase7 = 0x20E,
    /// IA32_MTRR_PHYSMASK7 MSR.
    mtrr_physmask7 = 0x20F,
    /// IA32_MTRR_FIX64K_00000 MSR.
    mtrr_fix64K_00000 = 0x250,
    /// IA32_MTRR_FIX16K_80000 MSR.
    mtrr_fix16K_80000 = 0x258,
    /// IA32_MTRR_FIX16K_A0000 MSR.
    mtrr_fix16K_A0000 = 0x259,
    /// IA32_MTRR_FIX4K_C0000 MSR.
    mtrr_fix4K_C0000 = 0x268,
    /// IA32_MTRR_FIX4K_C8000 MSR.
    mtrr_fix4K_C8000 = 0x269,
    /// IA32_MTRR_FIX4K_D0000 MSR.
    mtrr_fix4K_D0000 = 0x26A,
    /// IA32_MTRR_FIX4K_D8000 MSR.
    mtrr_fix4K_D8000 = 0x26B,
    /// IA32_MTRR_FIX4K_E0000 MSR.
    mtrr_fix4K_E0000 = 0x26C,
    /// IA32_MTRR_FIX4K_E8000 MSR.
    mtrr_fix4K_E8000 = 0x26D,
    /// IA32_MTRR_FIX4K_F0000 MSR.
    mtrr_fix4K_F0000 = 0x26E,
    /// IA32_MTRR_FIX4K_F8000 MSR.
    mtrr_fix4K_F8000 = 0x26F,
    /// IA32_PAT MSR.
    pat = 0x277,
    /// IA32_MTRR_DEF_TYPE MSR.
    mtrr_def_type = 0x2FF,
    /// IA32_VMX_BASIC MSR.
    vmx_basic = 0x0480,
    /// IA32_VMX_PINBASED_CTLS MSR.
    vmx_pinbased_ctls = 0x0481,
    /// IA32_VMX_PROCBASED_CTLS MSR.
    vmx_procbased_ctls = 0x0482,
    /// IA32_VMX_EXIT_CTLS MSR.
    vmx_exit_ctls = 0x0483,
    /// IA32_VMX_ENTRY_CTLS MSR.
    vmx_entry_ctls = 0x0484,
    /// IA32_VMX_MISC MSR.
    vmx_misc = 0x0485,
    /// IA32_VMX_CR0_FIXED0 MSR.
    vmx_cr0_fixed0 = 0x0486,
    /// IA32_VMX_CR0_FIXED1 MSR.
    vmx_cr0_fixed1 = 0x0487,
    /// IA32_VMX_CR4_FIXED0 MSR.
    vmx_cr4_fixed0 = 0x0488,
    /// IA32_VMX_CR4_FIXED1 MSR.
    vmx_cr4_fixed1 = 0x0489,
    /// IA32_VMX_PROCBASED_CTLS2 MSR.
    vmx_procbased_ctls2 = 0x048B,
    /// IA32_VMX_EPT_VPID_CAP MSR.
    vmx_ept_vpid_cap = 0x048C,
    /// IA32_VMX_TRUE_PINBASED_CTLS MSR.
    vmx_true_pinbased_ctls = 0x048D,
    /// IA32_VMX_TRUE_PROCBASED_CTLS MSR.
    vmx_true_procbased_ctls = 0x048E,
    /// IA32_VMX_TRUE_EXIT_CTLS MSR.
    vmx_true_exit_ctls = 0x048F,
    /// IA32_VMX_TRUE_ENTRY_CTLS MSR.
    vmx_true_entry_ctls = 0x0490,
    /// IA32_XSS MSR.
    xss = 0x0DA0,

    /// IA32_STAR MSR.
    star = 0xC0000081,
    /// IA32_LSTAR MSR.
    lstar = 0xC0000082,
    /// IA32_CSTAR MSR.
    cstar = 0xC0000083,
    /// IA32_FMASK MSR.
    fmask = 0xC0000084,
    /// IA32_FS_BASE MSR.
    fs_base = 0xC0000100,
    /// IA32_GS_BASE MSR.
    gs_base = 0xC0000101,
    /// IA32_KERNEL_GS_BASE MSR.
    kernel_gs_base = 0xC0000102,
    /// IA32_TSC_AUX MSR.
    tsc_aux = 0xC0000103,
    /// IA32_EFER MSR.
    efer = 0xC0000080,

    _,
};

/// IA32_EFER MSR.
pub const Efer = packed struct(u64) {
    /// System call extensions.
    sce: bool,
    /// ReservedZ.
    reserved1: u7 = 0,
    /// Long mode enable.
    lme: bool,
    ///
    ignored: bool,
    /// Long mode active.
    lma: bool,
    /// No execute enable.
    nxe: bool,
    /// Secure virtual machine enable.
    svme: bool,
    /// Long mode segment limit enable.
    lmsle: bool,
    /// Fast FXSAVE/FXRSTOR.
    ffxsr: bool,
    /// Translation cache extension.
    tce: bool,
    /// ReservedZ.
    reserved2: u48 = 0,
};

/// IA32_VMX_BASIC MSR.
pub const MsrVmxBasic = packed struct(u64) {
    /// VMCS revision identifier.
    vmcs_revision_id: u31,
    /// Reserved
    _zero: u1 = 0,
    /// VMXON region size.
    vmxon_region_size: u16,
    /// Reserved.
    _reserved1: u7,
    /// SDM Vol.3D Appendix A.5.
    true_control: bool,
    /// Reserved.
    _reserved2: u8,
};

/// IA32_VMX_EPT_VPID_CAP MSR.
pub const MsrVmxEptVpidCap = packed struct(u64) {
    ept_exec_only: bool,
    _reserved1: u5 = 0,
    ept_lv4: bool,
    ept_lv5: bool,
    ept_uc: bool,
    _reserved2: u5 = 0,
    ept_wb: bool,
    _reserved3: u1 = 0,
    ept_2m: bool,
    ept_1g: bool,
    _reserved4: u2 = 0,
    invept: bool,
    ept_dirty: bool,
    ept_advanced_exit: bool,
    shadow_stack: bool,
    _reserved5: u1 = 0,
    invept_single: bool,
    invept_all: bool,
    _reserved6: u5 = 0,
    invvpid: bool,
    _reserved7: u7 = 0,
    invvpid_individual: bool,
    invvpid_single: bool,
    invvpid_all: bool,
    invvpid_single_globals: bool,
    _reserved8: u4 = 0,
    hlat_prefix: u6,
    _reserved9: u10 = 0,
};

/// IA32_FEATURE_CONTROL MSR.
pub const MsrFeatureControl = packed struct(u64) {
    /// Lock bit.
    /// When set to true, further writes to this MSR causes #GP.
    /// Once the bit is set, it cannot be cleared until system reset.
    lock: bool,
    /// VMX in SMX (Safer Mode Extensions) operation.
    /// If set to false, VMXON in SMX causes #GP.
    vmx_in_smx: bool,
    /// VMX outside SMX operation.
    /// If set to false, VMXON outside SMX causes #GP.
    vmx_outside_smx: bool,
    /// Reserved.
    _reserved1: u5,
    /// Specify enabled functionality of the SYSENTER leaf function.
    senter_lfe: u7,
    /// SYSENTER global enable.
    senter_global_enable: bool,
    /// Reserved.
    _reserved2: u1,
    ///
    sgx_launch_control_enable: bool,
    ///
    sgx_global_enable: bool,
    /// Reserved.
    _reserved3: u1,
    lmce_on: bool,
    /// Reserved.
    _reserved4: u43,
};
