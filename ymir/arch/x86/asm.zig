//! This module provides a set of functions corresponding to x64 asm instructions.

const std = @import("std");

const ymir = @import("ymir");
const mem = ymir.mem;
const vmx = @import("vmx.zig");
const VmxError = vmx.VmxError;
const vmxerr = vmx.vmxtry;

pub inline fn inb(port: u16) u8 {
    return asm volatile (
        \\inb %[port], %[ret]
        : [ret] "={al}" (-> u8),
        : [port] "{dx}" (port),
    );
}

pub inline fn inw(port: u16) u8 {
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

pub inline fn lidt(idtr: u64) void {
    asm volatile (
        \\lidt (%[idtr])
        :
        : [idtr] "r" (idtr),
    );
}

pub inline fn lgdt(gdtr: u64) void {
    asm volatile (
        \\lgdt (%[gdtr])
        :
        : [gdtr] "r" (gdtr),
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

pub inline fn loadCr0(cr0: Cr0) void {
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

pub inline fn readCr2() Cr2 {
    var cr2: u64 = undefined;
    asm volatile (
        \\mov %%cr2, %[cr2]
        : [cr2] "=r" (cr2),
    );
    return cr2;
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

pub inline fn loadCr4(cr4: Cr4) void {
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

pub inline fn readEflags() FlagsRegister {
    return @bitCast(asm volatile (
        \\pushfq
        \\pop %[eflags]
        : [eflags] "=r" (-> u64),
    ));
}

pub inline fn writeEflags(eflags: FlagsRegister) void {
    asm volatile (
        \\push %[eflags]
        \\popfq
        :
        : [eflags] "r" (@as(u64, @bitCast(eflags))),
    );
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

pub inline fn readSegSelector(segment: Segment) u16 {
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

pub inline fn readSegLimit(selector: u32) u32 {
    return asm volatile (
        \\lsl %[selector], %[ret]
        : [ret] "=r" (-> u32),
        : [selector] "r" (selector),
    );
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

inline fn readDr7() u64 {
    return asm volatile (
        \\mov %%dr7, %[dr7]
        : [dr7] "=r" (-> u64),
    );
}

const CpuidRegisters = struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
};

pub fn cpuid(eax: u32) CpuidRegisters {
    var eax_ret: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    asm volatile (
        \\mov %[eax], %%eax
        \\cpuid
        \\mov %%eax, %[eax_ret]
        \\mov %%ebx, %[ebx]
        \\mov %%ecx, %[ecx]
        \\mov %%edx, %[edx]
        : [eax_ret] "=r" (eax_ret),
          [ebx] "=r" (ebx),
          [ecx] "=r" (ecx),
          [edx] "=r" (edx),
        : [eax] "r" (eax),
        : "rax", "rbx", "rcx", "rdx"
    );

    return .{
        .eax = eax_ret,
        .ebx = ebx,
        .ecx = ecx,
        .edx = edx,
    };
}

pub fn cpuidEcx(eax: u32, subEcx: u32) CpuidRegisters {
    var eax_ret: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    asm volatile (
        \\mov %[eax], %%eax
        \\mov %[subEcx], %%ecx
        \\cpuid
        \\mov %%eax, %[eax_ret]
        \\mov %%ebx, %[ebx]
        \\mov %%ecx, %[ecx]
        \\mov %%edx, %[edx]
        : [eax_ret] "=r" (eax_ret),
          [ebx] "=r" (ebx),
          [ecx] "=r" (ecx),
          [edx] "=r" (edx),
        : [eax] "r" (eax),
          [subEcx] "r" (subEcx),
        : "rax", "rbx", "rcx", "rdx"
    );

    return .{
        .eax = eax_ret,
        .ebx = ebx,
        .ecx = ecx,
        .edx = edx,
    };
}

pub fn readDebugRegister(dr: DebugRegister) u64 {
    var ret: u64 = undefined;
    switch (dr) {
        .dr0 => asm volatile ("mov %%dr0, %[ret]"
            : [ret] "=r" (ret),
        ),
        .dr1 => asm volatile ("mov %%dr1, %[ret]"
            : [ret] "=r" (ret),
        ),
        .dr2 => asm volatile ("mov %%dr2, %[ret]"
            : [ret] "=r" (ret),
        ),
        .dr3 => asm volatile ("mov %%dr3, %[ret]"
            : [ret] "=r" (ret),
        ),
        .dr6 => asm volatile ("mov %%dr6, %[ret]"
            : [ret] "=r" (ret),
        ),
        .dr7 => asm volatile ("mov %%dr7, %[ret]"
            : [ret] "=r" (ret),
        ),
    }
    return ret;
}

pub fn writeDebugRegister(dr: DebugRegister, value: u64) void {
    switch (dr) {
        .dr0 => asm volatile ("mov %[value], %%dr0"
            :
            : [value] "r" (value),
        ),
        .dr1 => asm volatile ("mov %[value], %%dr1"
            :
            : [value] "r" (value),
        ),
        .dr2 => asm volatile ("mov %[value], %%dr2"
            :
            : [value] "r" (value),
        ),
        .dr3 => asm volatile ("mov %[value], %%dr3"
            :
            : [value] "r" (value),
        ),
        .dr6 => asm volatile ("mov %[value], %%dr6"
            :
            : [value] "r" (value),
        ),
        .dr7 => asm volatile ("mov %[value], %%dr7"
            :
            : [value] "r" (value),
        ),
    }
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

    return (@as(u64, edx) << 32) | @as(u64, eax);
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

pub fn readMsrFeatureControl() MsrFeatureControl {
    const val = readMsr(Msr.feature_control);
    return @bitCast(val);
}

pub fn writeMsrFeatureControl(value: MsrFeatureControl) void {
    writeMsr(Msr.feature_control, @bitCast(value));
}

pub fn readMsrVmxBasic() MsrVmxBasic {
    const val = readMsr(Msr.vmx_basic);
    return @bitCast(val);
}

pub fn writeMsrVmxBasic(value: MsrVmxBasic) void {
    writeMsr(Msr.vmx_basic, @bitCast(value));
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

pub inline fn vmxoff() void {
    asm volatile (
        \\vmxoff
        ::: "cc");
}

/// Pause the CPU for a short period of time.
pub fn relax() void {
    asm volatile ("rep; nop");
}

/// MSR addresses.
pub const Msr = enum(u32) {
    /// IA32_FEATURE_CONTROL MSR.
    feature_control = 0x003A,
    /// IA32_SYSENTER_CS MSR. SDM Vol.3A Table 2-2.
    sysenter_cs = 0x174,
    /// IA32_SYSENTER_ESP MSR. SDM Vol.3A Table 2-2.
    sysenter_esp = 0x175,
    /// IA32_SYSENTER_EIP MSR. SDM Vol.3A Table 2-2.
    sysenter_eip = 0x176,
    /// IA32_MISC_ENABLE MSR.
    misc_enable = 0x1A0,
    /// IA32_PAT MSR.
    pat = 0x277,
    /// IA32_DEBUGCTL MSR. SDM Vol.4 Table 2-2.
    debugctl = 0x01D9,
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
    /// IA32_VMX_TRUE_PINBASED_CTLS MSR.
    vmx_true_pinbased_ctls = 0x048D,
    /// IA32_VMX_TRUE_PROCBASED_CTLS MSR.
    vmx_true_procbased_ctls = 0x048E,
    /// IA32_VMX_TRUE_EXIT_CTLS MSR.
    vmx_true_exit_ctls = 0x048F,
    /// IA32_VMX_TRUE_ENTRY_CTLS MSR.
    vmx_true_entry_ctls = 0x0490,

    /// IA32_FS_BASE MSR.
    fs_base = 0xC0000100,
    /// IA32_GS_BASE MSR.
    gs_base = 0xC0000101,
    /// IA32_EFER MSR.
    efer = 0xC0000080,
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
    sgx_launch_control_enable: bool,
    sgx_global_enable: bool,
    /// Reserved.
    _reserved3: u1,
    lmce_on: bool,
    /// Reserved.
    _reserved4: u43,
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

/// CR2 register. It contains VA of the last page fault.
pub const Cr2 = ymir.mem.Virt;

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
    /// Physical address extension.
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
    /// Reserved.
    _reserved: u1 = 0,
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

/// Debug register.
pub const DebugRegister = enum {
    /// DR0
    dr0,
    /// DR1
    dr1,
    /// DR2
    dr2,
    /// DR3
    dr3,
    /// DR6: Debug Status
    dr6,
    /// DR7: Debug Control
    dr7,
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
