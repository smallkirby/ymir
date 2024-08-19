//! This module provides a set of functions corresponding to x64 asm instructions.

const ymir = @import("ymir");
const mem = ymir.mem;

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

pub inline fn loadCr0(cr0: u64) void {
    asm volatile (
        \\mov %[cr0], %%cr0
        :
        : [cr0] "r" (cr0),
    );
}

pub inline fn readCr0() u64 {
    var cr0: u64 = undefined;
    asm volatile (
        \\mov %%cr0, %[cr0]
        : [cr0] "=r" (cr0),
    );
    return cr0;
}

pub inline fn readCr2() u64 {
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
    var cr3: u64 = undefined;
    asm volatile (
        \\mov %%cr3, %[cr3]
        : [cr3] "=r" (cr3),
    );
    return cr3;
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
    var eflags: u64 = undefined;
    asm volatile (
        \\pushfq
        \\pop %[eflags]
        : [eflags] "=r" (eflags),
    );
    return @bitCast(eflags);
}

pub inline fn writeEflags(eflags: FlagsRegister) void {
    asm volatile (
        \\push %[eflags]
        \\popfq
        :
        : [eflags] "r" (@as(u64, @bitCast(eflags))),
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

pub inline fn vmxon(vmxon_region: mem.Phys) FlagsRegister {
    var rflags: u64 = undefined;
    asm volatile (
        \\vmxon (%[vmxon_phys])
        \\pushf
        \\popq %[rflags]
        : [rflags] "=r" (rflags),
        : [vmxon_phys] "r" (&vmxon_region),
        : "cc", "memory"
    );
    return @bitCast(rflags);
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

pub const Msr = enum(u32) {
    /// IA32_FEATURE_CONTROL MSR.
    feature_control = 0x003A,
    /// IA32_VMX_BASIC MSR.
    vmx_basic = 0x0480,
    /// IA32_VMX_CR0_FIXED0 MSR.
    vmx_cr0_fixed0 = 0x0486,
    /// IA32_VMX_CR0_FIXED1 MSR.
    vmx_cr0_fixed1 = 0x0487,
    /// IA32_VMX_CR4_FIXED0 MSR.
    vmx_cr4_fixed0 = 0x0488,
    /// IA32_VMX_CR4_FIXED1 MSR.
    vmx_cr4_fixed1 = 0x0489,
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

pub const MsrVmxBasic = packed struct(u64) {
    /// VMCS revision identifier.
    vmcs_revision_id: u31,
    /// Reserved
    _zero: u1 = 0,
    /// VMXON region size.
    vmxon_region_size: u16,
    /// Reserved.
    _reserved: u16,
};

pub const FlagsRegister = packed struct(u64) {
    /// Carry flag.
    cf: bool,
    /// Reserved.
    _reserved1: u1,
    /// Parity flag.
    pf: bool,
    /// Reserved.
    _reserved2: u1,
    /// Auxiliary carry flag.
    af: bool,
    /// Reserved.
    _reserved3: u1,
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
    /// Reserved.
    md: bool,
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
    _reserved4: u8,
    /// Reserved.
    aes: bool,
    /// Alternate instruction set enabled.
    ai: bool,
    /// Reserved.
    _reserved: u32,
};

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
