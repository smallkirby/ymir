/// List of CPUID functions set to EAX on CPUID instruction.
pub const functions = enum(u32) {
    pub const vendor_id = 0x0000_0000;
    pub const feature_information = 0x0000_0001;
    pub const structure_extended_feature_flags = 0x0000_0007;
};

pub const CpuidInformation = packed struct {
    ecx: FeatureInformationEcx,
    edx: FeatureInformationEdx,
};

/// CPUID Feature Flags bitfield.
/// This value is returned by the CPUID instruction in the ECX when EAX is 1.
pub const FeatureInformationEcx = packed struct(u32) {
    /// Streaming SIMD Extensions 3 (SSE3).
    sse3: bool = false,
    /// PCLMULQDQ.
    pclmulqdq: bool = false,
    /// 64-bit DS Area.
    dtes64: bool = false,
    /// MONITOR/MWAIT.
    monitor: bool = false,
    // CPL Qualified Debug Store.
    ds_cpl: bool = false,
    /// Virtual Machine Extensions.
    vmx: bool = false,
    /// Safer Mode Extensions.
    smx: bool = false,
    /// Enhanced Intel SpeedStep Technology.
    eist: bool = false,
    /// Thermal Monitor 2.
    tm2: bool = false,
    /// SSSE3 extensions.
    ssse3: bool = false,
    /// L1 context ID.
    cnxt_id: bool = false,
    /// IA32_DEBUG_INTERFACE.
    sdbg: bool = false,
    /// FMA extesions using YMM state.
    fma: bool = false,
    /// CMPXCHG16B available.
    cmpxchg16b: bool = false,
    /// xTPR update control.
    xtpr: bool = false,
    /// Perfmon and Debug Capability.
    pdcm: bool = false,
    /// Reserved.
    _reserved_0: bool = false,
    /// Process-context identifiers.
    pcid: bool = false,
    /// Ability to prevent data from memory mapped devices.
    dca: bool = false,
    /// SSE4.1 extensions.
    sse4_1: bool = false,
    /// SSE4.2 extensions.
    sse4_2: bool = false,
    /// x2APIC support.
    x2apic: bool = false,
    /// MOVBE instruction.
    movbe: bool = false,
    /// POPCNT instruction.
    popcnt: bool = false,
    /// Local APIC timer supports one-shot operation using TSC deadline.
    tsc_deadline: bool = false,
    /// AES instruction.
    aesni: bool = false,
    /// XSAVE/XRSTOR states.
    xsave: bool = false,
    /// OS has enabled XSETBV/XGETBV instructions to access XCR0.
    osxsave: bool = false,
    /// AVX.
    avx: bool = false,
    /// 16-bit floating-point conversion instructions.
    f16c: bool = false,
    /// RDRAND instruction.
    rdrand: bool = false,
    /// Not used.
    hypervisor: bool = false,
};

/// CPUID Feature Flags bitfield.
/// This value is returned by the CPUID instruction in the EDX when EAX is 1.
pub const FeatureInformationEdx = packed struct(u32) {
    /// x87 FPU.
    fpu: bool = false,
    /// Virtual 8086 mode enhancements.
    vme: bool = false,
    /// Debugging extensions.
    de: bool = false,
    /// Page Size Extension.
    pse: bool = false,
    /// Time Stamp Counter.
    tsc: bool = false,
    /// RDMSR and WRMSR instructions.
    msr: bool = false,
    /// Physical Address Extension.
    pae: bool = false,
    /// Machine Check Exception.
    mce: bool = false,
    /// CMPXCHG8B instruction.
    cx8: bool = false,
    /// APIC on-chip.
    apic: bool = false,
    /// Reserved.
    _reserved_0: bool = false,
    /// SYSENTER/SYSEXIT instructions.
    sep: bool = false,
    /// Memory Type Range Registers.
    mtrr: bool = false,
    /// Page Global Bit.
    pge: bool = false,
    /// Machine check architecture.
    mca: bool = false,
    /// Conditional move instructions.
    cmov: bool = false,
    /// Page attribute table.
    pat: bool = false,
    /// 36-bit Page Size Extension.
    pse36: bool = false,
    /// Processor serial number.
    psn: bool = false,
    /// CLFLUSH instruction.
    clfsh: bool = false,
    /// Reserved.
    _reserved_1: bool = false,
    /// Debug store.
    ds: bool = false,
    /// Thermal monitor and software controlled clock facilities.
    acpi: bool = false,
    /// Intel MMX Technology.
    mmx: bool = false,
    /// FXSAVE and FXRSTOR instructions.
    fxsr: bool = false,
    /// SSE extensions.
    sse: bool = false,
    /// SSE2 extensions.
    sse2: bool = false,
    /// Self snoop.
    ss: bool = false,
    /// Max APIC IDs reserved field.
    htt: bool = false,
    /// Thermal monitor.
    tm: bool = false,
    /// Reserved.
    _reserved_2: bool = false,
    /// Pending Break Enable.
    pbe: bool = false,
};

const FeatureInfoEbx = packed struct(u32) {
    clflush_line: u16,
    num_ids: u8,
    initial_apic_id: u8,
};

pub const ExtFeatureEbx0 = packed struct(u32) {
    fsgsbase: bool = false,
    tsc_adjust: bool = false,
    sgx: bool = false,
    bmi1: bool = false,
    hle: bool = false,
    avx2: bool = false,
    fdp: bool = false,
    smep: bool = false,
    bmi2: bool = false,
    erms: bool = false,
    invpcid: bool = false,
    rtm: bool = false,
    rdtm: bool = false,
    fpucsds: bool = false,
    mpx: bool = false,
    rdta: bool = false,
    avx512f: bool = false,
    avx512dq: bool = false,
    rdseed: bool = false,
    adx: bool = false,
    smap: bool = false,
    avx512ifma: bool = false,
    _reserved1: u1 = 0,
    clflushopt: bool = false,
    clwb: bool = false,
    pt: bool = false,
    avx512pf: bool = false,
    avx512er: bool = false,
    avx512cd: bool = false,
    sha: bool = false,
    avx512bw: bool = false,
    avx512vl: bool = false,
};
