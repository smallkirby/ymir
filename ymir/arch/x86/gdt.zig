const am = @import("asm.zig");

/// Maximum number of GDT entries.
const max_num_gdt = 0x10;
/// Global Descriptor Table.
var gdt: [max_num_gdt]SegmentDescriptor align(16) = [_]SegmentDescriptor{
    SegmentDescriptor.new_null(),
} ** max_num_gdt;
/// GDT Register.
var gdtr = GdtRegister{
    .limit = @sizeOf(@TypeOf(gdt)) - 1,
    // TODO: BUG: Zig v0.13.0. https://github.com/ziglang/zig/issues/17856
    // .base = &gdt,
    // This initialization invokes LLVM error.
    // As a workaround, we make `gdtr` mutable and initialize it in `init()`.
    .base = undefined,
};

/// Index of the null descriptor.
pub const null_desc_index: u16 = 0x00;
/// Index of the kernel data segment.
pub const kernel_ds_index: u16 = 0x01;
/// Index of the kernel code segment.
pub const kernel_cs_index: u16 = 0x02;

/// Initialize the GDT.
pub fn init() void {
    gdtr.base = &gdt;

    gdt[null_desc_index] = SegmentDescriptor.new_null();
    gdt[kernel_cs_index] = SegmentDescriptor.new(
        .CodeER,
        0,
        0xfffff,
        0,
        .KByte,
    );
    gdt[kernel_ds_index] = SegmentDescriptor.new(
        .DataRW,
        0,
        0xfffff,
        0,
        .KByte,
    );

    am.lgdt(@intFromPtr(&gdtr));

    // Changing the entries in the GDT, or setting GDTR
    // does not automatically update the hidden(shadow) part.
    // To flush the changes, we need to set segment registers.
    loadKernelDs();
    loadKernelCs();
}

/// Load the kernel data segment selector.
/// This function leads to flush the changes of DS in the GDT.
fn loadKernelDs() void {
    asm volatile (
        \\mov %[kernel_ds], %di
        \\mov %%di, %%ds
        \\mov %%di, %%es
        \\mov %%di, %%fs
        \\mov %%di, %%gs
        \\mov %%di, %%ss
        :
        : [kernel_ds] "n" (@as(u32, kernel_ds_index << 3)),
    );
}

/// Load the kernel code segment selector.
/// This function leads to flush the changes of CS in the GDT.
/// CS cannot be loaded directly by mov, so we use far return.
fn loadKernelCs() void {
    asm volatile (
        \\
        // Push CS
        \\mov %[kernel_cs], %%rax
        \\push %%rax
        // Push RIP
        \\leaq next(%%rip), %%rax
        \\pushq %%rax
        \\lretq
        \\next:
        \\
        :
        : [kernel_cs] "n" (@as(u32, kernel_cs_index << 3)),
    );
}

/// Segment Descriptor Entry.
/// SDM Vol.3A 3.4.5
pub const SegmentDescriptor = packed struct(u64) {
    limit_low: u16,
    base_low: u24,
    /// Segment type that specifies the kinds of access to the segment.
    /// The interpretation of this field depends on the descriptor type (CS/DS, system).
    segment_type: SegmentType,
    /// Descriptor type.
    desc_type: DescriptorType,
    /// DPL.
    dpl: u2,
    /// Segment present.
    present: bool = true,
    limit_high: u4,
    /// Available for use by system software. Not used by Zakuro-OS.
    avl: u1 = 0,
    /// 64-bit code segment.
    /// If set to true, the code segment contains native 64-bit code.
    /// For data segments, this bit must be cleared to 0.
    long: bool,
    db: u1,
    /// Granularity.
    /// If set to .Byte, the segment limit is interpreted in byte units.
    /// Otherwise, the limit is interpreted in 4-KByte units.
    /// This field is ignored in 64-bit mode.
    granularity: Granularity,
    base_high: u8,

    /// Create a null segment selector.
    pub fn new_null() SegmentDescriptor {
        return @bitCast(@as(u64, 0));
    }

    /// Create a new segment descriptor.
    pub fn new(
        segment_type: SegmentType,
        base: u32,
        limit: u20,
        dpl: u2,
        granularity: Granularity,
    ) SegmentDescriptor {
        const long = if (@intFromEnum(segment_type) >= 0b1000) true else false;
        return SegmentDescriptor{
            .limit_low = @truncate(limit),
            .base_low = @truncate(base),
            .segment_type = segment_type,
            .desc_type = .CodeOrData,
            .dpl = dpl,
            .present = true,
            .limit_high = @truncate(limit >> 16),
            .avl = 0,
            .long = long,
            .db = @intFromBool(!long),
            .granularity = granularity,
            .base_high = @truncate(base >> 24),
        };
    }
};

const DescriptorType = enum(u1) {
    /// System Descriptor.
    System = 0,
    /// Application Descriptor.
    CodeOrData = 1,
};

const Granularity = enum(u1) {
    Byte = 0,
    KByte = 1,
};

const SegmentType = enum(u4) {
    // R: Read-Only
    // W: Write
    // A: Accessed
    // E(Data): Execute
    // E(Code): Expand Down
    // C: Conforming

    DataR = 0,
    DataRA = 1,
    DataRW = 2,
    DataRWA = 3,
    DataRE = 4,
    DataRAE = 5,
    DataRWE = 6,
    DataRWAE = 7,

    CodeE = 8,
    CodeEA = 9,
    CodeER = 10,
    CodeERA = 11,
    CodeEC = 12,
    CodeECA = 13,
    CodeERC = 14,
    CodeERCA = 15,
};

const GdtRegister = packed struct {
    limit: u16,
    base: *[max_num_gdt]SegmentDescriptor,
};
