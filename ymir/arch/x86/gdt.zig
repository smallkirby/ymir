const std = @import("std");

const ymir = @import("ymir");
const Virt = ymir.mem.Virt;

const am = @import("asm.zig");

/// Maximum number of GDT entries.
const max_num_gdt = 0x10;

/// Global Descriptor Table.
var gdt: [max_num_gdt]SegmentDescriptor align(16) = [_]SegmentDescriptor{
    SegmentDescriptor.newNull(),
} ** max_num_gdt;
/// GDT Register.
var gdtr = GdtRegister{
    .limit = @sizeOf(@TypeOf(gdt)) - 1,
    .base = &gdt,
};

/// Index of the kernel data segment.
pub const kernel_ds_index: u16 = 0x01;
/// Index of the kernel code segment.
pub const kernel_cs_index: u16 = 0x02;
/// Index of the kernel TSS.
/// Note that TSS descriptor occupies two GDT entries.
pub const kernel_tss_index: u16 = 0x04;

/// Unused TSS segment.
const tssUnused: [4096]u8 align(4096) = [_]u8{0} ** 4096;

/// Initialize the GDT.
pub fn init() void {
    // Init GDT.
    gdtr.base = &gdt;

    gdt[kernel_cs_index] = SegmentDescriptor.new(
        true,
        false,
        true,
        0,
        std.math.maxInt(u20),
        0,
        .kbyte,
    );
    gdt[kernel_ds_index] = SegmentDescriptor.new(
        true,
        false,
        false,
        0,
        std.math.maxInt(u20),
        0,
        .kbyte,
    );

    am.lgdt(@intFromPtr(&gdtr));

    // Changing the entries in the GDT, or setting GDTR
    // does not automatically update the hidden(shadow) part.
    // To flush the changes, we need to set segment registers.
    loadKernelDs();
    loadKernelCs();

    // TSS is not used by Ymir. But we have to set it for VMX.
    setTss(@intFromPtr(&tssUnused));
}

/// Load the kernel data segment selector.
/// This function flushes the changes of DS in the GDT.
fn loadKernelDs() void {
    asm volatile (
        \\mov %[kernel_ds], %di
        \\mov %%di, %%ds
        \\mov %%di, %%es
        \\mov %%di, %%fs
        \\mov %%di, %%gs
        \\mov %%di, %%ss
        :
        : [kernel_ds] "n" (@as(u16, @bitCast(SegmentSelector{
            .rpl = 0,
            .index = kernel_ds_index,
          }))),
        : "di"
    );
}

/// Set the TSS.
fn setTss(tss: Virt) void {
    const desc = TssDescriptor.new(tss, std.math.maxInt(u20));
    @as(*TssDescriptor, @ptrCast(&gdt[kernel_tss_index])).* = desc;

    loadKernelTss();
}

/// Load the kernel code segment selector.
/// This function flushes the changes of CS in the GDT.
/// CS cannot be loaded directly by mov, so we use far-return.
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
        : [kernel_cs] "n" (@as(u16, @bitCast(SegmentSelector{
            .rpl = 0,
            .index = kernel_cs_index,
          }))),
    );
}

/// Load the kernel TSS selector to TR.
/// Not used in Ymir.
fn loadKernelTss() void {
    asm volatile (
        \\mov %[kernel_tss], %%di
        \\ltr %%di
        :
        : [kernel_tss] "n" (@as(u16, @bitCast(SegmentSelector{
            .rpl = 0,
            .index = kernel_tss_index,
          }))),
        : "di"
    );
}

/// Segment Descriptor Entry.
/// SDM Vol.3A 3.4.5
pub const SegmentDescriptor = packed struct(u64) {
    /// Lower 16 bits of the segment limit.
    limit_low: u16,
    /// Lower 24 bits of the base address.
    base_low: u24,

    /// Segment is accessed.
    /// You should set to true in case the descriptor is stored in the read-only pages.
    accessed: bool = true,
    /// Readable / Writable.
    /// For code segment, true means the segment is readable (write access is not allowed for CS).
    /// For data segment, true means the segment is writable (read access is always allowed for DS).
    rw: bool,
    /// Direction / Conforming.
    /// For code selectors, conforming bit. If set to 1, code in the segment can be executed from an equal or lower privilege level.
    /// For data selectors, direction bit. If set to 0, the segment grows up; if set to 1, the segment grows down.
    dc: bool,
    /// Executable.
    /// If set to true, code segment. If set to false, data segment.
    executable: bool,
    /// Descriptor type.
    desc_type: DescriptorType,
    /// Descriptor Privilege Level.
    dpl: u2,
    /// Segment present.
    present: bool = true,

    /// Upper 4 bits of the segment limit.
    limit_high: u4,
    /// Available for use by system software.
    avl: u1 = 0,
    /// 64-bit code segment.
    /// If set to true, the code segment contains native 64-bit code.
    /// For data segments, this bit must be cleared to 0.
    long: bool,
    /// Size flag.
    db: u1,
    /// Granularity.
    /// If set to .Byte, the segment limit is interpreted in byte units.
    /// Otherwise, the limit is interpreted in 4-KByte units.
    /// This field is ignored in 64-bit mode.
    granularity: Granularity,
    /// Upper 8 bits of the base address.
    base_high: u8,

    /// Create a null segment selector.
    pub fn newNull() SegmentDescriptor {
        return @bitCast(@as(u64, 0));
    }

    /// Create a new segment descriptor.
    pub fn new(
        rw: bool,
        dc: bool,
        executable: bool,
        base: u32,
        limit: u20,
        dpl: u2,
        granularity: Granularity,
    ) SegmentDescriptor {
        return SegmentDescriptor{
            .limit_low = @truncate(limit),
            .base_low = @truncate(base),
            .rw = rw,
            .dc = dc,
            .executable = executable,
            .desc_type = .code_data,
            .dpl = dpl,
            .present = true,
            .limit_high = @truncate(limit >> 16),
            .avl = 0,
            .long = executable,
            .db = @intFromBool(!executable),
            .granularity = granularity,
            .base_high = @truncate(base >> 24),
        };
    }
};

/// TSS Descriptor in 64-bit mode.
///
/// Note that the descriptor is 16 bytes long and occupies two GDT entries.
/// cf. SDM Vol.3A Figure 8-4.
const TssDescriptor = packed struct(u128) {
    /// Lower 16 bits of the segment limit.
    limit_low: u16,
    /// Lower 24 bits of the base address.
    base_low: u24,

    /// Type: TSS.
    type: u4 = 0b1001, // tss-avail
    /// Descriptor type: System.
    desc_type: DescriptorType = .system,
    /// Descriptor Privilege Level.
    dpl: u2 = 0,
    present: bool = true,

    /// Upper 4 bits of the segment limit.
    limit_high: u4,
    /// Available for use by system software.
    avl: u1 = 0,
    /// Reserved.
    long: bool = true,
    /// Size flag.
    db: u1 = 0,
    /// Granularity.
    granularity: Granularity = .kbyte,
    /// Upper 40 bits of the base address.
    base_high: u40,
    /// Reserved.
    _reserved: u32 = 0,

    /// Create a new 64-bit TSS descriptor.
    pub fn new(base: Virt, limit: u20) TssDescriptor {
        return TssDescriptor{
            .limit_low = @truncate(limit),
            .base_low = @truncate(base),
            .limit_high = @truncate(limit >> 16),
            .base_high = @truncate(base >> 24),
        };
    }
};

/// Descriptor Type.
pub const DescriptorType = enum(u1) {
    /// System Descriptor.
    /// Must be System for TSS.
    system = 0,
    /// Application Descriptor.
    code_data = 1,
};

/// Granularity of the descriptor.
pub const Granularity = enum(u1) {
    byte = 0,
    kbyte = 1,
};

/// Segment selector.
pub const SegmentSelector = packed struct(u16) {
    /// Requested Privilege Level.
    rpl: u2,
    /// Table Indicator.
    ti: u1 = 0,
    /// Index.
    index: u13,

    pub fn from(val: anytype) SegmentSelector {
        return @bitCast(@as(u16, @truncate(val)));
    }
};

/// GDTR.
const GdtRegister = packed struct {
    limit: u16,
    base: *[max_num_gdt]SegmentDescriptor,
};
