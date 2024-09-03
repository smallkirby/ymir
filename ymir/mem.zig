const std = @import("std");
const Allocator = std.mem.Allocator;
const surtr = @import("surtr");
const MemoryMap = surtr.MemoryMap;

const ymir = @import("ymir");

pub const BootstrapPageAllocator = @import("mem/BootstrapPageAllocator.zig");
/// Temporary page allocator.
/// This allocator should be used until the general page allocator is initialized.
pub const page_allocator = Allocator{
    .ptr = &page_allocator_instance,
    .vtable = &PageAllocator.vtable,
};
/// General memory allocator.
pub const general_allocator = Allocator{
    .ptr = &bin_allocator_instance,
    .vtable = &BinAllocator.vtable,
};

pub const PageAllocator = @import("mem/PageAllocator.zig");
/// Page allocator instance.
/// You should use this allocator via `page_allocator` interface.
pub var page_allocator_instance = PageAllocator.newUninit();

const BinAllocator = @import("mem/BinAllocator.zig");
var bin_allocator_instance = BinAllocator.newUninit();

/// Physical address.
pub const Phys = u64;
/// Virtual address.
pub const Virt = u64;

pub const kib = 1024;
pub const mib = 1024 * kib;
pub const gib = 1024 * mib;

pub const page_size: u64 = page_size_4k;
pub const page_shift: u64 = page_shift_4k;
pub const page_mask: u64 = page_mask_4k;

/// Size in bytes of a 4K page.
pub const page_size_4k = 4 * kib;
/// Size in bytes of a 2M page.
pub const page_size_2mb = page_size_4k << 9;
/// Size in bytes of a 1G page.
pub const page_size_1gb = page_size_2mb << 9;
/// Shift in bits for a 4K page.
pub const page_shift_4k = 12;
/// Shift in bits for a 2M page.
pub const page_shift_2mb = 21;
/// Shift in bits for a 1G page.
pub const page_shift_1gb = 30;
/// Mask for a 4K page.
pub const page_mask_4k: u64 = page_size_4k - 1;
/// Mask for a 2M page.
pub const page_mask_2mb: u64 = page_size_2mb - 1;
/// Mask for a 1G page.
pub const page_mask_1gb: u64 = page_size_1gb - 1;

/// Initialize the page allocator.
/// You MUST call this function before using `page_allocator`.
pub fn initPageAllocator(map: MemoryMap) void {
    page_allocator_instance.init(map);
}

/// Initialize the general allocator.
/// You mUST call this function before using `general_allocator`.
pub fn initGeneralAllocator() void {
    bin_allocator_instance.init(page_allocator);
}

/// Translate the given virtual address to physical address.
/// This function just use simple calculation and does not walk page tables.
/// To do page table walk, use arch-specific functions.
pub fn virt2phys(addr: anytype) Phys {
    const value = switch (@typeInfo(@TypeOf(addr))) {
        .Int, .ComptimeInt => @as(u64, addr),
        .Pointer => @as(u64, @intFromPtr(addr)),
        else => @compileError("phys2virt: invalid type"),
    };
    return if (value < ymir.kernel_base) b: {
        // Direct mapping region.
        break :b value - ymir.direct_map_base;
    } else b: {
        // Kernel image mapping region.
        break :b value - ymir.kernel_base;
    };
}

/// Translate the given physical address to virtual address.
/// This function just use simple calculation and does not walk page tables.
/// To do page table walk, use arch-specific functions.
pub fn phys2virt(addr: anytype) Virt {
    const value = switch (@typeInfo(@TypeOf(addr))) {
        .Int, .ComptimeInt => @as(u64, addr),
        .Pointer => @as(u64, @intFromPtr(addr)),
        else => @compileError("phys2virt: invalid type"),
    };
    return value + ymir.direct_map_base;
}

// ========================================

const testing = std.testing;

test {
    testing.refAllDeclsRecursive(@This());
}

test "address translation" {
    const direct_map_base = ymir.direct_map_base;
    const kernel_base = ymir.kernel_base;

    // virt -> phys
    try testing.expectEqual(0x0, virt2phys(direct_map_base));
    try testing.expectEqual(0x100, virt2phys(direct_map_base + 0x100));
    try testing.expectEqual(page_size * 0x100, virt2phys(direct_map_base + page_size * 0x100));
    try testing.expectEqual(kernel_base - direct_map_base - 1, virt2phys(kernel_base - 1));
    try testing.expectEqual(0, virt2phys(kernel_base));
    try testing.expectEqual(0x100000, virt2phys(kernel_base + 0x100000));

    // phys -> virt
    try testing.expectEqual(direct_map_base, phys2virt(0x0));
    try testing.expectEqual(direct_map_base + 0x100, phys2virt(0x100));
}
