const std = @import("std");
const Allocator = std.mem.Allocator;
const surtr = @import("surtr");
const MemoryMap = surtr.MemoryMap;

const ymir = @import("ymir");

pub const BootstrapPageAllocator = @import("mem/BootstrapPageAllocator.zig");
pub const page_allocator = Allocator{
    .ptr = &page_allocator_instance,
    .vtable = &pa.vtable,
};
pub const general_allocator = Allocator{
    .ptr = &bin_allocator_instance,
    .vtable = &BinAllocator.vtable,
};

const pa = @import("mem/PageAllocator.zig");
var page_allocator_instance = pa.PageAllocator.newUninit();

const BinAllocator = @import("mem/BinAllocator.zig");
var bin_allocator_instance = BinAllocator.newUninit();

/// Physical address.
pub const Phys = u64;
/// Virtual address.
pub const Virt = u64;

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
pub fn virt2phys(addr: Virt) Phys {
    return if (addr < ymir.kernel_base) b: {
        // Direct mapping region.
        break :b addr - ymir.direct_map_base;
    } else b: {
        // Kernel image mapping region.
        break :b addr - ymir.kernel_base;
    };
}

/// Translate the given physical address to virtual address.
/// This function just use simple calculation and does not walk page tables.
/// To do page table walk, use arch-specific functions.
pub fn phys2virt(addr: Phys) Virt {
    return addr + ymir.direct_map_base;
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
    try testing.expectEqual(ymir.arch.page_size * 0x100, virt2phys(direct_map_base + ymir.arch.page_size * 0x100));
    try testing.expectEqual(kernel_base - direct_map_base - 1, virt2phys(kernel_base - 1));
    try testing.expectEqual(0, virt2phys(kernel_base));
    try testing.expectEqual(0x100000, virt2phys(kernel_base + 0x100000));

    // phys -> virt
    try testing.expectEqual(direct_map_base, phys2virt(0x0));
    try testing.expectEqual(direct_map_base + 0x100, phys2virt(0x100));
}
