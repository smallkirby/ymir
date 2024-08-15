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

const pa = @import("mem/PageAllocator.zig");
var page_allocator_instance = pa.PageAllocator.new_uninit();

/// Physical address.
pub const Phys = u64;
/// Virtual address.
pub const Virt = u64;

/// Initialize the page allocator.
/// You MUST call this function before using `page_allocator`.
pub fn initPageAllocator(map: MemoryMap) void {
    page_allocator_instance.init(map);
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
    return if (addr < ymir.kernel_base) b: {
        // Direct mapping region.
        break :b addr + ymir.direct_map_base;
    } else b: {
        // Kernel image mapping region.
        break :b addr + ymir.kernel_base;
    };
}
