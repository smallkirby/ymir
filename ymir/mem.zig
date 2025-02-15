//! Ymir has three memory regions.
//! - Initial direct mapping
//! - Direct mapping
//! - Kernel text mapping
//!
//! Initial direct mapping is used until page tables provided by UEFI are reconstructed.
//! It directly maps entire VA to PA without offset.
//! After the UEFI page tables are cloned and new tables are created, the second direct mapping is used.
//! The direct mapping maps entire memory with offset of `ymir.direct_map_base`.
//! At the same time, kernel text is mapped to `ymir.kernel_base` as the ELF image requests.
//! That means the kernel image is mapped to two VA: direct mapping and kernel text mapping.
//! Page allocator allocates pages from the direct mapping region.
//!
//! While the initial direct mapping is in use, VA is equal to PA.
//! After the initial direct mapping is discarded, VA-to-PA translation is done by simple calculation.
//! If the VA is in the direct mapping region, the PA can be calculated by subtracting the base address.
//! If the VA is in the kernel text mapping region, the PA can be calculated by subtracting the kernel base.

const std = @import("std");
const builtin = @import("builtin");
const atomic = std.atomic;
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.mem);
const surtr = @import("surtr");
const MemoryMap = surtr.MemoryMap;

const ymir = @import("ymir");
const arch = ymir.arch;

/// Page allocator.
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

/// Status of the page remap.
var mapping_reconstructed = atomic.Value(bool).init(false);

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

/// Check if the address is canonical form.
/// If the architecture does not have a concept of canonical form, this function always returns true.
pub const isCanonical = switch (builtin.target.cpu.arch) {
    .x86_64 => arch.page.isCanonical,
    else => @compileError("Unsupported architecture."),
};

/// Discard the initial direct mapping and construct Ymir's page tables.
/// It creates two mappings: direct mapping and kernel text mapping.
/// For the detail, refer to this module documentation.
pub fn reconstructMapping(allocator: Allocator) !void {
    arch.disableIntr();
    defer arch.enableIntr();

    try arch.page.reconstruct(allocator);

    // Remap pages.
    mapping_reconstructed.store(true, .release);

    // Notify that BootServicesData region is no longer needed.
    page_allocator_instance.discardBootService();
}

/// Translate the given virtual address to physical address.
/// This function just use simple calculation and does not walk page tables.
/// To do page table walk, use arch-specific functions.
pub fn virt2phys(addr: anytype) Phys {
    const value = switch (@typeInfo(@TypeOf(addr))) {
        .int, .comptime_int => @as(u64, addr),
        .pointer => @as(u64, @intFromPtr(addr)),
        else => @compileError("phys2virt: invalid type"),
    };
    return if (!mapping_reconstructed.load(.acquire)) b: {
        break :b value;
    } else if (value < ymir.kernel_base) b: {
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
        .int, .comptime_int => @as(u64, addr),
        .pointer => @as(u64, @intFromPtr(addr)),
        else => @compileError("phys2virt: invalid type"),
    };
    return if (!mapping_reconstructed.load(.acquire)) b: {
        break :b value;
    } else b: {
        break :b value + ymir.direct_map_base;
    };
}

// ========================================

const testing = std.testing;

test {
    testing.refAllDeclsRecursive(@This());
}

test "address translation" {
    const direct_map_base = ymir.direct_map_base;
    const kernel_base = ymir.kernel_base;

    mapping_reconstructed.store(true, .release);

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
