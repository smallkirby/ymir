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

pub const PageAllocator = @import("mem/PageAllocator.zig");
/// Page allocator instance.
/// You should use this allocator via `page_allocator` interface.
pub var page_allocator_instance = PageAllocator.newUninit();

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

/// Current status.
var mapping_reconstructed = atomic.Value(bool).init(false);

/// Initialize the page allocator.
/// You MUST call this function before using `page_allocator`.
pub fn initPageAllocator(map: MemoryMap) void {
    page_allocator_instance.init(map);
}

/// Check if the address is canonical form.
/// If the architecture does not have a concept of canonical form, this function always returns true.
pub const isCanonical = switch (builtin.target.cpu.arch) {
    .x86_64 => arch.page.isCanonical,
    else => @compileError("Unsupported architecture."),
};

/// Translate the given virtual address to physical address.
/// This function just use simple calculation and does not walk page tables.
/// To do page table walk, use arch-specific functions.
pub fn virt2phys(addr: anytype) Phys {
    const value = switch (@typeInfo(@TypeOf(addr))) {
        .Int, .ComptimeInt => @as(u64, addr),
        .Pointer => @as(u64, @intFromPtr(addr)),
        else => @compileError("phys2virt: invalid type"),
    };
    return value; // TODO
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
    return if (!mapping_reconstructed.load(.acquire)) b: {
        break :b value;
    } else {
        @panic("phys2virt: unimplemented");
    };
}
