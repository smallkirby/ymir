const std = @import("std");
const Allocator = std.mem.Allocator;
const surtr = @import("surtr");
const MemoryMap = surtr.MemoryMap;

pub const BootstrapPageAllocator = @import("mem/BootstrapPageAllocator.zig");
pub const page_allocator = Allocator{
    .ptr = &page_allocator_instance,
    .vtable = &pa.vtable,
};

const pa = @import("mem/PageAllocator.zig");
var page_allocator_instance = pa.PageAllocator.new_uninit();

/// Initialize the page allocator.
/// You MUST call this function before using `page_allocator`.
pub fn initPageAllocator(map: MemoryMap) void {
    page_allocator_instance.init(map);
}
