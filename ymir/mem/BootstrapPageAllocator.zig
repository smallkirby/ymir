//! Page allocator for the very early bootstrapping stage.
//!
//! This allocator takes a memory map given by UEFI and allocate pages from usable region.
//! Allocated pages are recorded as marked so that you can get them later.
//! When more appropriate allocator becomes available,
//! you have to tell the pages are in use to the new allocator.
//! This allocator does not support deallocation.
//! This allocator requires that memory regions described by the memory map are directly mapped.

const std = @import("std");
const uefi = std.os.uefi;
const Allocator = std.mem.Allocator;
const SinglyLinkedList = std.SinglyLinkedList;
const FixedBufferAllocator = std.heap.FixedBufferAllocator;
const surtr = @import("surtr");
const MemoryMap = surtr.MemoryMap;
const MemoryDescriptorIterator = surtr.MemoryDescriptorIterator;

const ymir = @import("ymir");
const mem = ymir.mem;
const arch = ymir.arch;
const page_size = mem.page_size;

const PageAddr = u64;
const PageInUseList = SinglyLinkedList(PageAddr);

const Error = error{
    /// No usable memory region found.
    NoMemory,
    /// Internal memory is not available.
    NoInternalMemory,
};

/// Static buffer size in bytes for the allocator.
const buffer_size = page_size * 10;

/// Static buffer internally used by the allocator.
var buffer: [buffer_size]u8 = undefined;
/// Whether the allocator is initialized.
var initialized: bool = false;

/// Memory map provided by UEFI.
var map: MemoryMap = undefined;
/// Fixed buffer allocator used internally.
var fba = FixedBufferAllocator.init(buffer[0..]);
/// Allocator used internally.
const allocator = fba.allocator();
/// List of pages in use.
var page_inuse_list = PageInUseList{};
/// Spin lock.
var lock = ymir.spin.SpinLock{};

/// Initialize the allocator.
pub fn init(memory_map: MemoryMap) void {
    if (initialized) @panic("BootstrapPageAllocator is already initialized");

    map = memory_map;
    initialized = true;
}

/// Allocate a 4 KiB page from the usable region.
/// Note that this functions returns a physical address.
pub fn allocatePage() Error![*]align(page_size) u8 {
    if (!initialized) @panic("BootstrapPageAllocator is not initialized");

    const mask = lock.lockSaveIrq();
    defer lock.unlockRestoreIrq(mask);

    var desc_iter = MemoryDescriptorIterator.new(map);
    while (true) {
        const desc = desc_iter.next() orelse continue;
        if (!surtr.isUsableMemory(desc)) continue;

        // Page tables allocated by UEFI are in BootServicesData region.
        // To avoid overwriting them, skip the region.
        if (desc.type == .BootServicesData) continue;

        // Find available page.
        var current = desc.physical_start;
        const end = current + desc.number_of_pages * page_size;
        while (current < end) : (current += page_size) {
            if (current == 0) continue; // avoid using NULL page
            if (!isPageInuse(current)) {
                try markPageInuse(current);
                return @ptrFromInt(current);
            }
        }
    }

    return Error.NoMemory;
}

/// Get the first node of the list of allocated pages.
pub fn getAllocatedPages() ?*PageInUseList.Node {
    return page_inuse_list.first;
}

/// Deinitialize the allocator.
/// After calling this function, you cannot use the allocator.
pub fn deinit() void {
    if (!initialized) @panic("BootstrapPageAllocator is not initialized");
    initialized = false;
}

inline fn markPageInuse(page: PageAddr) Error!void {
    const node = allocator.create(PageInUseList.Node) catch return Error.NoInternalMemory;
    node.data = page;
    page_inuse_list.prepend(node);
}

fn isPageInuse(page: PageAddr) bool {
    var node = page_inuse_list.first;
    while (node != null) : (node = node.?.next) {
        if (node.?.data == page) return true;
    }
    return false;
}
