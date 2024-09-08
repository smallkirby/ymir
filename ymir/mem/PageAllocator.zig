//! Page allocator.
//!
//! This allocator can be used after the necessary structures (eg. GDT, Page Tables)
//! are copied to ymir region frmo surtr region.
//! This allocator is initialized using BootstrapPageAllocator.
//!
//! This allocator allocates pages from direct map region.
//! Therefore, returned pages are ensured to be physically contiguous.

const std = @import("std");
const log = std.log.scoped(.pa);
const uefi = std.os.uefi;
const Allocator = std.mem.Allocator;
const surtr = @import("surtr");
const MemoryMap = surtr.MemoryMap;
const MemoryDescriptorIterator = surtr.MemoryDescriptorIterator;
const BootstrapPageAllocator = @import("BootstrapPageAllocator.zig");

const ymir = @import("ymir");
const mem = ymir.mem;
const spin = ymir.spin;
const arch = ymir.arch;
const p2v = ymir.mem.phys2virt;
const v2p = ymir.mem.virt2phys;
const Phys = ymir.mem.Phys;
const Virt = ymir.mem.Virt;
const page_size = mem.page_size;
const page_mask = mem.page_mask;
const kib = mem.kib;
const mib = mem.mib;
const gib = mem.gib;

pub const vtable = Allocator.VTable{
    .alloc = allocate,
    .free = free,
    .resize = resize,
};

/// Physical page frame ID.
const FrameId = u64;
/// Bytes per page frame.
const bytes_per_frame = 4 * kib;

const Self = @This();
const PageAllocator = Self;

/// Maximum physical memory size in bytes that can be managed by this allocator.
const max_physical_size = 128 * gib;
/// Maximum page frame count.
const frame_count = max_physical_size / 4096;

/// Single unit of bitmap line.
const MapLineType = u64;
/// Bits per map line.
const bits_per_mapline = @sizeOf(MapLineType) * 8;
/// Number of map lines.
const num_maplines = frame_count / bits_per_mapline;
/// Bitmap type.
const BitMap = [num_maplines]MapLineType;

/// First frame ID.
/// Frame ID 0 is reserved.
frame_begin: FrameId = 1,
/// First frame ID that is not managed by this allocator.
frame_end: FrameId,

/// Bitmap to manage page frames.
bitmap: BitMap = undefined,
/// Spin lock.
lock: spin.SpinLock = spin.SpinLock{},

/// Instantiate an uninitialized PageAllocator.
/// Returned instance must be initialized by calling `init`.
pub fn newUninit() Self {
    return Self{
        .frame_end = undefined,
        .bitmap = undefined,
    };
}

/// Initialize the allocator.
/// This function MUST be called before the direct mapping w/ offset 0x0 is unmapped.
pub fn init(self: *PageAllocator, map: MemoryMap) void {
    self.lock.lockDisableIrq();
    defer self.lock.unlockEnableIrq();

    var avail_end: Phys = 0;

    // Scan memory map and mark usable regions.
    var desc_iter = MemoryDescriptorIterator.new(map);
    while (true) {
        const desc = desc_iter.next() orelse break;
        if (desc.type == .ReservedMemoryType) continue;

        // Mark holes between regions as allocated (used).
        if (avail_end < desc.physical_start) {
            self.markAllocated(phys2frame(avail_end), desc.number_of_pages);
        }
        // Mark the region described by the descriptor as used or unused.
        const phys_end = desc.physical_start + desc.number_of_pages * page_size;
        if (surtr.isUsableMemory(desc)) {
            avail_end = phys_end;
            self.markNotUsed(phys2frame(desc.physical_start), desc.number_of_pages);
        } else {
            self.markAllocated(phys2frame(desc.physical_start), desc.number_of_pages);
        }

        self.frame_end = phys2frame(avail_end);
    }

    // Mark pages allocated by BootstrapPageAllocator as used.
    var inuse_page_node = BootstrapPageAllocator.getAllocatedPages();
    while (inuse_page_node != null) : (inuse_page_node = inuse_page_node.?.next) {
        const phys = inuse_page_node.?.data;
        self.markAllocated(phys2frame(phys), 1);
    }

    // Finalize BootstrapPageAllocator.
    BootstrapPageAllocator.deinit();
}

fn markAllocated(self: *Self, frame: FrameId, num_frames: usize) void {
    for (0..num_frames) |i| {
        self.set(frame + i, .used);
    }
}

fn markNotUsed(self: *Self, frame: FrameId, num_frames: usize) void {
    for (0..num_frames) |i| {
        self.set(frame + i, .unused);
    }
}

/// Page frame status.
const Status = enum(u1) {
    /// Page frame is in use.
    used = 0,
    /// Page frame is unused.
    unused = 1,

    pub inline fn from(boolean: bool) Status {
        return if (boolean) .used else .unused;
    }
};

fn get(self: *Self, frame: FrameId) Status {
    const line_index = frame / bits_per_mapline;
    const bit_index: u6 = @truncate(frame % bits_per_mapline);
    return Status.from(self.bitmap[line_index] & (@as(MapLineType, 1) << bit_index) != 0);
}

fn set(self: *Self, frame: FrameId, status: Status) void {
    const line_index = frame / bits_per_mapline;
    const bit_index: u6 = @truncate(frame % bits_per_mapline);
    switch (status) {
        .used => self.bitmap[line_index] |= (@as(MapLineType, 1) << bit_index),
        .unused => self.bitmap[line_index] &= ~(@as(MapLineType, 1) << bit_index),
    }
}

/// Allocate physically contiguous and aligned pages.
pub fn allocPages(self: *PageAllocator, num_pages: usize, align_size: usize) ?[]u8 {
    self.lock.lockDisableIrq();
    defer self.lock.unlockEnableIrq();

    if (align_size % page_size != 0) {
        log.err("Invalid alignment size: {}", .{align_size});
        return null;
    }

    const num_frames = num_pages;
    const align_frame = (align_size + page_size - 1) / page_size;
    var start_frame = align_frame;

    while (true) {
        var i: usize = 0;
        while (i < num_frames) : (i += 1) {
            if (start_frame + i >= self.frame_end) return null;
            if (self.get(start_frame + i) == .used) break;
        }
        if (i == num_frames) {
            self.markAllocated(start_frame, num_frames);
            const virt_addr: [*]u8 = @ptrFromInt(p2v(frame2phys(start_frame)));
            return virt_addr[0 .. num_pages * page_size];
        }

        start_frame += align_frame;
    }
}

fn allocate(ctx: *anyopaque, n: usize, _: u8, _: usize) ?[*]u8 {
    // NOTE: 3rd argument (`ptr_align`) can be safely ignored for the page allocator
    //  because the allocator always returns a page-aligned address
    //  and Zig does not assumes an align larger than a page size is not requested for Allocator interface.

    const self: *PageAllocator = @alignCast(@ptrCast(ctx));
    self.lock.lockDisableIrq();
    defer self.lock.unlockEnableIrq();

    const num_frames = (n + page_size - 1) / page_size;
    var start_frame = self.frame_begin;

    while (true) {
        var i: usize = 0;
        while (i < num_frames) : (i += 1) {
            if (start_frame + i >= self.frame_end) return null;
            if (self.get(start_frame + i) == .used) break;
        }
        if (i == num_frames) {
            self.markAllocated(start_frame, num_frames);
            return @ptrFromInt(p2v(frame2phys(start_frame)));
        }

        start_frame += i + 1;
    }
}

fn free(ctx: *anyopaque, slice: []u8, _: u8, _: usize) void {
    // NOTE: 3rd argument (`ptr_align`) can be safely ignored for the page allocator.
    //  See the comment in `allocate` function.

    const self: *PageAllocator = @alignCast(@ptrCast(ctx));
    self.lock.lockDisableIrq();
    defer self.lock.unlockEnableIrq();

    const num_frames = (slice.len + page_size - 1) / page_size;
    const start_frame_vaddr: Virt = @intFromPtr(slice.ptr) & ~page_mask;
    const start_frame = phys2frame(v2p(start_frame_vaddr));
    self.markNotUsed(start_frame, num_frames);
}

fn resize(_: *anyopaque, _: []u8, _: u8, _: usize, _: usize) bool {
    @panic("PageAllocator does not support resizing");
}

inline fn phys2frame(phys: Phys) FrameId {
    return phys / bytes_per_frame;
}

inline fn frame2phys(frame: FrameId) Phys {
    return frame * bytes_per_frame;
}
