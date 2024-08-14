//! Page allocator.
//!
//! This allocator can be used after the necessary structures (eg. GDT, Page Tables)
//! are copied to ymir region frmo surtr region.

const std = @import("std");
const log = std.log.scoped(.pa);
const uefi = std.os.uefi;
const Allocator = std.mem.Allocator;
const surtr = @import("surtr");
const MemoryMap = surtr.MemoryMap;
const MemoryDescriptorIterator = surtr.MemoryDescriptorIterator;
const BootstrapPageAllocator = @import("BootstrapPageAllocator.zig");

const ymir = @import("ymir");
const arch = ymir.arch;
const p2v = arch.page.translateRev;
const v2p = arch.page.translate;

const kib = 1024;
const mib = 1024 * kib;
const gib = 1024 * mib;

pub const vtable = Allocator.VTable{
    .alloc = allocate,
    .free = free,
    .resize = resize,
};

/// Physical page frame ID.
const FrameId = u64;
/// Bytes per page frame.
const bytes_per_frame = 4 * kib;

pub const PageAllocator = struct {
    const Self = @This();

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

    /// Instantiate an uninitialized PageAllocator.
    /// Returned instance must be initialized by calling `init`.
    pub fn new_uninit() Self {
        return Self{
            .frame_end = undefined,
            .bitmap = undefined,
        };
    }

    /// Initialize the allocator.
    pub fn init(self: *PageAllocator, map: MemoryMap) void {
        var avail_end: u64 = 0;

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
            const phys_end = desc.physical_start + desc.number_of_pages * arch.page_size;
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

    inline fn phys2frame(phys: u64) FrameId {
        return phys / bytes_per_frame;
    }
};

// TODO: log2_align, ra
fn allocate(ctx: *anyopaque, n: usize, log2_align: u8, ra: usize) ?[*]u8 {
    _ = log2_align;
    _ = ra;

    const self: *PageAllocator = @alignCast(@ptrCast(ctx));

    const num_frames = (n + arch.page_size - 1) / arch.page_size;
    var start_frame = self.frame_begin;

    while (true) {
        var i: usize = 0;
        while (i < num_frames) : (i += 1) {
            if (start_frame + i >= self.frame_end) return null;
            if (self.get(start_frame + i) == .used) break;
        }
        if (i == num_frames) {
            self.markAllocated(start_frame, num_frames);
            return @ptrFromInt(p2v(start_frame * bytes_per_frame));
        }

        start_frame += i + 1;
    }
}

// TODO: log2_buf_align, return_address
fn free(ctx: *anyopaque, slice: []u8, log2_buf_align: u8, return_address: usize) void {
    _ = log2_buf_align;
    _ = return_address;

    const self: *PageAllocator = @alignCast(@ptrCast(ctx));

    const num_frames = (slice.len + arch.page_size - 1) / arch.page_size;
    const start_frame_vaddr: u64 = @intFromPtr(slice.ptr) & ~arch.page_mask;
    const start_frame = v2p(start_frame_vaddr) / bytes_per_frame;
    self.markNotUsed(start_frame, num_frames);
}

fn resize(_: *anyopaque, _: []u8, _: u8, _: usize, _: usize) bool {
    @panic("PageAllocator does not support resizing");
}
