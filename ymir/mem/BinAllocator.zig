//! General purpose allocator.

const std = @import("std");
const Allocator = std.mem.Allocator;

const Self = @This();

pub const vtable = Allocator.VTable{
    .alloc = allocate,
    .free = free,
    .resize = resize,
};

const bin_sizes = [_]usize{
    0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800,
};

comptime {
    if (bin_sizes[0] < @sizeOf(ChunkMetaNode)) {
        @compileError("The smallest bin size is smaller than the size of ChunkMetaNode");
    }
    if (bin_sizes[bin_sizes.len - 1] > 4096) {
        @compileError("The largest bin size exceeds a 4KiB page size");
    }
}

/// Backing page allocator.
page_allocator: Allocator,
/// Heads of the chunk lists.
list_heads: [bin_sizes.len]ChunkMetaPointer,

/// Get a instance of BinAllocator without initialization.
pub fn newUninit() Self {
    return Self{
        .page_allocator = undefined,
        .list_heads = undefined,
    };
}

/// Initialize the BinAllocator.
pub fn init(self: *Self, page_allocator: Allocator) void {
    self.page_allocator = page_allocator;
    @memset(self.list_heads[0..self.list_heads.len], null);
}

/// Get the bin index for the given size.
/// If the size exceeds the largest bin size, return null.
fn binIndex(size: usize) ?usize {
    for (bin_sizes, 0..) |bin_size, i| {
        if (size <= bin_size) {
            return i;
        }
    }
    return null;
}

fn allocFromBin(self: *Self, bin_index: usize) ?[*]u8 {
    if (self.list_heads[bin_index] == null) {
        initBinPage(self, bin_index) orelse return null;
    }
    return @ptrCast(pop(&self.list_heads[bin_index]));
}

fn freeToBin(self: *Self, bin_index: usize, ptr: [*]u8) void {
    const chunk: *ChunkMetaNode = @alignCast(@ptrCast(ptr));
    push(&self.list_heads[bin_index], chunk);
}

fn initBinPage(self: *Self, bin_index: usize) ?void {
    const new_page = self.page_allocator.alloc(u8, 4096) catch return null;
    const bin_size = bin_sizes[bin_index];

    var i: usize = 4096 / bin_size - 1;
    while (true) : (i -= 1) {
        const chunk: *ChunkMetaNode = @ptrFromInt(@intFromPtr(new_page.ptr) + i * bin_size);
        push(&self.list_heads[bin_index], chunk);

        if (i == 0) break;
    }
}

fn push(list_head: *ChunkMetaPointer, node: *ChunkMetaNode) void {
    if (list_head.*) |next| {
        node.next = next;
        list_head.* = node;
    } else {
        list_head.* = node;
        node.next = null;
    }
}

fn pop(list_head: *ChunkMetaPointer) *ChunkMetaNode {
    if (list_head.*) |first| {
        list_head.* = first.next;
        return first;
    } else {
        @panic("BinAllocator: pop from empty list");
    }
}

fn allocate(ctx: *anyopaque, n: usize, log2_align: u8, _: usize) ?[*]u8 {
    const self: *Self = @alignCast(@ptrCast(ctx));

    const ptr_align = @as(usize, 1) << @as(Allocator.Log2Align, @intCast(log2_align));
    const bin_index = binIndex(@max(ptr_align, n));

    if (bin_index) |index| {
        return self.allocFromBin(index);
    } else {
        // Requested size including alignment exceeds a 4KiB page size.
        // Zig's Allocator does not assume an align larger than a page size.
        // So we can safely ignore the alignment, ang just return for requested size.
        const ret = self.page_allocator.alloc(u8, n) catch return null;
        return @ptrCast(ret.ptr);
    }
}

fn free(ctx: *anyopaque, slice: []u8, log2_align: u8, _: usize) void {
    const self: *Self = @alignCast(@ptrCast(ctx));

    const ptr_align = @as(usize, 1) << @as(Allocator.Log2Align, @intCast(log2_align));
    const bin_index = binIndex(@max(ptr_align, slice.len));

    if (bin_index) |index| {
        self.freeToBin(index, @ptrCast(slice.ptr));
    } else {
        self.page_allocator.free(slice);
    }
}

fn resize(_: *anyopaque, _: []u8, _: u8, _: usize, _: usize) bool {
    @panic("BinAllocator does not support resizing");
}

/// Metadata of free chunk.
/// NOTE: In zig, we don't need to store the size of the in-use chunk.
const ChunkMetaNode = packed struct {
    next: ChunkMetaPointer = null,
};
const ChunkMetaPointer = ?*ChunkMetaNode;

// ========================================

const testing = std.testing;

test {
    testing.refAllDeclsRecursive(@This());
}

fn getTestingAllocator() Allocator {
    var bin_allocator_instance // we don't want an error check
        = std.heap.page_allocator.create(Self) catch unreachable;
    bin_allocator_instance.init(std.heap.page_allocator);

    return Allocator{
        .ptr = bin_allocator_instance,
        .vtable = &vtable,
    };
}

test "allocation order" {
    const ba = getTestingAllocator();

    // Chunks are allocated in ascending order.
    // The distance between the chunks is the same as the chunk size.
    const sizes = bin_sizes;
    for (sizes) |size| {
        var prev = try ba.alloc(u8, size);
        for (0..4096 / size - 1) |_| {
            const ptr = try ba.alloc(u8, size);
            try testing.expectEqual(size, @intFromPtr(ptr.ptr) - @intFromPtr(prev.ptr));
            prev = ptr;
        }
    }

    // Most recently freed chunk is allocated first.
    for (0..3) |_| _ = try ba.alloc(u8, 0x10);
    const ptr = try ba.alloc(u8, 0x10);
    for (0..3) |_| _ = try ba.alloc(u8, 0x10);
    ba.free(ptr);
    try testing.expectEqual(ptr, try ba.alloc(u8, 0x10));
}

test "allocation size" {
    const ba = getTestingAllocator();

    for (0..5000) |size| {
        const ptr = try ba.alloc(u8, size);
        try testing.expectEqual(size, ptr.len);
        ba.free(ptr);
    }
}

test "allocation exceeds page size" {
    const ba = getTestingAllocator();

    for (0..4096 / 0x20 + 8) |_| {
        const ptr = try ba.alloc(u8, 0x20);
        try testing.expectEqual(0x20, ptr.len);
    }
}

test "no mitigation agains double free" {
    const ba = getTestingAllocator();

    const ptr = try ba.alloc(u8, 0x20);
    ba.free(ptr);
    ba.free(ptr);
}
