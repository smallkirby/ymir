//! This file defines structures shared among Surtr and Ymir.

const uefi = @import("std").os.uefi;

pub const surtr_magic: usize = 0xDEADBEEF_CAFEBABE;

/// Boot information.
/// This struct is passed from the bootloader to the kernel in Win64 calling convention.
pub const BootInfo = extern struct {
    /// Magic number to check if the boot info is valid.
    magic: usize = surtr_magic,
    memory_map: MemoryMap,
};

/// Memory map provided by UEFI.
pub const MemoryMap = extern struct {
    /// Total buffer size prepared to store the memory map.
    buffer_size: usize,
    /// Memory descriptors.
    descriptors: [*]uefi.tables.MemoryDescriptor,
    /// Total memory map size.
    map_size: usize,
    /// Map key used to check if the memory map has been changed.
    map_key: usize,
    /// Size in bytes of each memory descriptor.
    descriptor_size: usize,
    /// UEFI memory descriptor version.
    descriptor_version: u32,
};

/// Memory descriptor iterator.
pub const MemoryDescriptorIterator = struct {
    const Self = @This();
    const Md = uefi.tables.MemoryDescriptor;

    descriptors: [*]Md,
    current: *Md,
    descriptor_size: usize,
    total_size: usize,

    pub fn new(map: MemoryMap) Self {
        return MemoryDescriptorIterator{
            .descriptors = map.descriptors,
            .current = @ptrCast(map.descriptors),
            .descriptor_size = map.descriptor_size,
            .total_size = map.map_size,
        };
    }

    pub fn next(self: *Self) ?*Md {
        if (@intFromPtr(self.current) >= @intFromPtr(self.descriptors) + self.total_size) {
            return null;
        }
        const md = self.current;
        self.current = @ptrFromInt(@intFromPtr(self.current) + self.descriptor_size);
        return md;
    }
};
