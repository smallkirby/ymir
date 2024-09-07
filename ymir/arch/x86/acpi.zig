const std = @import("std");
const log = std.log.scoped(.acpi);

const ymir = @import("ymir");
const mem = ymir.mem;

const AcpiError = error{
    InvalidSignature,
    InvalidRevision,
    InvalidChecksum,
    InvalidExtendedChecksum,
};

/// Pointer to FADT.
/// You MUST call `init()` before using this pointer.
var fadt: ?*Fadt = null;
/// RSDP.
var rsdp_addr: ?mem.Phys = null;
/// XSDT
var xsdt_addr: ?mem.Phys = null;

pub fn getRsdpPhys() ?mem.Phys {
    return rsdp_addr;
}

pub fn getXsdtPhys() ?mem.Phys {
    return xsdt_addr;
}

/// Initialize ACPI.
pub fn init(_rsdp: *align(1) Rsdp) void {
    // Copy RSDP to the stack, because the original address of RSDP might not be correctly aligned.
    var rsdp: Rsdp = undefined;
    @memcpy(std.mem.asBytes(&rsdp), std.mem.asBytes(_rsdp));

    rsdp.valid() catch |e| switch (e) {
        AcpiError.InvalidSignature => @panic("Invalid RSDP signature."),
        AcpiError.InvalidRevision => @panic("Invalid RSDP revision."),
        AcpiError.InvalidChecksum => @panic("Invalid RSDP checksum."),
        AcpiError.InvalidExtendedChecksum => @panic("Invalid RSDP extended checksum."),
    };

    const xsdt: *Xsdt = @ptrFromInt(mem.phys2virt(rsdp.xsdt_address));
    xsdt.header.valid("XSDT") catch |e| switch (e) {
        AcpiError.InvalidSignature => @panic("Invalid XSDT signature."),
        AcpiError.InvalidChecksum => @panic("Invalid XSDT checksum."),
        else => unreachable,
    };

    var ix: usize = 0;
    fadt = while (ix < xsdt.size()) : (ix += 1) {
        const ent = xsdt.get(ix);
        if (ent.valid("FACP")) |_| {
            // The signature of FADT is "FACP".
            break @as(*Fadt, @ptrCast(ent));
        } else |_| {}
    } else @panic("FADT not found.");

    rsdp_addr = mem.virt2phys(_rsdp);
    xsdt_addr = rsdp.xsdt_address;
    log.debug("RSDP @ 0x{X:0>16}, XSDT @ 0x{X:0>16}", .{ rsdp_addr.?, xsdt_addr.? });
}

/// Calculate the checksum of RSDP structure.
/// `checksum` and `extended_checksum` is set so that the sum of all bytes is 0.
fn checksum(data: []u8) u8 {
    var sum: u8 = 0;
    for (data) |byte| {
        sum +%= byte;
    }
    return sum;
}

/// ACPI structure that contains information about ACPI fixed registers.
/// Most of fields are omitted here.
const Fadt = extern struct {
    header: DescriptorHeader,

    _reserved1: [76 - @sizeOf(DescriptorHeader)]u8,
    pm_tmr_blk: u32,
    _reserved2: [32]u8,
    flags: u32,
    _reserved3: [160]u8,

    comptime {
        if (@sizeOf(Fadt) != 276) {
            @compileError("Invalid size of FADT.");
        }
    }
};

/// XSDT (Extended System Descriptor Table) structure of ACPI v2.0+..
/// XSDT starts with a header and followed by a list of 64-bit pointers to other tables.
const Xsdt = extern struct {
    header: DescriptorHeader,
    _pointer_entries: void,

    /// Get the table entry at the specified index.
    pub fn get(self: *Xsdt, index: usize) *DescriptorHeader {
        // NOTE: 64bit pointer entries are 4 bytes aligned, not 8 bytes.
        //   Zig does not allow incorrect alignment cast, for example:
        //   `const ents: [*]*const DescriptorHeader = @alignCast(@ptrCast(&self._pointer_entries))`
        //   Therefore, we have to calculate the address from two 32bit integers.
        const ents_start = @intFromPtr(&self._pointer_entries);
        const first: *u32 = @ptrFromInt(ents_start + index * @sizeOf(u64));
        const second: *u32 = @ptrFromInt(ents_start + index * @sizeOf(u64) + @sizeOf(u32));
        return @ptrFromInt(mem.phys2virt((@as(u64, second.*) << 32) + first.*));
    }

    /// Number of table entries.
    pub fn size(self: *Xsdt) usize {
        return (self.header.length - @sizeOf(DescriptorHeader)) / @sizeOf(u64);
    }

    comptime {
        if (@sizeOf(Xsdt) != 36) {
            @compileError("Invalid size of XSDT.");
        }
    }
};

/// Descriptor header of ACPI structures.
const DescriptorHeader = extern struct {
    signature: [4]u8,
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [6]u8,
    oem_table_id: [8]u8,
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,

    _end_marker: void,

    pub fn valid(self: *DescriptorHeader, signature: []const u8) AcpiError!void {
        if (!std.mem.eql(u8, signature, &self.signature)) {
            return AcpiError.InvalidSignature;
        }
        const ents: [*]u8 = @ptrCast(self);
        if (checksum(ents[0..self.length]) != 0) {
            return AcpiError.InvalidChecksum;
        }
    }

    comptime {
        if (@sizeOf(DescriptorHeader) != 36) {
            @compileError("Invalid size of DescriptorHeader.");
        }
    }
};

/// RSDP (Root System Description Pointer) structure of ACPI v2.0+.
/// RSDP is used to find XSDT (Extended System Descriptor Table).
pub const Rsdp = extern struct {
    const size_first_byte = @offsetOf(Rsdp, "length");
    const size_extended_byte = @offsetOf(Rsdp, "_end_marker");

    /// Signature.
    /// It should be "RSD PTR ".
    signature: [8]u8,
    /// Checksum for the first 20 bytes.
    checksum: u8,
    /// OEM ID.
    oem_id: [6]u8,
    /// Revision.
    /// 0 for ACPI 1.0, 2 for ACPI 2.0.
    revision: u8,
    /// RSDT physical address.
    rsdt_address: u32,

    /// Total length of RSDP.
    length: u32,
    /// XSDT (Extended System Descriptor Table) physical address.
    xsdt_address: u64,
    /// Checksum for entire RSDP.
    extended_checksum: u8,
    /// Reserved.
    _reserved: [3]u8,

    _end_marker: void,

    comptime {
        if (size_extended_byte != 36) {
            @compileError("Invalid size of Rsdp.");
        }
    }

    fn valid(self: *Rsdp) AcpiError!void {
        if (!std.mem.eql(u8, &self.signature, "RSD PTR ")) {
            return AcpiError.InvalidSignature;
        }
        if (self.revision != 2) {
            return AcpiError.InvalidRevision;
        }
        if (checksum(std.mem.asBytes(self)[0..size_first_byte]) != 0) {
            return AcpiError.InvalidChecksum;
        }
        if (checksum(std.mem.asBytes(self)[0..size_extended_byte]) != 0) {
            return AcpiError.InvalidExtendedChecksum;
        }
    }
};

test "Size of structures" {
    std.testing.refAllDecls(@This());
    try std.testing.expectEqual(36, @sizeOf(DescriptorHeader));
    try std.testing.expectEqual(36, @sizeOf(Xsdt));
    try std.testing.expectEqual(276, @sizeOf(Fadt));
}
