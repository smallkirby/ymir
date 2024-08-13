const std = @import("std");
const log = std.log.scoped(.archp);
const Allocator = std.mem.Allocator;

const arch = @import("arch.zig");
const am = @import("asm.zig");

pub const PageError = error{
    /// Failed to allocate memory.
    NoMemory,
};

/// Size in bytes of a 4K page.
const page_size_4k: usize = arch.page_size;
/// Size in bytes of a 2M page.
const page_size_2mb: usize = page_size_4k << 9;
/// Size in bytes of a 1G page.
const page_size_1gb: usize = page_size_2mb << 9;
/// Shift in bits for a page.
const page_shift = arch.page_shift;
/// Number of entries in a page table.
const num_table_entries: usize = 512;

/// Shift in bits to extract the level-4 index from a virtual address.
const lv4_shift = 39;
/// Shift in bits to extract the level-3 index from a virtual address.
const lv3_shift = 30;
/// Shift in bits to extract the level-2 index from a virtual address.
const lv2_shift = 21;
/// Shift in bits to extract the level-1 index from a virtual address.
const lv1_shift = 12;
/// Mask to extract page entry index from a shifted virtual address.
const index_mask = 0x1FF;

/// Length of the implemented bits.
const implemented_bit_length = 48;
/// Most significant implemented bit in 0-origin.
const msi_bit = 47;

/// Physical address.
pub const Phys = u64;
/// Virtual address.
pub const Virt = u64;

/// Offset from physical to virtual address for page tables.
/// This value is determined by surtr bootloader and a backing UEFI firmware.
/// For now, we only assume OVMF as UEFI,
/// that directly maps available physical memory to virtual memory using 2MiB pages.
/// Therefore, the offset is 0x0 for OVMF.
const phys_virt_offset = 0x0;

/// Return true if the given address is canonical form.
/// The address is in canonical form if address bits 63 through 48 are copies of bit 47.
pub fn isCanonical(addr: Virt) bool {
    if ((addr >> msi_bit) & 1 == 0) {
        return (addr >> (implemented_bit_length)) == 0;
    } else {
        return addr >> (implemented_bit_length) == 0xFFFF;
    }
}

/// Get the level-4 page table of the current process.
pub fn getLv4PageTable() []Lv4PageTableEntry {
    const cr3 = am.readCr3() + phys_virt_offset;
    const lv4_table_ptr: [*]Lv4PageTableEntry = @ptrFromInt(cr3 & ~@as(u64, 0xFFF));
    return lv4_table_ptr[0..num_table_entries];
}

/// Get the level-3 page table at the given address.
pub fn getLv3PageTable(lv3_table_addr: Phys) []Lv3PageTableEntry {
    const lv3_table_ptr: [*]Lv3PageTableEntry = @ptrFromInt(lv3_table_addr + phys_virt_offset);
    return lv3_table_ptr[0..num_table_entries];
}

/// Get the level-2 page table at the given address.
pub fn getLv2PageTable(lv2_table_addr: Phys) []Lv2PageTableEntry {
    const lv2_table_ptr: [*]Lv2PageTableEntry = @ptrFromInt(lv2_table_addr + phys_virt_offset);
    return lv2_table_ptr[0..num_table_entries];
}

/// Get the level-1 page table at the given address.
pub fn getLv1PageTable(lv1_table_addr: Phys) []Lv1PageTableEntry {
    const lv1_table_ptr: [*]Lv1PageTableEntry = @ptrFromInt(lv1_table_addr + phys_virt_offset);
    return lv1_table_ptr[0..num_table_entries];
}

/// Translate the given virtual address to physical address.
/// If the translation fails, return null.
pub fn translate(addr: Virt) ?Phys {
    if (!isCanonical(addr)) return null;

    const lv4_table = getLv4PageTable();
    const lv4_index = (addr >> lv4_shift) & index_mask;
    const lv4_entry = &lv4_table[lv4_index];
    if (!lv4_entry.present) return null;

    const lv3_table = getLv3PageTable(lv4_entry.address());
    const lv3_index = (addr >> lv3_shift) & index_mask;
    const lv3_entry = &lv3_table[lv3_index];
    if (!lv3_entry.present) return null;
    if (lv3_entry.ps) { // 1GiB page
        return lv3_entry.address() + (addr & 0x1FFFFFFF);
    }

    const lv2_table = getLv2PageTable(lv3_entry.address());
    const lv2_index = (addr >> lv2_shift) & index_mask;
    const lv2_entry = &lv2_table[lv2_index];
    if (!lv2_entry.present) return null;
    if (lv2_entry.ps) { // 2MiB page
        return lv2_entry.address() + (addr & 0x1FFFF);
    }

    const lv1_table = getLv1PageTable(lv2_entry.address());
    const lv1_index = (addr >> lv1_shift) & index_mask;
    const lv1_entry = &lv1_table[lv1_index];
    if (!lv1_entry.present) return null;
    return lv1_entry.phys_addr + (addr & 0xFFF);
}

/// Show the process of the address translation for the given linear address.
/// TODO: do not use logger of this scope.
/// TODO: Level-1 page table entry is not implemented.
pub fn showPageTable(lin_addr: Virt) void {
    const pml4_index = (lin_addr >> lv4_shift) & index_mask;
    const pdp_index = (lin_addr >> lv3_shift) & index_mask;
    const pdt_index = (lin_addr >> lv2_shift) & index_mask;
    const pt_index = (lin_addr >> lv1_shift) & index_mask;
    log.err("Linear Address: 0x{X:0>16} (0x{X}, 0x{X}, 0x{X}, 0x{X})", .{
        lin_addr,
        pml4_index,
        pdp_index,
        pdt_index,
        pt_index,
    });

    const cr3 = am.readCr3();
    const pml4: [*]Lv4PageTableEntry = @ptrFromInt(cr3);
    log.debug("PML4: 0x{X:0>16}", .{@intFromPtr(pml4)});
    const pml4_entry = pml4[pml4_index];
    log.debug("\tPML4[{d}]: 0x{X:0>16}", .{ pml4_index, std.mem.bytesAsValue(u64, &pml4_entry).* });
    const pdp: [*]Lv3PageTableEntry = @ptrFromInt(pml4_entry.phys_pdpt << page_shift);
    log.debug("PDPT: 0x{X:0>16}", .{@intFromPtr(pdp)});
    const pdp_entry = pdp[pdp_index];
    log.debug("\tPDPT[{d}]: 0x{X:0>16}", .{ pdp_index, std.mem.bytesAsValue(u64, &pdp_entry).* });
    const pdt: [*]Lv2PageTableEntry = @ptrFromInt(pdp_entry.phys_pdt << page_shift);
    log.debug("PDT: 0x{X:0>16}", .{@intFromPtr(pdt)});
    const pdt_entry = pdt[pdt_index];
    log.debug("\tPDT[{d}]: 0x{X:0>16}", .{ pdt_index, std.mem.bytesAsValue(u64, &pdt_entry).* });
}

/// Level-4 (First) page table entry, PML4E.
/// This entry can map 512GiB region or reference a level-3 page table.
const Lv4PageTableEntry = packed struct(u64) {
    /// Present.
    present: bool = true,
    /// Read/Write.
    /// If set to false, wirte access is not allowed to the 512GB region.
    rw: bool,
    /// User/Supervisor.
    /// If set to false, user-mode access is not allowed to the 512GB region.
    us: bool,
    /// Page-level writh-through.
    /// Indirectly determines the memory type used to access the PDP Table.
    pwt: bool = false,
    /// Page-level cache disable.
    /// Indirectly determines the memory type used to access the PDP Table.
    pcd: bool = false,
    /// Accessed.
    /// Indicates wheter this entry has been used for translation.
    accessed: bool = false,
    /// Ignored.
    _ignored1: u1 = 0,
    /// ReservedZ.
    _reserved1: u1 = 0,
    /// Ignored
    _ignored2: u3 = 0,
    /// Ignored except for HLAT paging.
    restart: bool = false,
    /// 4KB aligned address of the PDP Table.
    phys_pdpt: u52,

    /// Get a new PML4E entry with the present bit set to false.
    pub fn new_nopresent() Lv4PageTableEntry {
        return Lv4PageTableEntry{
            .present = false,
            .rw = false,
            .us = false,
            .phys_pdpt = 0,
        };
    }

    /// Get a new PML4E entry.
    pub fn new(phys_pdpt: *Lv3PageTableEntry) Lv4PageTableEntry {
        return Lv4PageTableEntry{
            .present = true,
            .rw = true,
            .us = false,
            .phys_pdpt = @truncate(@as(u64, @intFromPtr(phys_pdpt)) >> page_shift),
        };
    }

    /// Get the physical address pointed by this entry.
    pub inline fn address(self: Lv4PageTableEntry) Phys {
        return @as(u64, @intCast(self.phys_pdpt)) << page_shift;
    }
};

/// Level-3 page table entry, PDPTE.
/// This entry can map 1GiB page or reference a level-2 page table.
const Lv3PageTableEntry = packed struct(u64) {
    /// Present.
    present: bool = true,
    /// Read/Write.
    /// If set to false, wirte access is not allowed to the 1GiB region.
    rw: bool,
    /// User/Supervisor.
    /// If set to false, user-mode access is not allowed to the GiB region.
    us: bool,
    /// Page-level writh-through.
    /// Indirectly determines the memory type used to access the PD Table.
    pwt: bool = false,
    /// Page-level cache disable.
    /// Indirectly determines the memory type used to access the PD Table.
    pcd: bool = false,
    /// Accessed.
    /// Indicates wheter this entry has been used for translation.
    accessed: bool = false,
    /// Ignored.
    _ignored1: u1 = 0,
    /// Page Size.
    /// If set to true, the entry maps a 1GiB page.
    /// If set to false, the entry references a PD Table.
    ps: bool,
    /// Ignored
    _ignored2: u3 = 0,
    /// Ignored except for HLAT paging.
    restart: bool = false,
    /// 4KB aligned address of the PD Table.
    phys_pdt: u52,

    /// Get a new PDPT entry with the present bit set to false.
    pub fn new_nopresent() Lv3PageTableEntry {
        return Lv3PageTableEntry{
            .present = false,
            .rw = false,
            .us = false,
            .ps = false,
            .phys_pdt = 0,
        };
    }

    /// Get a new PDPT entry.
    pub fn new(phys_pdt: u64) Lv3PageTableEntry {
        return Lv3PageTableEntry{
            .present = true,
            .rw = true,
            .us = false,
            .ps = false,
            .phys_pdt = @truncate(phys_pdt >> page_shift),
        };
    }

    /// Get the physical address pointed by this entry.
    pub inline fn address(self: Lv3PageTableEntry) Phys {
        return @as(u64, @intCast(self.phys_pdt)) << page_shift;
    }
};

/// Level-2 page table entry, PDE.
/// This entry can map a 2MiB page or reference a level-1 page table.
const Lv2PageTableEntry = packed struct(u64) {
    /// Present.
    present: bool = true,
    /// Read/Write.
    /// If set to false, wirte access is not allowed to the 2MiB region.
    rw: bool,
    /// User/Supervisor.
    /// If set to false, user-mode access is not allowed to the 2Mib region.
    us: bool,
    /// Page-level writh-through.
    /// Indirectly determines the memory type used to access the 2MiB page or Page Table.
    pwt: bool = false,
    /// Page-level cache disable.
    /// Indirectly determines the memory type used to access the 2MiB page or Page Table.
    pcd: bool = false,
    /// Accessed.
    /// Indicates wheter this entry has been used for translation.
    accessed: bool = false,
    /// Dirty bit.
    /// Indicates wheter software has written to the 2MiB page.
    /// Ignored when this entry references a Page Table.
    dirty: bool = false,
    /// Page Size.
    /// If set to true, the entry maps a 2Mib page.
    /// If set to false, the entry references a Page Table.
    ps: bool,
    /// Ignored when CR4.PGE != 1.
    /// Ignored when this entry references a 2MiB page.
    global: bool = false,
    /// Ignored
    _ignored2: u2 = 0,
    /// Ignored except for HLAT paging.
    restart: bool = false,
    /// When the entry maps a 2MiB page, physical address of the 2MiB page.
    /// When the entry references a Page Table, 4KB aligned address of the Page Table.
    phys_pt: u52,

    /// Get a new PDT entry with the present bit set to false.
    pub fn new_nopresent() Lv2PageTableEntry {
        return Lv2PageTableEntry{
            .present = false,
            .rw = false,
            .us = false,
            .ps = false,
            .phys_pt = 0,
        };
    }

    /// Get a new PDT entry that maps a 2MiB page.
    pub fn new_4mb(phys: u64) Lv2PageTableEntry {
        return Lv2PageTableEntry{
            .present = true,
            .rw = true,
            .us = false,
            .ps = true,
            .phys_pt = @truncate(phys >> 12),
        };
    }

    /// Get the physical address pointed by this entry.
    pub inline fn address(self: Lv2PageTableEntry) Phys {
        return @as(u64, @intCast(self.phys_pt)) << 12;
    }
};

/// Level-1 page table entry, PTE.
/// This entry can map 4KiB page.
const Lv1PageTableEntry = packed struct(u64) {
    /// Present.
    present: bool = true,
    /// Read/Write.
    /// If set to false, wirte access is not allowed to the 4KiB region.
    rw: bool,
    /// User/Supervisor.
    /// If set to false, user-mode access is not allowed to the 4KiB region.
    us: bool,
    /// Page-level writh-through.
    /// Indirectly determines the memory type used to access the 4KiB page or Page Table.
    pwt: bool = false,
    /// Page-level cache disable.
    /// Indirectly determines the memory type used to access the 4KiB page or Page Table.
    pcd: bool = false,
    /// Accessed.
    /// Indicates wheter this entry has been used for translation.
    accessed: bool = false,
    /// Dirty bit.
    /// Indicates wheter software has written to the 4KiB page.
    /// Ignored when this entry references a Page Table.
    dirty: bool = false,
    /// Indirectly determines the memory type used to access the 4KiB page.
    pat: bool,
    /// Global. Whether the translation is global.
    /// Ignored when CR4.PGE != 1.
    global: bool = false,
    /// Ignored
    _ignored2: u2 = 0,
    /// Ignored except for HLAT paging.
    restart: bool = false,
    /// Physical address of the 4KiB page.
    phys_addr: u52,

    /// Get the physical address pointed by this entry.
    pub inline fn address(self: Lv1PageTableEntry) Phys {
        return @as(u64, @intCast(self.phys_addr)) << 12;
    }
};

// ========================================

const testing = std.testing;

test {
    testing.refAllDeclsRecursive(@This());
}

test "isCanonical" {
    try testing.expectEqual(true, isCanonical(0x0));
    try testing.expectEqual(true, isCanonical(0x0000_7FFF_FFFF_FFFF));
    try testing.expectEqual(false, isCanonical(0x0000_8000_0000_0000));
    try testing.expectEqual(false, isCanonical(0x1000_0000_0000_0000));
    try testing.expectEqual(false, isCanonical(0xFFFF_7FFF_FFFF_FFFF));
    try testing.expectEqual(true, isCanonical(0xFFFF_FFFF_8000_0000));
}
