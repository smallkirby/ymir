const std = @import("std");
const log = std.log.scoped(.archp);
const uefi = std.os.uefi;
const BootServices = uefi.tables.BootServices;

const am = @import("asm.zig");

pub const PageError = error{
    /// Failed to allocate memory.
    NoMemory,
    /// Requested page table entry is not present.
    NotPresent,
    /// Given virtual address is not canonical.
    NotCanonical,
    /// Given address is invalid.
    InvalidAddress,
    /// Requested mapping already exists.
    AlreadyMapped,
};

/// Size in bytes of a 4K page.
const page_size_4k: usize = 4096;
/// Size in bytes of a 2M page.
const page_size_2mb: usize = page_size_4k << 9;
/// Size in bytes of a 1G page.
const page_size_1gb: usize = page_size_2mb << 9;
/// Shift in bits for a page.
const page_shift = 12;
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

/// Make level-4 page table writable.
/// The page tables prepared by the bootloader are marked as read-only.
/// To modify page mappings, this function duplicates the level-4 page table
/// and load the new level-4 page table to CR3.
pub fn setLv4PageTableWritable(bs: *BootServices) PageError!void {
    var new_lv4_table_ptr: [*]Lv4PageTableEntry = undefined;
    const status = bs.allocatePages(.AllocateAnyPages, .BootServicesData, 1, @ptrCast(&new_lv4_table_ptr));
    if (status != .Success) return PageError.NoMemory;

    const new_lv4_table = new_lv4_table_ptr[0..num_table_entries];
    const lv4_table = getLv4PageTable();
    @memcpy(new_lv4_table, lv4_table);

    am.loadCr3(@intFromPtr(new_lv4_table.ptr));
}

/// Maps 4KiB page at the given virtual address to the given physical address.
/// If the mapping already exists, this function modifies the existing mapping.
/// If the mapping does not exist, this function creates a new mapping,
/// where new memory is allocated for page tables using BootServices.
/// New page tables are allocated as 4KiB BootServicesData pages.
pub fn mapTo(virt: Virt, phys: Phys, bs: *BootServices) PageError!void {
    if (virt & 0xFFF != 0) return PageError.InvalidAddress;
    if (phys & 0xFFF != 0) return PageError.InvalidAddress;
    if (!isCanonical(virt)) return PageError.NotCanonical;

    const lv4_table = getLv4PageTable();
    const lv4_index = (virt >> lv4_shift) & index_mask;
    const lv4_entry = &lv4_table[lv4_index];
    if (!lv4_entry.present) {
        var lv3_ptr: Phys = undefined;
        const status = bs.allocatePages(.AllocateAnyPages, .BootServicesData, 1, @ptrCast(&lv3_ptr));
        if (status != .Success) return PageError.NoMemory;
        clearPage(lv3_ptr);
        lv4_entry.* = Lv4PageTableEntry.new(lv3_ptr);
    }

    const lv3_table = getLv3PageTable(lv4_entry.address());
    const lv3_index = (virt >> lv3_shift) & index_mask;
    const lv3_entry = &lv3_table[lv3_index];
    if (!lv3_entry.present) {
        var lv2_ptr: Phys = undefined;
        const status = bs.allocatePages(.AllocateAnyPages, .BootServicesData, 1, @ptrCast(&lv2_ptr));
        if (status != .Success) return PageError.NoMemory;
        clearPage(lv2_ptr);
        lv3_entry.* = Lv3PageTableEntry.new(lv2_ptr);
    }

    const lv2_table = getLv2PageTable(lv3_entry.address());
    const lv2_index = (virt >> lv2_shift) & index_mask;
    const lv2_entry = &lv2_table[lv2_index];
    if (!lv2_entry.present) {
        var lv1_ptr: Phys = undefined;
        const status = bs.allocatePages(.AllocateAnyPages, .BootServicesData, 1, @ptrCast(&lv1_ptr));
        if (status != .Success) return PageError.NoMemory;
        clearPage(lv1_ptr);
        lv2_entry.* = Lv2PageTableEntry.new(lv1_ptr);
    }
    if (lv2_entry.ps) return PageError.AlreadyMapped;

    const lv1_table = getLv1PageTable(lv2_entry.address());
    const lv1_index = (virt >> lv1_shift) & index_mask;
    const lv1_entry = &lv1_table[lv1_index];
    lv1_entry.* = Lv1PageTableEntry{
        .present = true,
        .rw = true, // TODO: make this configurable
        .us = false,
        .pat = false,
        .phys_addr = @truncate(phys >> page_shift),
    };
}

fn clearPage(addr: Phys) void {
    const page_ptr: [*]u8 = @ptrFromInt(addr);
    @memset(page_ptr[0..page_size_4k], 0);
}

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
    pub fn new(phys_pdpt: Phys) Lv4PageTableEntry {
        return Lv4PageTableEntry{
            .present = true,
            .rw = true,
            .us = false,
            .phys_pdpt = @truncate(phys_pdpt >> page_shift),
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
    pub fn new(phys_pdt: Phys) Lv3PageTableEntry {
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
    pub fn new_2mb(phys: u64) Lv2PageTableEntry {
        return Lv2PageTableEntry{
            .present = true,
            .rw = true,
            .us = false,
            .ps = true,
            .phys_pt = @truncate(phys >> 12),
        };
    }

    /// Get a new PDT entry that references a level-1 page table.
    pub fn new(phys: u64) Lv2PageTableEntry {
        return Lv2PageTableEntry{
            .present = true,
            .rw = true,
            .us = false,
            .ps = false,
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
