const std = @import("std");
const log = std.log.scoped(.archp);
const Allocator = std.mem.Allocator;

const arch = @import("arch.zig");
const am = @import("asm.zig");

const page_size_4k: usize = arch.page_size;
const page_size_2mb: usize = page_size_4k << 9;
const page_size_1gb: usize = page_size_2mb << 9;
const page_shift = arch.page_shift;
const num_table_entries: usize = 512;

pub const PageError = error{
    /// Failed to allocate memory.
    NoMemory,
};

/// Construct the identity mapping and switch to it.
/// This function uses 2MiB pages to reduce the number of page table entries.
/// Only the first entry of the PML4 table is used.
/// TODO: This is a temporary implementation. Replace it.
pub fn initIdentityMapping(allocator: Allocator) PageError!void {
    // Allocate and init tables.
    const pml4_table = allocator.alloc(Pml4Entry, num_table_entries) catch {
        return PageError.NoMemory;
    };
    errdefer allocator.free(pml4_table);
    for (0..num_table_entries) |i| {
        pml4_table[i] = Pml4Entry.new_nopresent();
    }

    const pdp_table = allocator.alloc(PdptEntry, num_table_entries) catch {
        return PageError.NoMemory;
    };
    errdefer allocator.free(pdp_table);
    for (0..num_table_entries) |i| {
        pdp_table[i] = PdptEntry.new_nopresent();
    }

    // Construct PML4 table.
    pml4_table[0] = Pml4Entry.new(&pdp_table[0]);

    // Construct PDPT table and 2MiB PDT entries.
    for (0..num_table_entries) |pdp_i| {
        const page_directory = allocator.alloc(PdtEntry, num_table_entries) catch {
            return PageError.NoMemory;
        };
        errdefer allocator.free(page_directory);

        pdp_table[pdp_i] = PdptEntry.new(@intFromPtr(page_directory.ptr));

        for (0..num_table_entries) |pdt_i| {
            page_directory[pdt_i] = PdtEntry.new_4mb(
                pdp_i * page_size_1gb + pdt_i * page_size_2mb,
            );
        }
    }

    // Load CR3 register.
    am.loadCr3(@intFromPtr(&pml4_table[0]));
}

/// Maps the given virtual address to the physical address identity for 2MiB page.
/// TODO: this is a temporary implementation to workaround the problem
/// that xHC MMIO address exceeds 16GiB.
pub fn mapIdentity(vaddr: u64, allocator: Allocator) !void {
    // TODO: remove magic numbers.
    const pml4_index = (vaddr >> 39) & 0x1FF;
    const pdp_index = (vaddr >> 30) & 0x1FF;
    const pdt_index = (vaddr >> 21) & 0x1FF;

    const pml4_table = getCurrentPml4();

    const pml4_ent = &pml4_table[pml4_index];
    if (!pml4_ent.present) {
        const pdpt = try allocator.alloc(PdptEntry, num_table_entries);
        pml4_ent.* = Pml4Entry.new(&pdpt[0]);
    }

    const pdp: [*]PdptEntry = @ptrFromInt(pml4_ent.phys_pdpt << page_shift);
    const pdp_ent = &pdp[pdp_index];
    if (!pdp_ent.present) {
        const pdt = try allocator.alloc(PdtEntry, num_table_entries);
        pdp_ent.* = PdptEntry.new(@intFromPtr(pdt.ptr));
    }

    const pdt: [*]PdtEntry = @ptrFromInt(pdp_ent.phys_pdt << page_shift);
    const pdt_ent = &pdt[pdt_index];
    if (!pdt_ent.present) {
        pdt_ent.* = PdtEntry.new_4mb(
            pml4_index * 512 * page_size_1gb + pdp_index * page_size_1gb + pdt_index * page_size_2mb,
        );
    } else {
        // TODO
        @panic("The page is already mapped.");
    }
}

/// Get the pointer to the PML4 table of the current CPU.
fn getCurrentPml4() [*]Pml4Entry {
    const cr3 = am.readCr3();
    return @ptrFromInt(cr3 & ~@as(u64, 0xFFF));
}

/// Show the process of the address translation for the given linear address.
/// TODO: do not use logger of this scope.
pub fn showPageTable(lin_addr: u64) void {
    // TODO: remove magic numbers.
    const pml4_index = (lin_addr >> 39) & 0x1FF;
    const pdp_index = (lin_addr >> 30) & 0x1FF;
    const pdt_index = (lin_addr >> 21) & 0x1FF;
    const pt_index = (lin_addr >> 12) & 0x1FF;
    log.err("Linear Address: 0x{X:0>16} (0x{X}, 0x{X}, 0x{X}, 0x{X})", .{
        lin_addr,
        pml4_index,
        pdp_index,
        pdt_index,
        pt_index,
    });

    const cr3 = am.readCr3();
    const pml4: [*]Pml4Entry = @ptrFromInt(cr3);
    log.debug("PML4: 0x{X:0>16}", .{@intFromPtr(pml4)});
    const pml4_entry = pml4[pml4_index];
    log.debug("\tPML4[{d}]: 0x{X:0>16}", .{ pml4_index, std.mem.bytesAsValue(u64, &pml4_entry).* });
    const pdp: [*]PdptEntry = @ptrFromInt(pml4_entry.phys_pdpt << page_shift);
    log.debug("PDPT: 0x{X:0>16}", .{@intFromPtr(pdp)});
    const pdp_entry = pdp[pdp_index];
    log.debug("\tPDPT[{d}]: 0x{X:0>16}", .{ pdp_index, std.mem.bytesAsValue(u64, &pdp_entry).* });
    const pdt: [*]PdtEntry = @ptrFromInt(pdp_entry.phys_pdt << page_shift);
    log.debug("PDT: 0x{X:0>16}", .{@intFromPtr(pdt)});
    const pdt_entry = pdt[pdt_index];
    log.debug("\tPDT[{d}]: 0x{X:0>16}", .{ pdt_index, std.mem.bytesAsValue(u64, &pdt_entry).* });
}

/// PML4E
const Pml4Entry = packed struct(u64) {
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
    pub fn new_nopresent() Pml4Entry {
        return Pml4Entry{
            .present = false,
            .rw = false,
            .us = false,
            .phys_pdpt = 0,
        };
    }

    /// Get a new PML4E entry.
    pub fn new(phys_pdpt: *PdptEntry) Pml4Entry {
        return Pml4Entry{
            .present = true,
            .rw = true,
            .us = false,
            .phys_pdpt = @truncate(@as(u64, @intFromPtr(phys_pdpt)) >> page_shift),
        };
    }
};

/// PDPT Entry
const PdptEntry = packed struct(u64) {
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
    pub fn new_nopresent() PdptEntry {
        return PdptEntry{
            .present = false,
            .rw = false,
            .us = false,
            .ps = false,
            .phys_pdt = 0,
        };
    }

    /// Get a new PDPT entry.
    pub fn new(phys_pdt: u64) PdptEntry {
        return PdptEntry{
            .present = true,
            .rw = true,
            .us = false,
            .ps = false,
            .phys_pdt = @truncate(phys_pdt >> page_shift),
        };
    }
};

/// PDT Entry
const PdtEntry = packed struct(u64) {
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
    pub fn new_nopresent() PdtEntry {
        return PdtEntry{
            .present = false,
            .rw = false,
            .us = false,
            .ps = false,
            .phys_pt = 0,
        };
    }

    /// Get a new PDT entry that maps a 2MiB page.
    pub fn new_4mb(phys: u64) PdtEntry {
        return PdtEntry{
            .present = true,
            .rw = true,
            .us = false,
            .ps = true,
            .phys_pt = @truncate(phys >> 12),
        };
    }
};
