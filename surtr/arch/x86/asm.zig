pub inline fn loadCr3(cr3: u64) void {
    asm volatile (
        \\mov %[cr3], %%cr3
        :
        : [cr3] "r" (cr3),
    );
}

pub inline fn readCr3() u64 {
    var cr3: u64 = undefined;
    asm volatile (
        \\mov %%cr3, %[cr3]
        : [cr3] "=r" (cr3),
    );
    return cr3;
}
