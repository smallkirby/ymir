export fn kernelEntry() callconv(.Naked) noreturn {
    while (true)
        asm volatile ("hlt");
}
