KERNEL_VADDR_BASE = 0xFFFFFFFF80000000;
KERNEL_VADDR_TEXT = 0xFFFFFFFF80100000;

STACK_SIZE = 0x5000;

PHDRS {
    text PT_LOAD;
    rodata PT_LOAD;
    data PT_LOAD;
    bss PT_LOAD;

    __stackguard_upper PT_LOAD FLAGS(4);
    __stack PT_LOAD FLAGS(6);
    __stackguard_lower PT_LOAD FLAGS(4);
}

SECTIONS {
    . = KERNEL_VADDR_TEXT;

    .text ALIGN(4K) : AT (ADDR(.text) - KERNEL_VADDR_BASE) {
        *(.text)
        *(.ltext)
    } :text

    .rodata ALIGN(4K) : AT (ADDR(.rodata) - KERNEL_VADDR_BASE) {
        *(.rodata)
    } :rodata

    .data ALIGN(4K) : AT (ADDR(.data) - KERNEL_VADDR_BASE) {
        *(.data)
        *(.ldata)
    } :data

    .bss ALIGN(4K) : AT (ADDR(.bss) - KERNEL_VADDR_BASE) {
        *(COMMON)
        *(.bss)
        *(.lbss)
    } :bss

    __stackguard_upper ALIGN(4K) (NOLOAD) : AT (ADDR(__stackguard_upper) - KERNEL_VADDR_BASE) {
        . += 4K;
    } :__stackguard_upper

    __stack ALIGN(4K) (NOLOAD) : AT (ADDR(__stack) - KERNEL_VADDR_BASE) {
        . += STACK_SIZE;
    } :__stack

    __stackguard_lower ALIGN(4K) (NOLOAD) : AT (ADDR(__stackguard_lower) - KERNEL_VADDR_BASE) {
        __stackguard_lower = .;
        . += 4K;
    } :__stackguard_lower
}
