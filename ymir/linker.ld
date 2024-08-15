KERNEL_VADDR_BASE = 0xFFFFFFFF80000000;
KERNEL_VADDR_TEXT = 0xFFFFFFFF80100000;

SECTIONS {
	. = KERNEL_VADDR_TEXT;

	.text ALIGN(4K) : AT (ADDR(.text) - KERNEL_VADDR_BASE) {
		*(.text)
	}

	.rodata ALIGN(4K) : AT (ADDR(.rodata) - KERNEL_VADDR_BASE) {
		*(.rodata)
	}

	.data ALIGN(4K) : AT (ADDR(.data) - KERNEL_VADDR_BASE) {
		*(.data)
	}

	.bss ALIGN(4K) : AT (ADDR(.bss) - KERNEL_VADDR_BASE) {
		*(COMMON)
		*(.bss)
	}
}
