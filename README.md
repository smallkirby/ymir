# Ymir: The Type-1 Hypervisor

![Zig](https://shields.io/badge/Zig-v0%2E14%2E0-blue?logo=zig&color=F7A41D&style=for-the-badge)

![Lint](https://github.com/smallkirby/ymir/actions/workflows/lint.yml/badge.svg)
![Test](https://github.com/smallkirby/ymir/actions/workflows/test.yml/badge.svg)
![Boot Linux](https://img.shields.io/travis/com/smallkirby/ymir?style=flat&logo=travis&label=Boot%20Linux)

Ymir is an Intel VT-x based baremetal hypervisor written in Zig.
It is minimalistic but can boot latest Linux kernel (v6.9).

![Ymir Logo](assets/ymir.png)

## Features

- Supports Intel x64 architecture.
- Can boot latest Linux kernel with initramfs.
- Uses EPT (Extended Page Tables) for memory virtualization.
- Super thin (passthrough) and minimalistic hypervisor.
- No dependencty. Everything is written from scratch in Zig.

## Limitations / Future Work

- No support of SMP.
- No support of APIC and other fundamental features.
- Can boot only Linux kernel with [x86 boot protocol](https://www.kernel.org/doc/html/v6.1/x86/boot.html).
- Can host only one VM at a time.
- And many more...

## Requirements

Install `ovmf` package to run UEFI firmware on QEMU:

```sh
sudo apt install ovmf
```

## Development

```sh
zig build install-samples
zig build run -Dlog_level=info -Doptimize=ReleaseFast
```

If you want to use your own kernel image and initramfs,
you can put your kernel image (`bzImage`) and initramfs (`initramfs.cpio`) to `/zig-out/img`.
It is tested that Ymir can boot Linux kernel v6.9 that is compiled with `defconfig` of x86-64.
