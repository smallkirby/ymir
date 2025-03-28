const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
        .ofmt = .elf,
    });
    const optimize = b.standardOptimizeOption(.{});

    // Options
    const s_log_level = b.option(
        []const u8,
        "log_level",
        "log_level",
    ) orelse "info";
    const log_level: std.log.Level = b: {
        const eql = std.mem.eql;
        break :b if (eql(u8, s_log_level, "debug"))
            .debug
        else if (eql(u8, s_log_level, "info"))
            .info
        else if (eql(u8, s_log_level, "warn"))
            .warn
        else if (eql(u8, s_log_level, "error"))
            .err
        else
            @panic("Invalid log level");
    };

    const wait_qemu = b.option(
        bool,
        "wait_qemu",
        "QEMU waits for GDB connection.",
    ) orelse false;

    const options = b.addOptions();
    options.addOption(std.log.Level, "log_level", log_level);

    // Modules
    const surtr_module = b.createModule(.{
        .root_source_file = b.path("surtr/defs.zig"),
    });
    surtr_module.addOptions("option", options);
    const ymir_module = b.createModule(.{
        .root_source_file = b.path("ymir/ymir.zig"),
    });
    ymir_module.addImport("ymir", ymir_module);
    ymir_module.addImport("surtr", surtr_module);
    ymir_module.addOptions("option", options);

    // Executables
    const surtr = b.addExecutable(.{
        .name = "BOOTX64.EFI",
        .root_source_file = b.path("surtr/boot.zig"),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = .x86_64,
            .os_tag = .uefi,
        }),
        .optimize = optimize,
        .linkage = .static,
    });
    surtr.root_module.addOptions("option", options);
    b.installArtifact(surtr);

    const ymir = b.addExecutable(.{
        .name = "ymir.elf",
        .root_source_file = b.path("ymir/main.zig"),
        .target = target, // Freestanding x64 ELF executable
        .optimize = optimize, // You can choose the optimization level.
        .linkage = .static,
        .code_model = .kernel,
    });
    ymir.root_module.red_zone = false; // Disable stack red zone.
    ymir.link_z_relro = false;
    ymir.entry = .{ .symbol_name = "kernelEntry" };
    ymir.linker_script = b.path("ymir/linker.ld");
    ymir.root_module.addImport("surtr", surtr_module);
    ymir.root_module.addImport("ymir", ymir_module);
    ymir.root_module.addOptions("option", options);
    b.installArtifact(ymir);

    // EFI directory
    const out_dir_name = "img";
    const install_surtr = b.addInstallFile(
        surtr.getEmittedBin(),
        b.fmt("{s}/efi/boot/{s}", .{ out_dir_name, surtr.name }),
    );
    install_surtr.step.dependOn(&surtr.step);
    b.getInstallStep().dependOn(&install_surtr.step);
    const install_ymir = b.addInstallFile(
        ymir.getEmittedBin(),
        b.fmt("{s}/{s}", .{ out_dir_name, ymir.name }),
    );
    install_ymir.step.dependOn(&ymir.step);
    b.getInstallStep().dependOn(&install_ymir.step);

    // Install sample assets.
    const install_rootfs = b.addInstallFile(
        b.path("assets/samples/rootfs.cpio.gz"),
        b.fmt("{s}/rootfs.cpio.gz", .{out_dir_name}),
    );
    const install_bzimage = b.addInstallFile(
        b.path("assets/samples/bzImage"),
        b.fmt("{s}/bzImage", .{out_dir_name}),
    );
    const install_samples_step = b.step("install-samples", "Install sample assets");
    install_samples_step.dependOn(&install_rootfs.step);
    install_samples_step.dependOn(&install_bzimage.step);

    // ymirsh
    const ymirsh = b.addExecutable(.{
        .name = "ymirsh",
        .root_source_file = b.path("ymirsh/main.zig"),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = .x86_64,
            .os_tag = .linux,
            .cpu_model = .baseline,
        }),
        .optimize = optimize,
        .linkage = .static,
    });
    ymirsh.root_module.addOptions("option", options);
    b.installArtifact(ymirsh);

    // Run QEMU
    // WARN: VVFAT somehow overwrites /ymir.elf.
    //  DO NOT use /zig-out/img/ymir.elf to analyze/debug ymir.
    //  Use /zig-out/bin/ymir.elf instead.
    var qemu_args = std.ArrayList([]const u8).init(b.allocator);
    defer qemu_args.deinit();
    try qemu_args.appendSlice(&.{
        "qemu-system-x86_64",
        "-m",
        "512M",
        "-bios",
        "/usr/share/ovmf/OVMF.fd", // TODO: Make this configurable
        "-drive",
        b.fmt("file=fat:rw:{s}/{s},format=raw", .{ b.install_path, out_dir_name }),
        "-nographic",
        "-serial",
        "mon:stdio",
        "-no-reboot",
        "-enable-kvm",
        "-cpu",
        "host",
        "-s",
    });
    if (wait_qemu) try qemu_args.append("-S");

    const qemu_cmd = b.addSystemCommand(qemu_args.items);
    qemu_cmd.step.dependOn(b.getInstallStep());

    const run_qemu_cmd = b.step("run", "Run QEMU");
    run_qemu_cmd.dependOn(&qemu_cmd.step);

    // Unit tests
    const ymir_tests = b.addTest(.{
        .name = "Unit Test",
        .root_source_file = b.path("ymir/ymir.zig"),
        .target = b.standardTargetOptions(.{}),
        .optimize = optimize,
        .link_libc = true,
    });
    ymir_tests.root_module.addImport("ymir", ymir_tests.root_module);
    ymir_tests.root_module.addImport("surtr", surtr_module);
    ymir_tests.root_module.addOptions("option", options);
    const run_ymir_tests = b.addRunArtifact(ymir_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_ymir_tests.step);

    // Documentation
    const install_docs = b.addInstallDirectory(.{
        .source_dir = ymir.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    const docs_step = b.step("docs", "Generate documentation");
    docs_step.dependOn(&install_docs.step);
}
