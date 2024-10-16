//! Log module for Surtr.
//! Surtr outputs logs to the UEFI console output utilizing SimpleTextOutput protocol.
//! You must call `init` function before using this module.

const std = @import("std");
const uefi = std.os.uefi;
const stdlog = std.log;
const option = @import("option");

const Sto = uefi.protocol.SimpleTextOutput;

const LogError = error{};

const Writer = std.io.Writer(
    void,
    LogError,
    writerFunction,
);

/// Default log options.
/// You can override std_options in your main file.
pub const default_log_options = std.Options{
    .log_level = switch (option.log_level) {
        .debug => .debug,
        .info => .info,
        .warn => .warn,
        .err => .err,
    },
    .logFn = log,
};

var con_out: *Sto = undefined;

/// Initialize bootloader log.
pub fn init(out: *Sto) void {
    con_out = out;
}

fn writerFunction(_: void, bytes: []const u8) LogError!usize {
    for (bytes) |b| {
        // EFI uses UCS-2 encoding.
        con_out.outputString(&[_:0]u16{b}).err() catch unreachable;
    }
    return bytes.len;
}

fn log(
    comptime level: stdlog.Level,
    scope: @Type(.EnumLiteral),
    comptime fmt: []const u8,
    args: anytype,
) void {
    const level_str = comptime switch (level) {
        .debug => "[DEBUG]",
        .info => "[INFO ]",
        .warn => "[WARN ]",
        .err => "[ERROR]",
    };
    const scope_str = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";

    std.fmt.format(
        Writer{ .context = {} },
        level_str ++ " " ++ scope_str ++ fmt ++ "\r\n",
        args,
    ) catch unreachable;
}
