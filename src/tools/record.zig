//! Record Received Datagrams.

const std = @import("std");
const fmt = std.fmt;
const fs = std.fs;
const io = std.io;
const log = std.log;
const mem = std.mem;
const os = std.os;
const time = std.time;

const lib = @import("../zinglib.zig");
const ia = lib.interact;
const Datagrams = lib.Datagrams;

/// Config for Recording Datagrams.
pub const RecordConfig = struct{
    /// Filename.
    filename: ?[]const u8 = null,
    /// Enable Printing of Datagrams to `stdout`.
    print: ?bool = true,
    /// Datagram Separator.
    dg_sep: ?[]const u8 = "===============================================",
    /// Interface Name.
    if_name: ?[]const u8 = "eth0",
    /// Receive Datagrams Max.
    recv_dgs_max: ?u32 = 0,
    /// Enable Multi-Threading.
    multithreaded: ?bool = true,
};

/// Record Context.
const RecordContext = struct{
    /// Enable Printing of Datagrams to `stdout`.
    enable_print: bool = true,
    /// Datagram Separator.
    dg_sep: []const u8 = "===============================================",
    /// Record File
    record_file: *?fs.File,
    /// Datagrams Count.
    count: u32 = 0,
};

/// Record Datagrams.
pub fn record(alloc: mem.Allocator, config: RecordConfig) !void {
    var cwd = fs.cwd();
    var record_file = 
        if (config.filename) |filename| try cwd.createFile(filename, .{ .truncate = false })
        else null;
    defer if (record_file) |file| file.close();

    var record_ctx = RecordContext{
        .enable_print = config.print.?,
        .dg_sep = config.dg_sep.?,
        .record_file = &record_file,
    };

    try ia.interact(
        alloc, 
        &record_ctx,
        .{ .if_name = config.if_name.? },
        .{
            .recv_dgs_max = config.recv_dgs_max.?,
            .multithreaded = config.multithreaded.?,
        },
        .{ .react_fn = recordReact },
    );
}

/// Record Reaction Function.
fn recordReact(_: mem.Allocator, ctx: anytype, datagram: Datagrams.Full) !void {
    if (@TypeOf(ctx) != *RecordContext) @compileError("This Reaction Function requires a context of Type `RecordCtx`.");
    
    const text_fmt = 
       \\
       \\ {d}:
       \\ {s}
       \\
       \\ {s}
       \\
    ;
    const text_ctx = .{
        time.timestamp(),
        datagram,
        ctx.dg_sep,
    };

    // TODO: Redo this with IO_Uring? 
    if (ctx.record_file.*) |file| {
        try file.seekFromEnd(0);
        try file.writer().print(text_fmt, text_ctx);
    }

    if (ctx.enable_print) try io.getStdOut().writer().print(text_fmt, text_ctx);
    log.debug("Recorded Datagram.", .{});

    ctx.*.count += 1;
}
