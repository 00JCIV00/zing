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
    enable_print: ?bool = true,
    /// Datagram Separator.
    dg_sep: ?[]const u8 = "===============================================",
    /// Ring Buffer Max size (Max: 4096)
    ring_buf_max: ?u13 = 4096,
};

/// Record Context.
const RecordContext = struct{
    /// Record Config.
    record_config: RecordConfig = .{},

    /// Record IO_Uring
    record_io: *os.linux.IO_Uring,
    /// Record Completion Query Events
    record_cqes: []os.linux.io_uring_cqe,

    /// Record File
    record_file: *?fs.File,

    /// Datagrams Count.
    count: u32 = 0,
};

/// Record Datagrams.
pub fn record(alloc: mem.Allocator, config: RecordConfig) !void {
    const ring_buf_max = config.ring_buf_max orelse 4096;
    var record_io = try os.linux.IO_Uring.init(ring_buf_max, 0);
    defer record_io.deinit();
    var record_cqes = try alloc.alloc(os.linux.io_uring_cqe, ring_buf_max);
    defer alloc.free(record_cqes);

    var cwd = fs.cwd();
    defer cwd.close();
    var record_file = 
        if (config.filename) |filename| try cwd.createFile(filename, .{ .truncate = false })
        else null;
    defer if (record_file) |file| file.close();

    try ia.interact(
        alloc, 
        RecordContext{
            .record_config = config,
            .record_io = &record_io,
            .record_cqes = record_cqes,
            .record_file = &record_file,
        },
        .{ .react_fn = recordReact },
    );
}

/// Record Reaction Function.
fn recordReact(_: mem.Allocator, ctx: anytype, datagram: Datagrams.Full) !void {
    if (@TypeOf(ctx) != RecordContext) @compileError("This Reaction Function requires a context of Type `RecordCtx`.");
    //var ctx = ctx orelse {
    //    log.err("This Reaction Function requires a context of Type `RecordCtx`.", .{});
    //    return error.NullContextProvided;
    //};
    
    const text_fmt = 
       \\
       \\ {d}:
       \\ {s}
       \\
       \\ {?s}
       \\
    ;
    const text_ctx = .{
        time.timestamp(),
        datagram,
        ctx.record_config.dg_sep,
    };

    // TODO: Redo this with IO_Uring 
    if (ctx.record_file.*) |file| {
        try file.seekFromEnd(0);
        try file.writer().print(text_fmt, text_ctx);
    }

    if (ctx.record_config.enable_print orelse true) try io.getStdOut().writer().print(text_fmt, text_ctx);
    log.debug("Recorded Datagram.", .{});
}
