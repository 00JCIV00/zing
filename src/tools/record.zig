//! Record Received Datagrams.

const std = @import("std");
const ascii = std.ascii;
const fmt = std.fmt;
const fs = std.fs;
const io = std.io;
const log = std.log;
const mem = std.mem;
const os = std.os;
const time = std.time;

const lib = @import("../zinglib.zig");
const craft = lib.craft;
const ia = lib.interact;
const Datagrams = lib.Datagrams;

/// Config for Recording Datagrams.
pub const RecordConfig = struct{
    /// Filename.
    filename: ?[]const u8 = null,
    /// Enable Printing of Datagrams to `stdout`.
    stdout: ?bool = false,
    /// Encode Format.
    format: ?craft.EncodeFormat = .txt,
    /// Datagram Separator.
    dg_sep: ?[]const u8 = "\n===============================================\n\n",
    /// Interface Name.
    if_name: ?[]const u8 = "eth0",
    /// Receive Datagrams Max.
    recv_dgs_max: ?u32 = 0,
    /// Enable Multi-Threading.
    multithreaded: ?bool = false,
};

/// Record Context.
pub const RecordContext = struct{
    /// Encode Format
    encode_fmt: craft.EncodeFormat = .txt,
    /// Enable Printing of Datagrams to `stdout`.
    enable_print: bool = false,
    /// Datagram Separator.
    dg_sep: []const u8 = "\n===============================================\n\n",
    /// Record File
    record_file: *?fs.File,
    /// Record Writer
    record_writer: ?*ia.InteractWriter(io.Writer(fs.File, os.WriteError, fs.File.write)),
    /// Datagrams Count.
    count: u32 = 0,
};

/// Record Datagrams.
pub fn record(alloc: mem.Allocator, config: RecordConfig) !void {
    var cwd = fs.cwd();
    var record_file = 
        if (config.filename) |filename| recFile: {
            const format = @tagName(config.format.?);
            const full_name = 
                if (ascii.endsWithIgnoreCase(filename, format)) filename
                else try fmt.allocPrint(alloc, "{s}.{s}", .{ filename, format });
            defer alloc.free(full_name);
            break :recFile try cwd.createFile(full_name, .{ .truncate = false });
        }
        else null;
    defer if (record_file) |file| file.close();
    const record_writer = if (record_file) |r_file| ia.InteractWriter(io.Writer(fs.File, os.WriteError, fs.File.write)).init(r_file.writer()) else null;

    var record_ctx = RecordContext{
        .encode_fmt = config.format.?,
        .enable_print = config.stdout.?,
        .dg_sep = config.dg_sep.?,
        .record_file = &record_file,
        // TODO: Fix Pointer to Temporary?
        .record_writer = if (record_writer) |rec_w| @constCast(&rec_w) else null,
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
fn recordReact(alloc: mem.Allocator, ctx: anytype, datagram: Datagrams.Full) !void {
    if (@TypeOf(ctx) != *RecordContext) @compileError("This Reaction Function requires a Context of Type `RecordContext`.");
    const stdout = io.getStdOut().writer();
    if (ctx.record_file.*) |file| {
        try file.seekFromEnd(0);
        try craft.encodeDatagram(alloc, datagram, ctx.record_writer.?, ctx.encode_fmt);
        if (ctx.encode_fmt == .txt) try ctx.record_writer.?.print("{s}", .{ ctx.dg_sep });
    }
    if (ctx.enable_print) {
        try craft.encodeDatagram(alloc, datagram, stdout, ctx.encode_fmt);
        if (ctx.encode_fmt == .txt) try stdout.print("{s}", .{ ctx.dg_sep });
    }
    ctx.*.count += 1;
    log.debug("Recorded Datagram #{d}.", .{ ctx.count });
}
