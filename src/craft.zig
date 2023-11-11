//! Functions for Crafting Network Datagrams. This commonly means Packets (Layer 3), but could mean full Frames (Layer 2) or smaller Segments (Layer 4).

const std = @import("std");
const fs = std.fs;
const json = std.json;
const log = std.log;
const mem = std.mem;
const meta = std.meta;
const os = std.os;
const process = std.process;
const time = std.time;

const Allocator = mem.Allocator;
const strToEnum = std.meta.stringToEnum;

const lib = @import("zinglib.zig");
const Datagrams = lib.Datagrams;


/// Crafting Errors.
pub const CraftingError = error{
    InvalidLayer,
    InvalidHeader,
    InvalidFooter,
};

/// Craft a new Datagram using a JSON file template.
pub fn newDatagramFile(alloc: mem.Allocator, filename: []const u8, layer: u3, headers: []const []const u8, data: []const u8, footer: []const u8) !Datagrams.Full {
    if (!(layer >= 2 and layer <= 4)) return CraftingError.InvalidLayer;

    log.info(
        \\
        \\Crafting a custom header:
        \\- File: {s}
        \\- Layer: {d}
        \\- Headers: {s}
        \\- Data: {s}
        \\- Footer: {s}
        \\
        , .{ filename, layer, headers, data, footer }
    );

    // Create Datagram Template Struct
    const en_datagram = Datagrams.Full.init(layer, headers, data, footer) catch |err| return err;

    // Encode
    try encodeDatagramToFile(alloc, en_datagram, filename, .json); 

    // Open JSON for editing
    try editDatagramFile(alloc, filename);

    // Decode
    return try decodeDatagram(alloc, filename); 
}

/// Config for `newDatagramFileCmd`().
pub const NewDatagramFileConfig = struct{
    filename: []const u8,
    layer: ?u3 = 2,
    l2_header: ?[]const u8 = "eth",
    l3_header: ?[]const u8 = "ip",
    l4_header: ?[]const u8 = "udp",
    data: ?[]const u8 = "",
    footer: ?[]const u8 = null,
};

/// Cova CLI wrapper for `newDatagramFile`().
pub fn newDatagramFileCmd(alloc: mem.Allocator, config: NewDatagramFileConfig) !Datagrams.Full {
    const all_headers = [_][]const u8{ config.l2_header.?, config.l3_header.?, config.l4_header.? };
    const headers = all_headers[(config.layer.? - 2)..];
    const footer = config.footer orelse config.l2_header.?;
    
    return try newDatagramFile(alloc, config.filename, config.layer.?, headers, config.data.?, footer);
}

/// Edit a Custom Datagram File. (Currently, these are only JSON encoded Datagrams.Full.)
pub fn editDatagramFile (alloc: Allocator, filename: []const u8) !void {
    // Edit File
    var editor = std.os.getenv("EDITOR") orelse "vi";
    var proc = process.Child.init(&[_][]const u8{ editor, filename }, alloc);
    defer _ = proc.kill() catch |err| log.err("The program was unable to kill the editor ({s}) child process:\n{}\n", .{ editor, err });

    var edit_fin = std.ChildProcess.Term.Unknown;
    while (edit_fin != .Exited) {
        edit_fin = proc.spawnAndWait() catch |err| {
            log.err("The program was unable to spawn the editor ({s}) child process:\n{}", .{ editor, err });
            return err;
        };
    }

    const file = try fs.openFileAbsolute(filename, .{});
    defer file.close();
    // Report Success
    const file_meta = try file.metadata();
    log.info(
        \\
        \\Packet encoded to JSON:
        \\- Name: {s}
        \\- Size: {d}B
        \\
        , .{ fs.path.basename(filename), file_meta.size() }
    );

    return;
} 

/// Formats for Encoding Datagrams.
pub const EncodeFormat = enum{
    /// Normal text
    txt,
    /// JSON
    json,
    /// Packet Capture (WIP)
    pcap,
};

/// Encode a Datagram (`en_datagram`) to the provided File (`filename`). 
pub fn encodeDatagramToFile(alloc: Allocator, en_datagram: Datagrams.Full, filename: []const u8, en_fmt: EncodeFormat) !void {
    // Write the JSON to the provided file
    const en_file = try fs.createFileAbsolute(filename, .{});
    defer en_file.close();
    try encodeDatagram(alloc, en_datagram, en_file.writer(), en_fmt);
}

/// Encode a Datagram (`en_datagram`) to the provided Writer (`writer`). (Currently only Datagrams.Full to JSON.)
pub fn encodeDatagram(alloc: Allocator, en_datagram: Datagrams.Full, writer: anytype, en_fmt: EncodeFormat) !void {
    switch (en_fmt) {
        .txt => {
            // Text Format
            const text_fmt = 
               \\
               \\ {d}:
               \\ {s}
               \\
            ;
            // Text Context
            const text_ctx = .{
                time.timestamp(),
                en_datagram,
            };
            // Write Text out
            try writer.print(text_fmt, text_ctx);
        },
        .json => {
            // Convert Datagram Template Struct to JSON
            const en_json = try json.stringifyAlloc(alloc, en_datagram, .{ .whitespace = .indent_4 });
            defer alloc.free(en_json);
            // Write the JSON out
            try writer.print("{s}\n\n", .{ en_json });
        },
        .pcap => log.warn("PCAP encoding is not yet supported.", .{}),
    }
}

/// Decode a Datagram. (Currently only JSON to Datagrams.Full.)
pub fn decodeDatagram(alloc: Allocator, filename: []const u8) !Datagrams.Full {
    // Read in the JSON file
    const de_file = try fs.openFileAbsolute(filename, .{});
    const de_file_buf = try de_file.reader().readUntilDelimiterOrEofAlloc(alloc, '\r', 8192) orelse return error.EmptyDatagramFile;
    defer alloc.free(de_file_buf);

    // Parse the JSON file
    @setEvalBranchQuota(10_000); //TODO - Test what's actually needed here? Or see if there's even a penalty for a higher number?
    //const stream = std.json.TokenStream.init(de_file_buf);
    //const de_datagram = try std.json.parse(Datagrams.Full, @constCast(&stream), .{ .allocator = alloc });
    const de_datagram = try json.parseFromSliceLeaky(Datagrams.Full, alloc, de_file_buf, .{ .allocate = .alloc_always });
    //defer json.parseFree(Datagrams.Full, de_datagram, .{ .allocator = alloc });
    return de_datagram;    
}
