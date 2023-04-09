//! Functions for Crafting Packets

const std = @import("std");
const fs = std.fs;
const process = std.process;

const strToEnum = std.meta.stringToEnum;

const lib = @import("lib.zig");
const Datagrams = lib.Datagrams;

pub const CraftingError = error {
    InvalidLayer,
    InvalidHeader,
};

pub fn packetFile(alloc: std.mem.Allocator, filename: []const u8, layer: u3, headers: []const []const u8, data: []const u8, footer: []const u8) !Datagrams.Full {
    if (!(layer >= 2 and layer <= 4)) return CraftingError.InvalidLayer;

    std.debug.print(\\Crafting a custom header. (WIP):
                    \\- File: {s}
                    \\- Layer: {d}
                    \\- Headers: {s}
                    \\- Data: {s}
                    \\- Footer: {s}
                    \\
                    , .{ filename, layer, headers, data, footer });

    // Create Datagram Template Struct
    const en_datagram = Datagrams.Full {
        .l2_header = if (layer > 2) .{ .eth = .{} } else l2Hdr: {
            const l2_hdr_tag = strToEnum(std.meta.Tag(Datagrams.Layer2Header), headers[0]) orelse return CraftingError.InvalidHeader;
            break :l2Hdr @unionInit(Datagrams.Layer2Header, @tagName(l2_hdr_tag), .{});
        },
    };

    // Encode
    {
        // - Convert Datagram Template Struct to JSON
        const en_json = try std.json.stringifyAlloc(alloc, en_datagram, .{ .whitespace = .{
            .indent = .Tab,
            .separator = true,
        } });
        defer alloc.free(en_json);

        // - Write the JSON to a file
        const en_file = try fs.createFileAbsolute(filename, .{});
        defer en_file.close();
        _ = try en_file.writeAll(en_json);
    }

    // Open JSON for editing
    var editor = std.os.getenv("EDITOR") orelse "vi";
    var proc = process.Child.init(&[_][]const u8{ editor, filename }, alloc);
    defer _ = proc.kill() catch |err| std.debug.print("The program was unable to kill the editor ({s}) child process:\n{}\n", .{ editor, err });

    var edit_fin = std.ChildProcess.Term.Unknown;
    while (edit_fin != .Exited) {
        edit_fin = proc.spawnAndWait() catch |err| {
            std.debug.print("The program was unable to spawn the editor ({s}) child process:\n{}", .{ editor, err });
            return err;
        };
    }

    const file = try fs.openFileAbsolute(filename, .{});
    defer file.close();

    return Datagrams.Full{}; 
}
