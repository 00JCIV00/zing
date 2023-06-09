//! A small Zig tool to craft and send basic packets based on IETF specifications.

// Standard Lib
const std = @import("std");
const stdout = std.io.getStdOut().writer();
const json = std.json;
const os = std.os;
const process = std.process;
// - Functions
const eql = std.mem.eql;
const lowerString = std.ascii.lowerString;
const parseInt = std.fmt.parseInt;
const sleep = std.time.sleep;
const strToEnum = std.meta.stringToEnum;

// Zing Lib
const lib = @import("zinglib");
const Addresses = lib.Addresses;
const Datagrams = lib.Datagrams;
const craft = lib.craft;
const send = lib.send;

// Cova Lib
const cova = @import("cova");
const Command = cova.Command.Custom(.{ .global_help_prefix = "Zing" });
const Value = cova.Value;


pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa_alloc = gpa.allocator();
    defer {
        const leaked = gpa.deinit();
        if (leaked == .leak) std.debug.print("UH OH! WE LEAKED!\n", .{});
    }
    var arena = std.heap.ArenaAllocator.init(gpa_alloc);
    defer arena.deinit();
    const alloc = arena.allocator();

    // TODO improve argument handling. Maybe use zig-clap?
    const args = try process.argsAlloc(alloc);
    defer alloc.free(args);
    if (args.len == 0) {
        std.debug.print("Please provide arguments.\n", .{});
        return;
    }
    const main_cmd = strToEnum(main_cmds, args[1]) orelse {
        std.debug.print("No command '{s}'. Please use one of the following:\ncraft, send\n", .{ args[1] });
        return;   
    };
    const sub_cmds = args[2..];
    // TODO - Figure out how to sanitize lists of strings. Maybe just use an allocator?
    //var sub_cmds_buf: [20][50]u8 = undefined;
    //const sub_cmds = sanitizeList(sub_cmds_raw, &sub_cmds_buf)[0..sub_cmds_raw.len];
    
    switch (main_cmd) {
        .craft => {
            var datagram: ?Datagrams.Full = craftDG: {
                var craft_kind_buf: [50]u8 = undefined;
                const craft_kind = sanitize(sub_cmds[0], &craft_kind_buf);
                if (eql(u8, craft_kind, "custom")) {
                    const filename = sub_cmds[1];
                    const layer = try parseInt(u3, sub_cmds[2], 10);
                    const l_diff = 7 - layer;
                    const headers = sub_cmds[3..l_diff + 1]; 
                    const data = sub_cmds[l_diff + 1];
                    const footer = sub_cmds[l_diff + 2];
                    
                    break :craftDG craft.newDatagramFile(alloc, filename, layer, headers, data, footer) catch |err| {
                        switch (err) {
                            error.FileNotFound => std.debug.print("Couldn't locate File! Please double check the '{s}' file.\n", .{ filename }),
                            error.EmptyDatagramFile => std.debug.print("Empty Datagram File! Please double check the '{s}' file.\n", .{ filename }),
                            error.InvalidLayer => std.debug.print("Invalid Layer! All layers must be between 2-4 (inclusive).\n", .{}),
                            error.InvalidHeader => std.debug.print("Invalid Header! Please see the documentation for valid Header options.\n", .{}),
                            else => return err,
                        }
                        return;
                    };
                }
                else if (eql(u8, craft_kind, "basic")) {
                    std.debug.print("Basic Packet (WIP)\n", .{});
                    return;
                }
                else {
                    std.debug.print("Unrecognized craft kind: '{s}'. Craft kinds are 'basic' or 'custom'.\n", .{ craft_kind });
                    return;
                }
            };
            std.debug.print("\nCustom Packet:\n", .{});
            _ = try datagram.?.formatToText(stdout, .{
                .add_bit_ruler = true,
                .add_bitfield_title = true
            });
            return;
        },
        .send => {
            const sub_cmd = strToEnum(send_sub_cmds, sub_cmds[0]) orelse {
                std.debug.print("No sub-command '{s}' for 'send'. Please use one of the following:\ncustom, basic\n", .{ sub_cmds[0] });
                return;
            };
            switch (sub_cmd) {
                .custom => {
                    const filename = sub_cmds[1];
                    const if_name = sub_cmds[2];

                    send.sendDatagramFile(alloc, filename, if_name) catch |err| {
                        switch(err) {
                            error.FileNotFound => std.debug.print("Couldn't locate File! Please double check the '{s}' file.\n", .{ filename }),
                            error.CouldNotConnectToInterface => std.debug.print(\\There was an issue connecting to the provided interface '{s}'.
                                                                                \\Please double-check the interface name and status using 'ip a' or 'ifconfig'.
                                                                                \\Error: {}
                                                                                \\
                                                                                , .{ if_name, err }),
                            //error.CouldNotOpenPromiscuous => std.debug.print("There was an issue opening the socket in Promiscuous Mode:\n{s}\n", .{ os.errno() }),
                            error.CouldNotWriteData => std.debug.print("There was an issue writing the data:\n{}\n", .{ err }),
                            else => return err,
                        }
                    };

                },
                .basic => {},
            } 
        },
    }
}

// TODO - Write your own arg parser? (Commands, Options, Values)
/// Zing Main Commands
const main_cmds = enum {
    craft,
    send,
};

/// - Craft Sub Commands
const craft_sub_cmds = enum {
    custom,
    basic,
    edit,
};

/// - Send Sub Commands
const send_sub_cmds = enum {
    custom,
    basic,
};

/// Sanitize the given input string. (Currently just makes it lowercase.)
pub fn sanitize(str: []const u8, buf: []u8) []u8 {
    return lowerString(buf, str);
}
/// Sanitize the given list of input strings. (TODO - use an allocator)
pub fn sanitizeList(list: [][]const u8, buf: [][]u8) [][]u8 {
    for (list, buf[0..list.len]) |raw, san| _ = sanitize(raw, san);
    return buf;
}
