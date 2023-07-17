//! A small Zig tool to craft and send basic packets based on IETF specifications.

// Standard Lib
const std = @import("std");
const json = std.json;
const mem = std.mem;
const meta = std.meta;
const log = std.log;
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


/// Craft Sub Command for Main Command
const craft_cmd = Command{
    .name = "craft",
    .description = "Craft a new Network Datagram.",
    .sub_cmds = &.{
        Command.from(craft.NewDatagramFileConfig, .{
            .cmd_name = "custom",
            .cmd_description = "Craft a new Datagram using a JSON file template.",
            .sub_descriptions = &.{
                .{ "filename", "Filename of the JSON Datagram template file to craft this Datagram." },
                .{ "layer", "The OSI Model Network Layer for this Datagram. Supported Layers: 2 (default) - 4." },
                .{ "l2_header", "The type of Layer 2 Header for this Datagram. Supported types: 'eth' (default) and 'wifi'." },
                .{ "l3_header", "The type of Layer 3 Header for this Datagram. Supported types: 'ip' (default) and 'icmp' (wip)." },
                .{ "l4_header", "The type of Layer 4 Header for this Datagram. Supported types: 'udp' (default) and 'tcp'." },
                .{ "data", "The data payload for this Datagram. This is a slice of bytes, which is typically just represented as a string." },
                .{ "footer", "The type of Layer 2 Footer for this Datagram. Supported types: 'eth' and 'wifi'. This will default to whatever l2_header is set to." },
            },  
        }),
    },
};

/// Send Sub Command for Main Command
const send_cmd = Command{
    .name = "send",
    .description = "Send a Network Datagram.",
    .sub_cmds = &.{
        Command.from(send.SendDatagramFileConfig, .{
            .cmd_name = "custom",
            .cmd_description = "Send a custom Network Datagram from a JSON file template on the provided interface.",
            .sub_descriptions = &.{
                .{ "filename", "Filename of the JSON Datagram template file to send as a Datagram." },
                .{ "if_name", "The Name of the Network Interface to use. Defaults to 'eth0'." },
            },
        }),
    },
};

/// Setup for Main Command
const setup_cmd = Command{
    .name = "zing",
    .description = "A network datagram crafting tool.",
    .sub_cmds = &.{
        craft_cmd,
        send_cmd,
    }, 
};

pub fn main() !void {
    // Setup
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa_alloc = gpa.allocator();
    defer {
        const leaked = gpa.deinit();
        if (leaked == .leak) log.warn("Memory leak detected!\n", .{});
    }
    var arena = std.heap.ArenaAllocator.init(gpa_alloc);
    defer arena.deinit();
    const alloc = arena.allocator();
    const stdout = std.io.getStdOut().writer();

    // Parse End-User Arguments
    const main_cmd = &(try setup_cmd.init(alloc, .{}));
    defer main_cmd.deinit();
    var args_iter = try cova.ArgIteratorGeneric.init(alloc);
    defer args_iter.deinit();
    cova.parseArgs(&args_iter, Command, main_cmd, stdout, .{}) catch |err| {
        switch (err) {
            error.UsageHelpCalled => return,
            else => |parse_err| return parse_err,
        }
    };

    // Analyze End-User Arguments
    const sub_cmd = main_cmd.sub_cmd orelse {
        log.err("A command for 'zing' was expected but was not given.\n", .{});
        try main_cmd.usage(stdout);
        return;
    };

    if (mem.eql(u8, sub_cmd.name, "craft")) { 
        const craft_sub_cmd = sub_cmd.sub_cmd orelse {
            log.err("A command for 'craft' was expected but was not given.\n", .{});
            try main_cmd.usage(stdout);
            return;
        };
        if (mem.eql(u8, craft_sub_cmd.name, "custom")) {
            const datagram_config = try craft_sub_cmd.to(craft.NewDatagramFileConfig, .{});
            var datagram: Datagrams.Full = craft.newDatagramFileCmd(alloc, datagram_config) catch |err| {
                switch (err) {
                    error.FileNotFound => log.err("Couldn't locate File! Please double check the '{s}' file.\n", .{ datagram_config.filename }),
                    error.EmptyDatagramFile => log.err("Empty Datagram File! Please double check the '{s}' file.\n", .{ datagram_config.filename }),
                    error.InvalidLayer => log.err("Invalid Layer! All layers must be between 2-4 (inclusive).\n", .{}),
                    error.InvalidHeader => log.err("Invalid Header! Please see the documentation for valid Header options.\n", .{}),
                    else => return err,
                }
                return;
            };
            try stdout.print("\nCustom Network Datagram:\n", .{});
            _ = try datagram.formatToText(stdout, .{
                .add_bit_ruler = true,
                .add_bitfield_title = true,
                //.enable_detailed_strings = true,
            });
            return;
        }
        else log.warn("The Sub Command '{s}' is not yet implemented.", .{ craft_sub_cmd.name });

    }

    if (mem.eql(u8, sub_cmd.name, "send")) {
        const send_sub_cmd = sub_cmd.sub_cmd orelse {
            log.err("A command for 'send' was expected but was not given.\n", .{});
            try main_cmd.usage(stdout);
            return;
        };
        if (mem.eql(u8, send_sub_cmd.name, "custom")) {
            const send_dg_file_config = try send_sub_cmd.to(send.SendDatagramFileConfig, .{});
            send.sendDatagramFileCmd(alloc, send_dg_file_config) catch |err| {
                switch(err) {
                    error.FileNotFound => log.err("Couldn't locate File! Please double check the '{s}' file.\n", .{ send_dg_file_config.filename }),
                    error.CouldNotConnectToInterface => log.err(
                        \\There was an issue connecting to the provided interface '{?s}'.
                        \\Please double-check the interface name and status using 'ip a' or 'ifconfig'.
                        \\Error: {}
                        \\
                        , .{ send_dg_file_config.if_name, err }),
                    //error.CouldNotOpenPromiscuous => log.err("There was an issue opening the socket in Promiscuous Mode:\n{s}\n", .{ os.errno() }),
                    error.CouldNotWriteData => log.err("There was an issue writing the data:\n{}\n", .{ err }),
                    else => return err,
                }
            };
            return;
        }
        else log.warn("The Sub Command '{s}' is not yet implemented.", .{ send_sub_cmd.name });
    }

    else log.warn("The Sub Command '{s}' is not yet implemented.", .{ sub_cmd.name });
}

/// Sanitize the given input string. (Currently just makes it lowercase.)
pub fn sanitize(str: []const u8, buf: []u8) []u8 {
    return lowerString(buf, str);
}
/// Sanitize the given list of input strings. (TODO - use an allocator)
pub fn sanitizeList(list: [][]const u8, buf: [][]u8) [][]u8 {
    for (list, buf[0..list.len]) |raw, san| _ = sanitize(raw, san);
    return buf;
}
