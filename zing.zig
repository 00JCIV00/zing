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
const recv = lib.recv;
const interact = lib.interact;
const tools = lib.tools;

// Cova Lib
const cova = @import("cova");
const CommandT = cova.Command.Custom(.{ 
    .global_help_prefix = "Zing",
    .val_config = .{
        .custom_types = &.{ 
            u13,
            craft.EncodeFormat,
        },
    },
});

/// Craft Sub Command for Main Command
const craft_setup_cmd = CommandT{
    .name = "craft",
    .description = "Craft a new Network Datagram.",
    .cmd_group = "CRAFT",
    .sub_cmds = &.{
        CommandT.from(craft.NewDatagramFileConfig, .{
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
const send_setup_cmd = CommandT{
    .name = "send",
    .description = "Send a Network Datagram.",
    .cmd_group = "INTERACT",
    .sub_cmds = &.{
        CommandT.from(send.SendDatagramFileConfig, .{
            .cmd_name = "custom",
            .cmd_description = "Send a custom Network Datagram from a JSON file template on the provided interface.",
            .sub_descriptions = &.{
                .{ "filename", "Filename of the JSON Datagram template file to send as a Datagram." },
                .{ "if_name", "The Name of the Network Interface to use. Defaults to 'eth0'." },
            },
        }),
    },
};

/// Receive Sub Command for Main Command
const recv_setup_cmd = CommandT{
    .name = "recv",
    .description = "Receive a Network Datagram.",
    .cmd_group = "INTERACT",
    .sub_cmds = &.{
        CommandT.from(recv.RecvDatagramConfig, .{
            .cmd_name = "raw",
            .cmd_description = "Receive a raw Network Datagram from the provided interface.",
            .sub_descriptions = &.{
                .{ "if_name", "The Name of the Network Interface to receive from. Defaults to 'eth0'." },
                .{ "max_dg", "The Maximum number of Datagrams that are allowed in a Stream." },
            },
            .vals_mandatory = false,
        }),
    },
    .opts = &.{
        .{
            .name = "stream",
            .description = "Receive Datagrams as a Stream",
            .short_name = 's',
            .long_name = "stream",
            .val = CommandT.ValueT.ofType(bool, .{
                .name = "stream_val",
            }),
        }
    }
};

/// Setup for Record Command
const record_setup_cmd = CommandT.from(tools.RecordConfig, .{
    .cmd_name = "record",
    .cmd_description = "Record Datagrams to a File and/or stdout.",
    .sub_descriptions = &.{
        .{ "filename", "The File to record to." },
        .{ "enable_print", "Print to stdout." },
        .{ "dg_sep", "Datagram Separator, printed between each Datagram." },
    }
});

/// Setup for Main Command
const setup_cmd = CommandT{
    .name = "zing",
    .description = "A network datagram crafting tool.",
    .cmd_groups = &.{ "CRAFT", "INTERACT" },
    .sub_cmds = &.{
        craft_setup_cmd,
        send_setup_cmd,
        recv_setup_cmd,
        record_setup_cmd,
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
    //var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const stdout = std.io.getStdOut().writer();


    // Parse End-User Arguments
    const main_cmd = try setup_cmd.init(alloc, .{});
    defer main_cmd.deinit();
    var args_iter = try cova.ArgIteratorGeneric.init(alloc);
    defer args_iter.deinit();
    cova.parseArgs(&args_iter, CommandT, &main_cmd, stdout, .{}) catch |err| {
        switch (err) {
            error.UsageHelpCalled => return,
            error.TooManyValues,
            error.UnrecognizedArgument,
            error.UnexpectedArgument,
            error.CouldNotParseOption => {},
            else => |parse_err| return parse_err,
        }
    };

    // TODO - Figure out why the main_cmd must be referenced for ReleaseSafe and ReleaseSmall
    //log.info("{s}\n", .{ &main_cmd.name });
    //try cova.utils.displayCmdInfo(CommandT, main_cmd, alloc, stdout);

    // Open Message
    try stdout.print(
        \\    ________  ___  ________   ________
        \\   |\_____  \|\  \|\   ___  \|\   ____\
        \\    \|___/  /\ \  \ \  \\ \  \ \  \___|
        \\        /  / /\ \  \ \  \\ \  \ \  \  ___
        \\       /  /_/__\ \  \ \  \\ \  \ \  \|\  \
        \\      |\________\ \__\ \__\\ \__\ \_______\
        \\       \|_______|\|__|\|__| \|__|\|_______|
        \\
        \\ A Datagram Crafting and Network Interaction Tool.
        \\
        \\
    , .{});


    // Analyze End-User Arguments
    if (main_cmd.matchSubCmd("craft")) |craft_cmd| { 
        if (craft_cmd.matchSubCmd("custom")) |custom_cmd| {
            const datagram_config = try custom_cmd.to(craft.NewDatagramFileConfig, .{});
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
    }

    if (main_cmd.matchSubCmd("send")) |send_cmd| {
        if (send_cmd.matchSubCmd("custom")) |custom_cmd| {
            const send_dg_file_config = try custom_cmd.to(send.SendDatagramFileConfig, .{});
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
    }

    if (main_cmd.matchSubCmd("recv")) |recv_cmd| {
        if (recv_cmd.matchSubCmd("raw")) |raw_cmd| {
            const recv_raw_dg_config = try raw_cmd.to(recv.RecvDatagramConfig, .{});
            const recv_cmd_opts = try recv_cmd.getOpts();
            const stream = useStream: { break :useStream try (recv_cmd_opts.get("stream") orelse break :useStream false).val.getAs(bool); };
            if (stream) {
                var dg_buf = std.ArrayList(Datagrams.Full).init(alloc);
                try recv.recvDatagramStreamCmd(alloc, stdout, &dg_buf, recv_raw_dg_config);
            }
            else _ = try recv.recvDatagramCmd(alloc, recv_raw_dg_config);

        }
    }

    if (main_cmd.matchSubCmd("record")) |record_cmd| {
        const record_config = try record_cmd.to(tools.RecordConfig, .{});
        try tools.record(alloc, record_config);
    }
}
