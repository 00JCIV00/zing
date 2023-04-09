//! A small Zig tool to craft and send basic packets based on IETF specifications.

// Standard Lib
const std = @import("std");
const process = std.process;
// - Functions
const eql = std.mem.eql;
const lowerString = std.ascii.lowerString;
const parseInt = std.fmt.parseInt;

//Zing Lib
const lib = @import("src/lib.zig");
pub const Datagrams = lib.Datagrams;
pub const craft = lib.craft;


pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();
    defer {
        const leaked = gpa.deinit();
        if (leaked) std.debug.print("UH OH! WE LEAKED!\n", .{});
    }

    // TODO improve argument handling. Maybe use zig-clap?
    const args = try process.argsAlloc(alloc);
    defer alloc.free(args);
    if (args.len == 0) {
        std.debug.print("Please provide arguments.\n", .{});
        return;
    }
    const main_cmd = args[1];
    const sub_cmds = args[2..];
    
    if (eql(u8, main_cmd, "craft")) {
        var craft_kind_buf: [50]u8 = undefined;
        const craft_kind = sanitize(sub_cmds[0], &craft_kind_buf);
        if (eql(u8, craft_kind, "custom")) {
            const filename = sub_cmds[1];
            const layer = try parseInt(u3, sub_cmds[2], 10);
            const l_diff = 7 - layer;
            const headers = sub_cmds[3..l_diff + 1]; 
            const data = sub_cmds[l_diff + 1];
            const footer = sub_cmds[l_diff + 2];
            
            _ = craft.packetFile(alloc, filename, layer, headers, data, footer) catch |err| {
                switch (err) {
                    craft.CraftingError.InvalidLayer => std.debug.print("Invalid Layer! All layers must be between 2-4 (inclusive).\n", .{}),
                    craft.CraftingError.InvalidHeader => std.debug.print("Invalid Header! Please see the documentation for valid Header options.\n", .{}),
                    else => return err,
                }
                return;
            };
            return;
        }
        else if (eql(u8, craft_kind, "basic")) {
            std.debug.print("Basic Packet (WIP)\n", .{});
            return;
        }
        else {
            std.debug.print("Unrecognized craft kind: '{s}'. Craft kinds are 'basic' or 'custom'.\n", .{ craft_kind });
        }
    }
}

/// Sanitize the given input string. (Currently just makes it lowercase.)
pub fn sanitize(str: []const u8, buf: []u8) []u8 {
    return lowerString(buf, str);
}

