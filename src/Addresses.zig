//! Abstractions for commonly used Network Addresses.

const std = @import("std");
const BFG = @import("BitFieldGroup.zig");

/// IPv4
pub const IPv4 = packed struct(u32) {
    first: u8 = 0,
    second: u8 = 0,
    third: u8 = 0,
    fourth: u8 = 0,

    // Equivalent to 0.0.0.0
    pub const Any = std.mem.zeroes(@This());
    // This could be any 127.0.0.0/8, but is set to the common 127.0.0.1 for convenience.
    pub const Loopback = fromStr("127.0.0.1");

    /// Create an IPv4 Address from a String
    pub fn fromStr(str: []const u8) !@This() {
        // Parse out port data
        var port_tokens = std.mem.tokenize(u8, str, ":");
        _ = port_tokens.next();
        const port = port_tokens.next();
        _ = port;

        // Parse out CIDR data
        port_tokens.reset();
        const cidr_str = port_tokens.next() orelse {
            std.debug.print("\nThe provided string '{s}' is not a valid IPv4 address.\n", .{str});
            return error.InvalidIPv4String;
        };
        var cidr_tokens = std.mem.tokenize(u8, cidr_str, "/");
        _ = cidr_tokens.next();
        const cidr = cidr_tokens.next();
        _ = cidr;

        // Parse out IP data
        cidr_tokens.reset();
        const ip_str = cidr_tokens.next() orelse {
            std.debug.print("\nThe provided string '{s}' is not a valid IPv4 address.\n", .{str});
            return error.InvalidIPv4String;
        };
        var ip_tokens = std.mem.tokenize(u8, ip_str, ".");

        var ip_out: @This() = .{};

        var idx: u8 = 0;
        while (ip_tokens.next()) |byte| : (idx += 1) {
            const field = switch (idx) {
                0 => &ip_out.first,
                1 => &ip_out.second,
                2 => &ip_out.third,
                3 => &ip_out.fourth,
                else => return error.InvalidIPv4String,
            };
            field.* = std.fmt.parseInt(u8, byte, 10) catch |err| {
                std.debug.print("\nThere was an error while parsing the provided string '{s}':\n{}\n", .{ str, err });
                return error.InvalidIPv4String;
            };
        }

        return ip_out;
    }

    /// Return the MAC Address as a ByteArray [6]u8
    pub fn toByteArray(self: *@This()) [6]u8 {
        return [_]u8{ self.first, self.second, self.third, self.fourth };
    }

    pub usingnamespace BFG.implBitFieldGroup(@This(), .{});
};

// TODO IPv6

/// MAC
pub const MAC = packed struct(u48) {
    first: u8 = 0,
    second: u8 = 0,
    third: u8 = 0,
    fourth: u8 = 0,
    fifth: u8 = 0,
    sixth: u8 = 0,

    /// Create a MAC Address from a string.
    pub fn fromStr(str: []const u8) !@This() {
        const symbols = [_][]const u8{ ":", "-", " " };
        const delimiter = setDelim: for (symbols) |symbol| {
            if (std.mem.containsAtLeast(u8, str, 5, symbol)) break :setDelim symbol;
        } else {
            std.debug.print("The provided string '{s}' is not a valid MAC Address.", .{str});
            return error.InvalidMACString;
        };
        var mac_tokens = std.mem.tokenize(u8, str, delimiter);

        var mac_out: @This() = .{};
        var idx: u8 = 0;
        while (mac_tokens.next()) |byte| : (idx += 1) {
            const field = switch (idx) {
                0 => &mac_out.first,
                1 => &mac_out.second,
                2 => &mac_out.third,
                3 => &mac_out.fourth,
                4 => &mac_out.fifth,
                5 => &mac_out.sixth,
                else => return error.InvalidMACString,
            };
            field.* = std.fmt.parseInt(u8, byte, 16) catch |err| {
                std.debug.print("\nThere was an error while parsing the provided string '{s}':\n{}\n", .{ str, err });
                return error.InvalidMACString;
            };
        }
        return mac_out;
    }

    /// Return the MAC Address as a ByteArray [6]u8
    pub fn toByteArray(self: *@This()) [6]u8 {
        return [_]u8{ self.first, self.second, self.third, self.fourth, self.fifth, self.sixth };
    }

    pub usingnamespace BFG.implBitFieldGroup(@This(), .{});
};
