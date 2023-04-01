//! Abstractions for commonly used Network Addresses.

const std = @import("std");
const BFG = @import("BitFieldGroup.zig");

/// IPv4
pub const IPv4 = packed struct (u32) {
	const Self = @This();

	first: u8 = 0,
	second: u8 = 0,
	third: u8 = 0,
	fourth: u8 = 0,

	pub const Any = std.mem.zeroes(Self);
	pub const loopback = fromStr("127.0.0.1");

	/// Create an IPv4 Address from a String
	pub fn fromStr(str: []const u8) !Self {
		// Parse out port data
		var port_tokens = std.mem.tokenize(u8, str, ":");
		_ = port_tokens.next();
		const port = port_tokens.next();
		_ = port;

		// Parse out CIDR data
		port_tokens.reset();
		const cidr_str = port_tokens.next() orelse {
			std.debug.print("\nThe provided string '{s}' is not a valid IPv4 address.\n", .{ str });
			return error.InvalidIPv4String;
		};
		var cidr_tokens = std.mem.tokenize(u8, cidr_str, "/");
		_ = cidr_tokens.next();
		const cidr = cidr_tokens.next();
		_ = cidr;

		// Parse out IP data
		cidr_tokens.reset();
		const ip_str = cidr_tokens.next() orelse {
			std.debug.print("\nThe provided string '{s}' is not a valid IPv4 address.\n", .{ str });
			return error.InvalidIPv4String;
		};
		var ip_tokens = std.mem.tokenize(u8, ip_str, ".");
		
		var ip_out: Self = .{};
		
		var idx: u8 = 0;
		while (ip_tokens.next()) |byte| : (idx += 1) { 
			const field = switch (idx) { 
				0 => &ip_out.first,
				1 => &ip_out.second,
				2 => &ip_out.third,
				3 => &ip_out.fourth,
				else => return error.CannotParseToIPv4,
			};
			field.* = std.fmt.parseInt(u8, byte, 10) catch |err| {
				std.debug.print("\nThere was an error while parsing the provided string '{s}':\n{}\n", .{ str, err });
				return error.InvalidIPv4String;
			};
		}

		return ip_out;
	}

	pub usingnamespace BFG.implBitFieldGroup(@This(), .{});
};
