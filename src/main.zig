const std = @import("std");
const testing = std.testing;
const stdout = std.io.getStdOut().writer();
const Packets = @import("Packets.zig");
const PacketBitFieldGroup = @import("PacketBitFieldGroup.zig");

//export fn add(a: i32, b: i32) i32 {
//    return a + b;
//}
//
//test "basic add functionality" {
//    try testing.expect(add(3, 7) == 10);
//}

fn createIPHeader() Packets.IPHeader {
	return .{
		.version = 0,
		.total_len = 192,
		.id = 1234,
		.frag_offset = 20,
		.time_to_live = 1,
		.protocol = @enumToInt(Packets.IPHeader.Protocols.UDP),
		.header_checksum = 0xFFFF,
		.src_addr = 0xFFEEDDCC,
		.dest_addr = 0xCCDDEEFF,
	};
}

test "ip header creation" {
	var ip_header = createIPHeader();
	const ip_header_bitsize = @bitSizeOf(@TypeOf(ip_header)); 
	std.debug.print("\nIP Header Size: {d}\n", .{ip_header_bitsize});
	try ip_header.writeBitInfo(testing.allocator, stdout, .{ .add_header = true, .add_bitfield_header = true, });
	std.debug.print("\n", .{});
	try testing.expectEqual(@as(u8, 192), ip_header_bitsize);
}

