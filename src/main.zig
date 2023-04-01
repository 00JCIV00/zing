const std = @import("std");
const testing = std.testing;
const stdout = std.io.getStdOut().writer();
const Packets = @import("Packets.zig");
const BFG = @import("BitFieldGroup.zig");

//export fn add(a: i32, b: i32) i32 {
//    return a + b;
//}
//
//test "basic add functionality" {
//    try testing.expect(add(3, 7) == 10);
//}

fn createIPHeader() Packets.IPHeader {
	return .{
		//.version = 0,
		//.id = 1234,
		//.frag_offset = 20,
		//.time_to_live = 1,
		//.protocol = @enumToInt(Packets.IPHeader.Protocols.UDP),
		//.header_checksum = 0xFFFF,
		//.src_addr = 0xFFEEDDCC,
		//.dest_addr = 0xCCDDEEFF,
	};
}

test "convert from u8 to [8]u1" {
	const test_u8: u8 = 0b10110001;
	var test_u1_ary: [8]u1 = BFG.intToBitArray(test_u8) catch {};
//	inline for (&test_u1_ary, 0..) |*bit, idx|
//		bit.* = @truncate(u1, (std.math.pow(u8, 2, idx) & @bitReverse(test_u8)) >> (idx));
	std.debug.print("\nTest u8: {b:0>8}\nTest Array: {any}\n", .{ test_u8, test_u1_ary });
	try testing.expectEqual([_]u1{1,0,1,1,0,0,0,1}, test_u1_ary);
}

test "ip header creation" {
	var ip_header = createIPHeader();
	const ip_header_bitsize = @bitSizeOf(@TypeOf(ip_header)); 
	std.debug.print("\nIP Header Size: {d}b\n", .{ip_header_bitsize});
	_ = try ip_header.writeBitInfo(testing.allocator, stdout, .{ .add_header = true, .add_bitfield_header = true, });
	std.debug.print("\n", .{});
	try testing.expectEqual(@as(u8, 192), ip_header_bitsize);
}


