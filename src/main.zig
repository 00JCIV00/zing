const std = @import("std");
const testing = std.testing;
const stdout = std.io.getStdOut().writer();
const Packets = @import("Packets.zig");
const BFG = @import("BitFieldGroup.zig");

test "convert from u8 to [8]u1" {
	const test_u8: u8 = 0b10110001;
	var test_u1_ary: [8]u1 = BFG.intToBitArray(test_u8) catch {};
//	inline for (&test_u1_ary, 0..) |*bit, idx|
//		bit.* = @truncate(u1, (std.math.pow(u8, 2, idx) & @bitReverse(test_u8)) >> (idx));
	std.debug.print("\nTest u8: {b:0>8}\nTest Array: {any}\n\n", .{ test_u8, test_u1_ary });
	try testing.expectEqual([_]u1{1,0,1,1,0,0,0,1}, test_u1_ary);
}

test "ip header creation" {
	var ip_header: Packets.IPHeader = .{
		//.version = 0,
		//.id = 1234,
		//.frag_offset = 20,
		//.time_to_live = 1,
		//.protocol = @enumToInt(Packets.IPHeader.Protocols.UDP),
		//.header_checksum = 0xFFFF,
		//.src_addr = 0xFFEEDDCC,
		//.dest_addr = 0xCCDDEEFF,
	};
	const ip_header_bitsize = @bitSizeOf(@TypeOf(ip_header)); 
	std.debug.print("\nIP Header Size: {d}b\n", .{ ip_header_bitsize });
	_ = try ip_header.writeBitInfo(testing.allocator, stdout, .{ .add_bit_ruler = true, .add_bitfield_title = true, });
	std.debug.print("\n", .{});
	try testing.expectEqual(@as(u8, 192), ip_header_bitsize);
}

test "udp packet creation" {
	var udp_packet: Packets.UDPPacket = .{
		.header = .{ 
			.src_port = 6969,
			.dest_port = 12345,
		},
	};
	udp_packet.ip_header.src_addr = 0xFFFFFF00;

	const udp_packet_bitsize = @bitSizeOf(@TypeOf(udp_packet)); 
	std.debug.print("\nUDP Header Size: {d}b\n", .{ udp_packet_bitsize });
	_ = try udp_packet.writeBitInfo(testing.allocator, stdout, .{ .add_bit_ruler = true, .add_bitfield_title = true, });
	std.debug.print("\n", .{});
	try testing.expectEqual(@as(u9, 256), udp_packet_bitsize);
}

test "tcp packet creation" {
	var tcp_packet: Packets.TCPPacket = .{
		.header = .{ 
			.src_port = 6969,
			.dest_port = 12345,
		},
	};
	tcp_packet.ip_header.src_addr = 0xFFFFFF00;

	const tcp_packet_bitsize = @bitSizeOf(@TypeOf(tcp_packet)); 
	std.debug.print("\nTCP Header Size: {d}b\n", .{ tcp_packet_bitsize });
	_ = try tcp_packet.writeBitInfo(testing.allocator, stdout, .{ .add_bit_ruler = true, .add_bitfield_title = true, });
	std.debug.print("\n", .{});
	try testing.expectEqual(@as(u9, 448), tcp_packet_bitsize);
}

test "icmp packet creation" {
	var icmp_packet: Packets.ICMPPacket = .{
		.header = .{ 
			.icmp_type = 5,
			.code = 1,
		},
	};
	icmp_packet.ip_header.src_addr = 0x00FFFF00;

	const icmp_packet_bitsize = @bitSizeOf(@TypeOf(icmp_packet)); 
	std.debug.print("\nICMP Header Size: {d}b\n", .{ icmp_packet_bitsize });
	_ = try icmp_packet.writeBitInfo(testing.allocator, stdout, .{ .add_bit_ruler = true, .add_bitfield_title = true, });
	std.debug.print("\n", .{});
	try testing.expectEqual(@as(u9, 256), icmp_packet_bitsize);
}
