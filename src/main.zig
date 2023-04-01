//! Tests for zacket-lib

const std = @import("std");
const testing = std.testing;
const stdout = std.io.getStdOut().writer();
const Addr = @import("Addresses.zig");
const Packets = @import("Packets.zig");
const BFG = @import("BitFieldGroup.zig");

test "convert from u8 to [8]u1" {
	const test_u8: u8 = 0b10110001;
	var test_u1_ary: [8]u1 = BFG.intToBitArray(test_u8) catch return;
//	inline for (&test_u1_ary, 0..) |*bit, idx|
//		bit.* = @truncate(u1, (std.math.pow(u8, 2, idx) & @bitReverse(test_u8)) >> (idx));
	std.debug.print("\nTest u8: {b:0>8}\nTest Array: {any}\n\n", .{ test_u8, test_u1_ary });
	try testing.expectEqual([_]u1{1,0,1,1,0,0,0,1}, test_u1_ary);
}

test "ipv4 address creation" {
	const ipv4 = Addr.IPv4.fromStr("192.168.0.1/24:8080") catch |err| {
		std.debug.print("\nIPv4 Creation Error: {}\n", .{ err });
		return;
	};
	const ipv4_be = std.mem.nativeToBig(u32, @bitCast(u32, ipv4));
	std.debug.print("\nSet IP: 192.168.0.1\nIP Binary: {b:0>32}\nIPv4 Struct:\n{}\nIPv4 Binary: {b:0>32}\n", .{ 
		0xC0A80001, 
		ipv4, 
		ipv4_be,
	});
	try testing.expectEqual(@as(u32, 0xC0A80001), ipv4_be);
}

test "ip header creation" {
	var ip_header: Packets.IPHeader = .{
		.version = 0,
		.id = 1234,
		.frag_offset = 20,
		.time_to_live = 1,
		.protocol = @enumToInt(Packets.IPHeader.Protocols.UDP),
		.header_checksum = 0xFFFF,
		.src_addr = Addr.IPv4.fromStr("10.10.10.1") catch return,
		.dest_addr = Addr.IPv4.fromStr("10.10.10.2") catch return,
	};
	const ip_header_bitsize = @bitSizeOf(@TypeOf(ip_header)); 
	std.debug.print("\nIP Header Size: {d}b, IP Header Kind: {s}\n", .{ ip_header_bitsize, @tagName(ip_header.getKind()) });
	_ = try ip_header.writeBitInfo(stdout, .{ .add_bit_ruler = true, .add_bitfield_title = true, });
	std.debug.print("\n", .{});
	try testing.expectEqual(@as(u8, 192), ip_header_bitsize);
}

test "icmp packet creation" {
	var icmp_packet: Packets.ICMPPacket = .{
		.header = .{ 
			.icmp_type = @enumToInt(Packets.ICMPPacket.Header.Types.DEST_UNREACHABLE),
			.code = @enumToInt(Packets.ICMPPacket.Header.Codes.DEST_UNREACHABLE.PROTOCOL),
		},
	};
	icmp_packet.ip_header.src_addr = Addr.IPv4.fromStr("192.168.55.200") catch return;

	const icmp_packet_bitsize = @bitSizeOf(@TypeOf(icmp_packet)); 
	std.debug.print("\nICMP Packet Size: {d}b\n", .{ icmp_packet_bitsize });
	_ = try icmp_packet.writeBitInfo(stdout, .{ .add_bit_ruler = true, .add_bitfield_title = true, });
	std.debug.print("\n", .{});
	try testing.expectEqual(@as(u9, 256), icmp_packet_bitsize);
}

test "udp packet creation" {
	var udp_packet: Packets.UDPPacket = .{
		.header = .{ 
			.src_port = 6969,
			.dest_port = 12345,
		},
	};
	udp_packet.ip_header.src_addr = Addr.IPv4.fromStr("172.31.128.10") catch return;

	const udp_packet_bitsize = @bitSizeOf(@TypeOf(udp_packet)); 
	std.debug.print("\nUDP Packet Size: {d}b, UDP Packet Kind: {s}\n", .{ udp_packet_bitsize, @tagName(udp_packet.getKind()) });
	_ = try udp_packet.writeBitInfo(stdout, .{ .add_bit_ruler = true, .add_bitfield_title = true, });
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
	tcp_packet.ip_header.src_addr = Addr.IPv4.fromStr("10.20.30.40") catch return;

	const tcp_packet_bitsize = @bitSizeOf(@TypeOf(tcp_packet)); 
	std.debug.print("\nTCP Packet Size: {d}b\n", .{ tcp_packet_bitsize });
	_ = try tcp_packet.writeBitInfo(stdout, .{ .add_bit_ruler = true, .add_bitfield_title = true, });
	std.debug.print("\n", .{});
	try testing.expectEqual(@as(u9, 448), tcp_packet_bitsize);
}


