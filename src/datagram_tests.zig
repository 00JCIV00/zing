//! Tests for zacket-lib

const std = @import("std");
const testing = std.testing;
const stdout = std.io.getStdOut().writer();

const lib = @import("lib.zig");
const Addr = lib.Addresses;
const Frames = lib.Frames;
const Packets = lib.Packets;
const BFG = lib.BitFieldGroup; 

test "convert from u8 to [8]u1" {
    const test_u8: u8 = 0b10110001;
    var test_u1_ary: [8]u1 = BFG.intToBitArray(test_u8) catch return;
    std.debug.print("\nTest u8: {b:0>8}\nTest Array: {any}\n\n", .{ test_u8, test_u1_ary });
    try testing.expectEqual([_]u1{ 1, 0, 1, 1, 0, 0, 0, 1 }, test_u1_ary);
}

test "mac address creation" {
    const set_mac = 0xA1B2C3D4E5F6;
    const mac = Addr.MAC.fromStr("A1:B2:C3:D4:E5:F6") catch |err| {
        std.debug.print("\nMAC Creation Error: {}\n", .{err});
        return;
    };
    const mac_be = std.mem.nativeToBig(u48, @bitCast(mac));
    std.debug.print("\nSet MAC: {x}\nCreated MAC: {x}\nCreated MAC Struct:\n{}\n\n", .{
        set_mac,
        mac_be,
        mac,
    });
    try testing.expectEqual(@as(u48, set_mac), mac_be);
}

test "ipv4 address creation" {
    const ipv4 = Addr.IPv4.fromStr("192.168.0.1/24:8080") catch |err| {
        std.debug.print("\nIPv4 Creation Error: {}\n", .{err});
        return;
    };
    const ipv4_be = std.mem.nativeToBig(u32, @bitCast(ipv4));
    std.debug.print("\nSet IP: 192.168.0.1\nIP Binary: {b:0>32}\nIPv4 Struct:\n{}\nIPv4 Binary: {b:0>32}\n\n", .{
        0xC0A80001,
        ipv4,
        ipv4_be,
    });
    try testing.expectEqual(@as(u32, 0xC0A80001), ipv4_be);
}

test "ethernet frame creation" {
    var eth_frame = (Frames.EthFrame.initBFGEncapHeader(.{}, Packets.ICMPPacket{}) catch return){};
    const eth_frame_type = @TypeOf(eth_frame);
    const eth_frame_size = @bitSizeOf(eth_frame_type);
    std.debug.print("\nEth Frame:\n- Size: {d}b\n- Kind: {s}\n- Name: {s}\n", .{
        eth_frame_size,
        @tagName(eth_frame_type.bfg_kind),
        eth_frame_type.bfg_name,
    });
    _ = try eth_frame.formatToText(stdout, .{
        .add_bit_ruler = true,
        .add_bitfield_title = true,
    });
    std.debug.print("\n", .{});
    try testing.expectEqual(@as(u16, 368), eth_frame_size);
}

test "ip header creation" {
    var ip_header: Packets.IPPacket.Header = .{
        .version = 0,
        .id = 1234,
        .frag_offset = 20,
        .time_to_live = 1,
        .protocol = @intFromEnum(Packets.IPPacket.Header.Protocols.UDP),
        .header_checksum = 0xFFFF,
        .src_ip_addr = Addr.IPv4.fromStr("10.10.10.1") catch return,
        .dst_ip_addr = Addr.IPv4.fromStr("10.10.10.2") catch return,
    };
    const ip_header_type = @TypeOf(ip_header);
    const ip_header_bitsize = @bitSizeOf(ip_header_type);
    std.debug.print("\nIP Header:\n- Size: {d}b\n- Kind: {s}\n- Name: {s}\n", .{
        ip_header_bitsize,
        @tagName(ip_header_type.bfg_kind),
        ip_header_type.bfg_name,
    });
    _ = try ip_header.formatToText(stdout, .{
        .add_bit_ruler = true,
        .add_bitfield_title = true,
    });
    std.debug.print("\n", .{});
    try testing.expectEqual(@as(u8, 192), ip_header_bitsize);
}

test "icmp packet creation" {
    var icmp_packet: Packets.ICMPPacket = .{
        .header = .{
            .icmp_type = @intFromEnum(Packets.ICMPPacket.Header.Types.DEST_UNREACHABLE),
            .code = @intFromEnum(Packets.ICMPPacket.Header.Codes.DEST_UNREACHABLE.PROTOCOL),
        },
    };
    icmp_packet.ip_header.src_ip_addr = Addr.IPv4.fromStr("192.168.55.200") catch return;

    const icmp_packet_type = @TypeOf(icmp_packet);
    const icmp_packet_bitsize = @bitSizeOf(icmp_packet_type);
    std.debug.print("\nICMP Packet:\n- Size: {d}b\n- Kind: {s}\n- Name: {s}\n", .{
        icmp_packet_bitsize,
        @tagName(icmp_packet_type.bfg_kind),
        icmp_packet_type.bfg_name,
    });
    _ = try icmp_packet.formatToText(stdout, .{
        .add_bit_ruler = true,
        .add_bitfield_title = true,
    });
    std.debug.print("\n", .{});
    try testing.expectEqual(@as(u9, 256), icmp_packet_bitsize);
}

test "udp packet creation" {
    var udp_packet: Packets.UDPPacket = .{
        .header = .{
            .src_port = 6969,
            .dst_port = 12345,
        },
    };
    udp_packet.ip_header.src_ip_addr = Addr.IPv4.fromStr("172.31.128.10") catch return;

    const udp_packet_type = @TypeOf(udp_packet);
    const udp_packet_bitsize = @bitSizeOf(udp_packet_type);
    std.debug.print("\nUDP Packet:\n- Size: {d}b\n- Kind: {s}\n- Name: {s}\n", .{
        udp_packet_bitsize,
        @tagName(udp_packet_type.bfg_kind),
        udp_packet_type.bfg_name,
    });
    _ = try udp_packet.formatToText(stdout, .{
        .add_bit_ruler = true,
        .add_bitfield_title = true,
    });
    std.debug.print("\n", .{});
    try testing.expectEqual(@as(u9, 256), udp_packet_bitsize);
}

test "tcp packet creation" {
    var tcp_packet: Packets.TCPPacket = .{
        .header = .{
            .src_port = 6969,
            .dst_port = 12345,
        },
    };
    tcp_packet.ip_header.src_ip_addr = Addr.IPv4.fromStr("10.20.30.40") catch return;

    const tcp_packet_type = @TypeOf(tcp_packet);
    const tcp_packet_bitsize = @bitSizeOf(tcp_packet_type);
    std.debug.print("\nTCP Packet:\n- Size: {d}b\n- Kind: {s}\n- Name: {s}\n", .{
        tcp_packet_bitsize,
        @tagName(tcp_packet_type.bfg_kind),
        tcp_packet_type.bfg_name,
    });
    _ = try tcp_packet.formatToText(stdout, .{
        .add_bit_ruler = true,
        .add_bitfield_title = true,
    });
    std.debug.print("\n", .{});
    try testing.expectEqual(@as(u9, 448), tcp_packet_bitsize);
}

test "initialized full packet creation" {
    var full_packet = (Frames.EthFrame.initBFG(.{
            .src_mac_addr = Addr.MAC.fromStr("AB:CD:EF:12:34:56") catch return,
            .dst_mac_addr = Addr.MAC.fromStr("DE:AD:BE:EF:01:23") catch return,
        }, 
        (Packets.IPPacket.initBFGEncapHeader(.{
                .protocol = @intFromEnum(Packets.IPPacket.Header.Protocols.UDP),
                .src_ip_addr = Addr.IPv4.fromStr("10.10.10.1") catch return,
                .dst_ip_addr = Addr.IPv4.fromStr("10.10.10.2") catch return,
            }, 
            Packets.UDPPacket.Header{
                .src_port = 32123,
                .dst_port = 12321,
        }) catch return){}, 
        "Hello World", 
        .{ .eth_frame_check_seq = 100 }
    ) catch return){};

    const full_packet_type = @TypeOf(full_packet);
    const full_packet_bitsize = @bitSizeOf(full_packet_type);
    std.debug.print("\nFull Packet:\n- Size: {d}b\n- Kind: {s}\n- Layer: {d}\n- Name: {s}\n", .{
        full_packet_bitsize,
        @tagName(full_packet_type.bfg_kind),
        full_packet_type.bfg_layer,
        full_packet_type.bfg_name,
    });
    _ = try full_packet.formatToText(stdout, .{
        .add_bit_ruler = true,
        .add_bitfield_title = true,
    });
    std.debug.print("\n", .{});
    try testing.expectEqual(@as(u9, 464), full_packet_bitsize);
}

test "raw full packet creation" { 
    const payload = "Raw Full Packet!!!";
    const payload_type = @TypeOf(payload);
    const full_packet_type = packed struct {
        wifi_header: Frames.WifiFrame.Header = .{},
        ip_header: Packets.IPPacket.Header = .{},
        udp_header: Packets.UDPPacket.Header = .{},
        data: payload_type = payload,
        wifi_footer: Frames.WifiFrame.Footer = .{},

        pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = .FRAME, .layer = 2, .name = "RawFrame" });
    };
    
    var full_packet = full_packet_type{};
    const full_packet_bitsize = @bitSizeOf(full_packet_type);
    std.debug.print("\nFull Packet:\n- Size: {d}b\n- Kind: {s}\n- Layer: {d}\n- Name: {s}\n", .{
        full_packet_bitsize,
        @tagName(full_packet_type.bfg_kind),
        full_packet_type.bfg_layer,
        full_packet_type.bfg_name,
    });
    std.debug.print("Payload:\n- Size: {d}b\n- Type: {s}\n\n", .{
        @bitSizeOf(payload_type),
        @typeName(payload_type),
    });
    _ = try full_packet.formatToText(stdout, .{
        .add_bit_ruler = true,
        .add_bitfield_title = true,
    });
    try testing.expectEqual(@as(u10, 800), full_packet_bitsize);

}
