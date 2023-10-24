//! Receive Datagrams

const std = @import("std");
const stdout = std.io.getStdOut().writer();
const fs = std.fs;
const fmt = std.fmt;
const linux = os.linux;
const log = std.log;
const mem = std.mem;
const meta = std.meta;
const net = std.net;
const os = std.os;
const process = std.process;

const eql = mem.eql;
const socket = os.socket;
const sleep = std.time.sleep;
const strToEnum = std.meta.stringToEnum;

const lib = @import("zinglib.zig");
const Addresses = lib.Addresses;
const Datagrams = lib.Datagrams;

/// Config for `recvDatagramCmd` and `recvDatagramStreamCmd`
pub const RecvDatagramConfig = struct{
    /// Interface Name
    if_name: []const u8 = "eth0",
};

/// Cova CLI Wrapper for `recvDatagram`().
pub fn recvDatagramCmd(alloc: mem.Allocator, writer: anytype, config: RecvDatagramConfig) !void {
    return recvDatagram(alloc, writer, config.if_name);
}

/// Receive a Layer 2 Datagram from the specified interface `(if_name)`.
/// (WIP) Parameters on contents chaning rapidly.
pub fn recvDatagram(alloc: mem.Allocator, writer: anytype, if_name: []const u8) !void {
    //_ = alloc;

    // Linux Interface Constants. Found in .../linux/if_ether.h, if_arp.h, if_socket.h, etc
    const ETH_P_ALL = mem.nativeToBig(u16, 0x03);

    // Setup Socket
    var recv_sock = try socket(linux.AF.PACKET, linux.SOCK.RAW, ETH_P_ALL);
    defer os.closeSocket(recv_sock);
    var if_name_ary: [16]u8 = .{0} ** 16;
    mem.copy(u8, if_name_ary[0..], if_name);

    // Receive from Socket
    log.info("Receiving a Datagram from '{s}'...", .{ if_name });
    var recv_buf: [1518]u8 = .{ 0 } ** 1518;
    const recv_bytes = try os.recv(recv_sock, recv_buf[0..], 0);
    log.info("Received {d} bytes.", .{ recv_bytes });

    // Layer 2
    const EthHeader = lib.Frames.EthFrame.Header;
    const eth_hdr_end = @bitSizeOf(EthHeader) / 8;
    var eth_hdr: EthHeader = @bitCast(recv_buf[0..eth_hdr_end].*);
    
    _ = try eth_hdr.formatToText(writer, .{});
    const src_mac = eth_hdr.src_mac_addr;
    const dst_mac = eth_hdr.dst_mac_addr;
    const eth_type_raw = mem.bigToNative(u16, eth_hdr.ether_type);

    const EthTypes = EthHeader.EtherTypes;
    const eth_type = if (EthTypes.inEnum(eth_type_raw)) ethType: { 
        switch (@as(EthTypes.Enum(), @enumFromInt(eth_type_raw))) {
            inline else => |tag| break :ethType @tagName(tag),
        }
    }
    else if (eth_type_raw <= 1500) "802.3 - Payload Size"
    else "Unknown";
        
    log.info(
        \\
        \\LAYER 2: ETH
        \\SRC MAC: {s}
        \\DST MAC: {s}
        \\ETH TYPE: {s}
        \\
        , .{
            try src_mac.toStr(alloc),
            try dst_mac.toStr(alloc),
            eth_type,
        }
    );

    // Layer 3
    if (eth_type_raw != EthTypes.IPv4) {
        log.info("Not an IPv4 Packet. Finished parsing.", .{});
        return;
    }
    
    const IPHeader = lib.Packets.IPPacket.Header;
    const ip_hdr_end = eth_hdr_end + (@bitSizeOf(IPHeader) / 8);
    var ip_hdr: IPHeader = @bitCast(recv_buf[eth_hdr_end..ip_hdr_end].*);
    
    _ = try ip_hdr.formatToText(stdout, .{});
    const src_ip = ip_hdr.src_ip_addr;
    const dst_ip = ip_hdr.dst_ip_addr;
    const ip_proto_raw = ip_hdr.protocol;

    const IPProtos = IPHeader.Protocols;
    const ip_proto = if (IPProtos.inEnum(ip_proto_raw)) ipProto: {
        break :ipProto switch (@as(IPProtos.Enum(), @enumFromInt(ip_proto_raw))) {
            inline else => |tag| @tagName(tag),
        };
    }
    else "UNKNOWN";

    log.info(
        \\
        \\LAYER 3: IPv4
        \\SRC IP: {s}
        \\DST IP: {s}
        \\IP PROTO: {s}
        \\
        , .{
            try src_ip.toStr(alloc),
            try dst_ip.toStr(alloc),
            ip_proto,
        }
    );

    // Layer 4
    switch (@as(IPProtos.Enum(), @enumFromInt(ip_proto_raw))) {
        .UDP => {
            const UDPHeader = lib.Packets.UDPPacket.Header;
            const udp_hdr_end = ip_hdr_end + (@bitSizeOf(UDPHeader) / 8);
            var udp_hdr: UDPHeader = @bitCast(recv_buf[ip_hdr_end..udp_hdr_end].*);

            _ = try udp_hdr.formatToText(stdout, .{});
            const src_port = udp_hdr.src_port;
            const dst_port = udp_hdr.dst_port;

            log.info(
                \\
                \\LAYER 4: UDP
                \\SRC PORT: {d}
                \\DST PORT: {d}
                \\
                , .{
                    src_port,
                    dst_port,
                }
            );

        },
        .TCP => {
            const TCPHeader = lib.Packets.TCPPacket.Header;
            const tcp_hdr_end = ip_hdr_end + (@bitSizeOf(TCPHeader) / 8);
            var tcp_hdr: TCPHeader = @bitCast(recv_buf[ip_hdr_end..tcp_hdr_end].*);

            _ = try tcp_hdr.formatToText(stdout, .{});
            const src_port = tcp_hdr.src_port;
            const dst_port = tcp_hdr.dst_port;
            const seq_num = tcp_hdr.seq_num;

            log.info(
                \\
                \\LAYER 4: TCP
                \\SRC PORT: {d}
                \\DST PORT: {d}
                \\SEQ #: {d}
                \\
                , .{
                    src_port,
                    dst_port,
                    seq_num,
                }
            );

        },
        .ICMP => {
            log.info("ICMP Packet!", .{});
        },
        else => {
            log.info("Not a parseable IP Protocol '{s}'. Finished parsing.", .{ ip_proto });
        },
    }
        
    
}


/// Cova CLI Wrapper for `recvDatagramStream`().
pub fn recvDatagramStreamCmd(alloc: mem.Allocator, writer: anytype, config: RecvDatagramConfig) !void {
    return recvDatagramStream(alloc, writer, config.if_name);
}

/// Receiver a Stream of Datagrams.
pub fn recvDatagramStream(alloc: mem.Allocator, writer: anytype, if_name: []const u8) !void {
    log.info("Receiving Datagram Stream...", .{});
    while (true) {
        try recvDatagram(alloc, writer, if_name);
        try stdout.print(
        \\
        \\==============================
        \\
        \\
        , .{}
        );
    }
}


