//! Receive Datagrams

const std = @import("std");
const fs = std.fs;
const fmt = std.fmt;
const log = std.log;
const mem = std.mem;
const meta = std.meta;
const net = std.net;
const os = std.os;
const process = std.process;
const time = std.time;

const lib = @import("zinglib.zig");
const consts = lib.constants;
const Addresses = lib.Addresses;
const Datagrams = lib.Datagrams;

/// Receive Socket
pub const RecvSocket = struct{
    /// System Pointer to the Socket.
    ptr: os.socket_t,
    /// Interface Name.
    if_name: []const u8,
    /// Interface Hardware Family.
    hw_fam: u16, 
};

/// Create a Socket Connection to an Interface (`if_name`).
pub fn connectRecvSocket(if_name: []const u8) !RecvSocket {
    // Setup Socket
    var recv_sock = try os.socket(os.linux.AF.PACKET, os.linux.SOCK.RAW, consts.ETH_P_ALL);
    var if_name_ary: [16]u8 = .{ 0 } ** 16;
    mem.copy(u8, if_name_ary[0..], if_name);
    
    // - Interface Request
    var if_req = mem.zeroes(os.ifreq);
    if_req.ifrn.name = if_name_ary;

    // - Request Interface Family
    const ioctl_num = os.linux.ioctl(recv_sock, consts.SIOCGIFHWADDR, @intFromPtr(&if_req));
    if (ioctl_num != 0) {
        log.err("There was an issue getting the Hardware info for Interface '{s}': '{d}'.", .{ if_name, ioctl_num });
        return error.CouldNotGetInterfaceInfo;
    }
    const hw_fam = if_req.ifru.hwaddr.family;

    // - Interface Address
    var if_addr = os.sockaddr.ll{
        .family = os.linux.AF.PACKET,
        .protocol = consts.ETH_P_ALL,
        .pkttype = consts.PACKET_HOST,
        .halen = 6,
        .hatype = hw_fam,
        .addr = if_req.ifru.hwaddr.data[0..8].*,
        .ifindex = ifIdx: {
            // Request Interface Index
            try os.ioctl_SIOCGIFINDEX(recv_sock, &if_req);
            break :ifIdx if_req.ifru.ivalue;
        },
    };

    // - Bind to Socket
    os.bind(recv_sock, @as(*os.linux.sockaddr, @ptrCast(&if_addr)), @sizeOf(@TypeOf(if_addr))) catch return error.CouldNotConnectToInterface;

    return .{
        .ptr = recv_sock,
        .if_name = if_name,
        .hw_fam = hw_fam,
    };
}

/// Config for `recvDatagramCmd` and `recvDatagramStreamCmd`
pub const RecvDatagramConfig = struct{
    /// Interface Name
    if_name: []const u8 = "eth0",
};

/// Cova CLI Wrapper for `recvDatagram`().
pub fn recvDatagramCmd(alloc: mem.Allocator, config: RecvDatagramConfig) !Datagrams.Full {
    return recvDatagramInterface(alloc, config.if_name);
}

/// Receive a Layer 2 Datagram from the specified interface `(if_name)`.
pub fn recvDatagramInterface(alloc: mem.Allocator, if_name: []const u8) !Datagrams.Full {
    const recv_sock = try connectRecvSocket(if_name);
    defer os.closeSocket(recv_sock.ptr);
    return recvDatagram(alloc, recv_sock);
}

/// Receive a Layer 2 Datagram from the specified Socket `(recv_sock)`.
pub fn recvDatagram(alloc: mem.Allocator, recv_sock: RecvSocket) !Datagrams.Full {

    // Receive from Socket
    log.debug("Awaiting a Datagram from '{s}'...", .{ recv_sock.if_name });
    const max_frame_len: usize = switch (recv_sock.hw_fam) {
        consts.ARPHRD_ETHER => 1518,
        consts.ARPHRD_IEEE80211 => 2304,
        else => |if_fam| {
            log.err("Unrecognized Interface Family '{d}' for '{s}'.", .{ if_fam, recv_sock.if_name });
            return error.UnrecognizedInterfaceType;
        },
    };
    const recv_buf = try alloc.alloc(u8, max_frame_len);
    const recv_bytes = try os.recv(recv_sock.ptr, recv_buf[0..], 0);
    if (recv_bytes > max_frame_len) {
        log.warn("The number of received bytes '{d}B' is greater than the expected frame length '{d}B' for this interface '{s}'.", .{ 
            recv_bytes, 
            max_frame_len,
            recv_sock.if_name,
        });
        return error.UnexpectedlyLargeFrame;
    }
    const frame_buf = recv_buf[0..recv_bytes];
    log.debug("Received a {d}B Datagram.", .{ recv_bytes });

    var datagram: Datagrams.Full = undefined;

    // Layer 2
    const EthHeader = lib.Frames.EthFrame.Header;
    // TODO: Convert each Layer and sub-Type to their own functions since slice indexes must be compile time known.
    const l3_buf, const l3_type, const l2_footer_len: usize = l2Hdr: {
        switch (recv_sock.hw_fam) {
            consts.ARPHRD_ETHER => {
                log.debug("Ethernet Interface Detected.", .{});
                const eth_hdr_end = @bitSizeOf(EthHeader) / 8;
                var eth_hdr: EthHeader = @bitCast(frame_buf[0..eth_hdr_end].*);

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

                log.debug(
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

                datagram.l2_header = .{ .eth = eth_hdr };                
                break :l2Hdr .{ 
                    frame_buf[eth_hdr_end..], 
                    eth_type_raw, 
                    @bitSizeOf(lib.Frames.EthFrame.Footer) / 8,
                };
            },
            consts.ARPHRD_IEEE80211 => {
                log.debug("WiFi Interface Detected.", .{});
                log.debug("WiFi is not yet implemented. Stopping.", .{});
                return error.UnimplementedReceiveType;
            },
            else => |if_fam| {
                log.err("Unrecognized Interface Family '{d}' for '{s}'.", .{ if_fam, recv_sock.if_name });
                return error.UnrecognizedInterfaceType;
            },
        }
    };

    // Layer 3
    if (l3_type != EthHeader.EtherTypes.IPv4) {
        log.debug("Not an IPv4 Packet. Finished parsing.", .{});
        return error.UnimplementedReceiveType;
    }
    
    const IPHeader = lib.Packets.IPPacket.Header;
    const ip_hdr_end = (@bitSizeOf(IPHeader) / 8);
    var ip_hdr: IPHeader = @bitCast(l3_buf[0..ip_hdr_end].*);
    const l4_buf = l3_buf[ip_hdr_end..];
    
    const IPProtos = IPHeader.Protocols;
    const ip_proto = if (IPProtos.inEnum(ip_hdr.protocol)) ipProto: {
        break :ipProto switch (@as(IPProtos.Enum(), @enumFromInt(ip_hdr.protocol))) {
            inline else => |tag| @tagName(tag),
        };
    }
    else "UNKNOWN";

    log.debug(
        \\
        \\LAYER 3: IPv4
        \\SRC IP: {s}
        \\DST IP: {s}
        \\IP PROTO: {s}
        \\
        , .{
            try ip_hdr.src_ip_addr.toStr(alloc),
            try ip_hdr.dst_ip_addr.toStr(alloc),
            ip_proto,
        }
    );
    datagram.l3_header = .{ .ip = ip_hdr };

    // Layer 4
    if (!IPProtos.inEnum(ip_hdr.protocol)) return error.UnimplementedReceiveType;
    const payload_buf = switch (@as(IPProtos.Enum(), @enumFromInt(ip_hdr.protocol))) {
        .UDP => payload: {
            const UDPHeader = lib.Packets.UDPPacket.Header;
            const udp_hdr_end = (@bitSizeOf(UDPHeader) / 8);
            var udp_hdr: UDPHeader = @bitCast(l4_buf[0..udp_hdr_end].*);

            log.debug(
                \\
                \\LAYER 4: UDP
                \\SRC PORT: {d}
                \\DST PORT: {d}
                \\
                , .{
                    udp_hdr.src_port,
                    udp_hdr.dst_port,
                }
            );

            datagram.l4_header = .{ .udp = udp_hdr };
            break :payload l4_buf[udp_hdr_end..];
        },
        .TCP => payload: {
            const TCPHeader = lib.Packets.TCPPacket.Header;
            const tcp_hdr_end = (@bitSizeOf(TCPHeader) / 8);
            var tcp_hdr: TCPHeader = @bitCast(l4_buf[0..tcp_hdr_end].*);

            log.debug(
                \\
                \\LAYER 4: TCP
                \\SRC PORT: {d}
                \\DST PORT: {d}
                \\SEQ #: {d}
                \\
                , .{
                    tcp_hdr.src_port,
                    tcp_hdr.dst_port,
                    tcp_hdr.seq_num,
                }
            );

            datagram.l4_header = .{ .tcp = tcp_hdr };
            break :payload l4_buf[tcp_hdr_end..];
        },
        .ICMP => payload: {
            const ICMPHeader = lib.Packets.ICMPPacket.Header;
            const icmp_hdr_end = (@bitSizeOf(ICMPHeader) / 8);
            var icmp_hdr: ICMPHeader = @bitCast(l4_buf[0..icmp_hdr_end].*);

            const ICMPTypes = ICMPHeader.Types;
            const icmp_type = if (ICMPTypes.inEnum(icmp_hdr.icmp_type)) icmpType: {
                break :icmpType switch (@as(ICMPTypes.Enum(), @enumFromInt(icmp_hdr.icmp_type))) {
                    inline else => |tag| @tagName(tag),
                };
            }
            else "UNKNOWN";

            const ICMPCodes = ICMPHeader.Codes;
            var code_buf: [50]u8 = .{ 0 } ** 50;
            const icmp_code = if (ICMPCodes.DEST_UNREACHABLE.inEnum(icmp_hdr.code)) icmpCode: {
                break :icmpCode switch (@as(ICMPCodes.DEST_UNREACHABLE.Enum(), @enumFromInt(icmp_hdr.code))) {
                    inline else => |tag| try std.fmt.bufPrint(code_buf[0..], "DEST UNREACHABLE - {s}", .{ @tagName(tag) })
                };
            }
            else if (ICMPCodes.TIME_EXCEEDED.inEnum(icmp_hdr.code)) icmpCode: {
                break :icmpCode switch (@as(ICMPCodes.TIME_EXCEEDED.Enum(), @enumFromInt(icmp_hdr.code))) {
                    inline else => |tag| try std.fmt.bufPrint(code_buf[0..], "TIME EXCEEDED - {s}", .{ @tagName(tag) })
                };
            }
            else if (ICMPCodes.REDIRECT.inEnum(icmp_hdr.code)) icmpCode: {
                break :icmpCode switch (@as(ICMPCodes.REDIRECT.Enum(), @enumFromInt(icmp_hdr.code))) {
                    inline else => |tag| try std.fmt.bufPrint(code_buf[0..], "REDIRECT - {s}", .{ @tagName(tag) })
                };
            }
            else "UNKNOWN";

            log.debug(
                \\
                \\LAYER 4: ICMP
                \\TYPE: {s}
                \\CODE: {s}
                \\
                , .{
                    icmp_type,
                    icmp_code,
                }
            );

            datagram.l4_header = .{ .icmp = icmp_hdr };
            break :payload l4_buf[icmp_hdr_end..];
        },
        else => {
            log.debug("Not a parseable IP Protocol '{s}'. Finished parsing.", .{ ip_proto });
            return error.UnimplementedReceiveType;
        },
    };
        
    // Payload
    const payload_end = payload_buf.len - l2_footer_len;
    if (payload_end > 0) {
        log.debug(
            \\
            \\PAYLOAD (Size: {d}B):
            \\{s}
            \\
            , .{ 
                payload_end,
                payload_buf[0..payload_end],
            }
        );
        datagram.payload = payload_buf[0..payload_end];
    }
    else {
        log.debug("NO DEBUG", .{});
        datagram.payload = "";
    }

    // Footer
    const footer_buf = payload_buf[payload_end..(payload_end + 4)];
    switch(recv_sock.hw_fam) {
        consts.ARPHRD_ETHER => {
            const EthFooter = lib.Frames.EthFrame.Footer;
            var eth_footer: EthFooter = @bitCast(@as(*const [@sizeOf(EthFooter)]u8, @ptrCast(footer_buf)).*);

            log.debug(
                \\
                \\FOOTER: ETH
                \\FCS: {d}
                \\
                , .{ eth_footer.eth_frame_check_seq }
            );

            datagram.l2_footer = .{ .eth = eth_footer };
        },
        consts.ARPHRD_IEEE80211 => {},
        else => {},
    }

    return datagram;
}


/// Cova CLI Wrapper for `recvDatagramStream`().
pub fn recvDatagramStreamCmd(alloc: mem.Allocator, writer: anytype, config: RecvDatagramConfig) !void {
    return recvDatagramStream(alloc, writer, config.if_name);
}

/// Receiver a Stream of Datagrams.
pub fn recvDatagramStream(alloc: mem.Allocator, writer: anytype, if_name: []const u8) !void {
    const recv_sock = try connectRecvSocket(if_name);
    defer os.closeSocket(recv_sock.ptr);
    log.debug("Receiving Datagram Stream...\n", .{});
    while (true) {
        const datagram = recvDatagram(alloc, recv_sock) catch |err| switch (err) {
            error.UnimplementedReceiveType => continue,
            else => return err,
        };
        try writer.print(
            \\
            \\Datagram Received:
            \\{s}
            \\
            \\==============================
            \\
            \\
            , .{ datagram }
        );
    }
}


