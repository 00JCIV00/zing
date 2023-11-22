//! Components of the base Packet structure for IP, ICMP, TCP, and UDP packets.

const std = @import("std");
const mem = std.mem;

const BFG = @import("BitFieldGroup.zig");
const Addr = @import("Addresses.zig");
const consts = @import("constants.zig");
const utils = @import("utils.zig");

/// IP Packet - [IETC RFC 791](https://datatracker.ietf.org/doc/html/rfc791#section-3.1)
pub const IPPacket = struct{
    header: Header = .{},
    options: ?[]Option = null,
    pseudo_header: ?SegmentPseudoHeader = null,
    len: u16 = 20,

    /// IP Header
    pub const Header = packed struct{
        version: u4 = 4,
        ip_header_len: u4 = 5,
        service_type: ServiceType = .{},
        total_len: u16 = 20,

        id: u16 = 0,
        flags: Flags = .{},
        frag_offset: u13 = 0,

        time_to_live: u8 = 64,
        protocol: u8 = Protocols.UDP, 
        header_checksum: u16 = 0,

        src_ip_addr: Addr.IPv4 = .{},

        dst_ip_addr: Addr.IPv4 = .{},

        //options: u24 = 0, // TODO Create Options packed struct. Probably as a separate struct outside of the Header.
        //padding: u8 = 0,

        /// IP Header Service Type Info
        pub const ServiceType = packed struct(u8){
            precedence: u3 = ServicePrecedence.ROUTINE,
            delay: u1 = 0,
            throughput: u1 = 0,
            relibility: u1 = 0,
            reserved: u2 = 0,

            pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{});
        };

        /// IP Header Flags Info
        pub const Flags = packed struct(u3){
            reserved: bool = false,
            dont_frag: bool = true,
            more_frags: bool = false,

            pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{});
        };


        // IP Packet Service Precedence Levels
        pub const ServicePrecedence = struct{
            pub const ROUTINE: u3 = 0;
            pub const PRIORITY: u3 = 1;
            pub const IMMEDIATE: u3 = 2;
            pub const FLASH: u3 = 3;
            pub const FLASH_OVERRIDE: u3 = 4;
            pub const CRITIC: u3 = 5;
            pub const INTERNETWORK_CONTROL: u3 = 6;
            pub const NETWORK_CONTROL: u3 = 7;

            pub usingnamespace utils.ImplEnumerable(@This());
        };

        /// IP Protocols
        pub const Protocols = struct{
            pub const ICMP: u8 = 1;
            pub const IGMP: u8 = 2;
            pub const TCP: u8 = 6;
            pub const UDP: u8 = 17;
            pub const ENCAP: u8 = 41;
            pub const OSPF: u8 = 89;
            pub const SCTP: u8 = 132;

            pub usingnamespace utils.ImplEnumerable(@This());
        };


        /// Calculate the Total Length and Checksum of this IP Packet
        pub fn calcLengthAndChecksum(self: *@This(), alloc: mem.Allocator, _: ?[]const u8, opts_len: u16, payload: []const u8) !void {
            const hdr_len: u16 = @bitSizeOf(IPPacket.Header) / 8; 
            self.total_len = hdr_len + @as(u16, @intCast(payload.len));
            self.ip_header_len = @truncate((hdr_len + opts_len) / 4);

            self.header_checksum = 0;
            const header_bytes = try self.asNetBytesBFG(alloc);
            self.header_checksum = calcChecksum(header_bytes);
        }

        pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ 
            .kind = BFG.Kind.HEADER, 
            .layer = 3,
        });
    };

    /// Segment Pseudo Header
    /// Does NOT include the Segment Length, which is handled at the Segment level (Layer 4).
    pub const SegmentPseudoHeader = packed struct(u80){
        src_ip_addr: Addr.IPv4 = .{},
        
        dst_ip_addr: Addr.IPv4 = .{},
        
        protocol: u16 = Header.Protocols.UDP,

        pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ 
            .kind = BFG.Kind.HEADER, 
            .layer = 3,
        });
    };

    /// IP Options
    pub const Option = struct{
        opt_type: OptionType = .{},
        len: ?u8 = null,
        data: ?[]const u8 = null,

        /// Create a new IP Option from the provided Byte Buffer (`byte_buf`).
        pub fn from(byte_buf: []const u8) !@This() {
            if (byte_buf.len == 0) return error.EmptyByteBuffer;
            if (!OptionTypes.inEnum(byte_buf[0])) return error.UnimplementedType;
            return switch (@as(OptionTypes.Enum(), @enumFromInt(byte_buf[0]))) {
                .END_OF_OPTS, .NO_OP => .{ 
                    .opt_type = @bitCast(byte_buf[0]),
                    .data = byte_buf[3..7],
                },
                else =>  .{
                    .opt_type = @bitCast(byte_buf[0]),
                    .len = byte_buf[1],
                    .data = byte_buf[2..(byte_buf[1] + (4 - (byte_buf[1] % 4 )))],
                }
            };
        }
        
        /// IP Option Type
        pub const OptionType = packed struct{
            copied_flag: bool = false,
            opt_class: u2 = 0,
            opt_num: u5 = 0,

            pub const OptionClasses = struct{
                pub const CONTROL: u2 = 0;
                pub const RESERVED: u2 = 1;
                pub const DEBUG: u2 = 2;
                pub const RESERVED2: u2 = 3;

                pub usingnamespace utils.ImplEnumerable(@This());
            };

            pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{});
        };

        /// IP Option Types
        pub const OptionTypes = struct{
            pub const END_OF_OPTS: u8 = 0;
            pub const NO_OP: u8 = 1;
            pub const RECORD_ROUTE: u8 = 7;
            pub const TIMESTAMP: u8 = 68;
            pub const SECURITY: u8 = 130;
            /// Loose Source and Record Route
            pub const LSRR: u8 = 131;
            pub const STREAM_ID: u8 = 136;
            /// Strict Source and Record Route
            pub const SSRR: u8 = 137;

            pub usingnamespace utils.ImplEnumerable(@This());
        };

        /// IP Option Lengths
        pub fn getLength(opt_type: OptionTypes.Enum) u8 {
            return switch (opt_type) {
                .RECORD_ROUTE => 0,
                .TIMESTAMP => 0,
                .SECURITY => 11,
                .LSRR => 131,
                .STREAM_ID => 136,
                .SSRR => 137,
                else => 0,
            };
        }
        
        pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ 
            .kind = BFG.Kind.OPTION, 
            .layer = 3,
        });
    };

    /// Create a new IP Packet from the provided Byte Buffer (`byte_buf`) using the provided Allocator (`alloc`).
    pub fn from(alloc: mem.Allocator, byte_buf: []const u8) !@This() {
        const hdr_end: u16 = @bitSizeOf(Header) / 8;
        if (byte_buf.len < hdr_end) return error.UnexpectedlySmallBuffer;
        var size_buf: [@sizeOf(Header)]u8 = .{ 0 } ** @sizeOf(Header);
        for (size_buf[0..hdr_end], byte_buf[0..hdr_end]) |*s, b| s.* = b;
        var hdr: Header = mem.bytesToValue(Header, size_buf[0..]);
        try hdr.toLSB();
        const ip_len: u16 = hdr.ip_header_len * @as(u16, 4);
        //const ip_len: u16 = @intCast(hdr.ip_header_len * 4);
        const p_hdr_end: u16 = ip_len + @as(u16, switch (@as(Header.Protocols.Enum(), @enumFromInt(hdr.protocol))) {
            .TCP, .UDP => @bitSizeOf(SegmentPseudoHeader) / 8,
            else => 0,
        });
        return .{
            .header = hdr,
            .options = 
                if (ip_len > 20) opts: {
                    const opts_raw_buf = byte_buf[hdr_end..ip_len];
                    var opts_list = std.ArrayList(Option).init(alloc);
                    var idx: u16 = 0;
                    while (idx < opts_raw_buf.len) {
                        const opt = try Option.from(opts_raw_buf[idx..]);
                        idx += @bitSizeOf(@TypeOf(opt));
                        try opts_list.append(opt);
                    }
                    break :opts try opts_list.toOwnedSlice();
                }
                else null,
            .pseudo_header = 
                if (p_hdr_end -| hdr_end > 0) pHdr: {
                    const pseudo_size = @bitSizeOf(SegmentPseudoHeader) / 8;
                    var pseudo_buf: [@sizeOf(SegmentPseudoHeader)]u8 = .{ 0 } ** @sizeOf(SegmentPseudoHeader);
                    for (pseudo_buf[0..pseudo_size], byte_buf[hdr_end..(hdr_end + pseudo_size)]) |*s, b| s.* = b;
                    break :pHdr mem.bytesToValue(SegmentPseudoHeader, pseudo_buf[0..]);
                }
                else null,
            .len = ip_len,
        };
    }
    
    pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ 
        .kind = BFG.Kind.PACKET, 
        .layer = 3, 
        .name = "IP_Packet" 
    });
};

/// ARP Packet - [IETF RFC 826](https://datatracker.ietf.org/doc/html/rfc826)
pub const ARPPacket = packed struct{
    header: Header = .{},

    pub const Header = packed struct{
        hw_type: u16 = consts.ARPHRD_ETHER,
        proto_type: u16 = 0x0800,
        hw_addr_len: u8 = 6,
        proto_addr_len: u8 = 4,
        op_code: u16 = OpCodes.REQUEST,
        sender_hw_addr: Addr.MAC = .{},
        sender_proto_addr: Addr.IPv4 = .{},
        tgt_hw_addr: Addr.MAC = mem.zeroes(Addr.MAC),
        tgt_proto_addr: Addr.IPv4 = .{},

        pub const OpCodes = struct{
            pub const REQUEST: u16 = 1;
            pub const REPLY: u16 = 2;

            pub usingnamespace utils.ImplEnumerable(@This());
        };

        pub fn calcCRC(_: @This(), _: mem.Allocator, _: []const u8) !void {}

        pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ 
            .kind = BFG.Kind.HEADER, 
            .layer = 3,
        });
    };

    pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ 
        .kind = BFG.Kind.PACKET, 
        .layer = 3, 
        .name = "ARP_Packet" 
    });
};

/// ICMP Packet - [IETF RFC 792](https://datatracker.ietf.org/doc/html/rfc792)
pub const ICMPPacket = packed struct{
    // Layer 4
    header: ICMPPacket.Header = .{},

    /// ICMP Header
    pub const Header = packed struct(u64) {
        icmp_type: u8 = Types.DEST_UNREACHABLE,
        code: u8 = Codes.DEST_UNREACHABLE.NET,
        checksum: u16 = 0,

        // TODO - Create an Option for the final Word (32-bit) which can vary.
        id: u16 = 1,
        seq_num: u16 = 0,

        /// ICMP Types
        pub const Types = struct{
            pub const ECHO_REPLY: u8 = 0;
            pub const DEST_UNREACHABLE: u8 = 3;
            pub const SRC_QUENCH: u8 = 4;
            pub const REDIRECT: u8 = 5;
            pub const ECHO: u8 = 8;
            pub const TIME_EXCEEDED: u8 = 11;
            pub const PARAM_PROBLEM: u8 = 12;
            pub const TIMESTAMP: u8 = 13;
            pub const TIMESTAMP_REPLY: u8 = 14;
            pub const INFO_REQUEST: u8 = 15;
            pub const INFO_REPLY: u8 = 16;

            pub usingnamespace utils.ImplEnumerable(@This());
        };

        /// ICMP Codes
        pub const Codes = struct{
            pub const DEST_UNREACHABLE = struct{
                pub const NET: u8 = 0;
                pub const HOST: u8 = 1;
                pub const PROTOCOL: u8 = 2;
                pub const PORT: u8 = 3;
                pub const FRAG_NEEDED: u8 = 4;
                pub const SRC_ROUTE_FAILED: u8 = 5;
                
                pub usingnamespace utils.ImplEnumerable(@This());
            };
            pub const TIME_EXCEEDED = struct{
                pub const TTL: u8 = 0;
                pub const FRAG_REASSEMBLY: u8 = 1;

                pub usingnamespace utils.ImplEnumerable(@This());
            };
            pub const REDIRECT = struct{
                pub const NETWORK: u8 = 0;
                pub const HOST: u8 = 1;
                pub const TOS_AND_NETWORK: u8 = 2;
                pub const TOS_AND_HOST: u8 = 3;

                pub usingnamespace utils.ImplEnumerable(@This());
            };
        };

        /// Calculates the total Length (in Bytes) and the Checksum (from 16-bit words) of this ICMP Header with the given payload.
        pub fn calcLengthAndChecksum(self: *@This(), alloc: mem.Allocator, _: ?[]const u8, _: u16, payload: []const u8) !void {
            var icmp_hdr_bytes = try self.asNetBytesBFG(alloc);
            const icmp_bytes = try mem.concat(alloc, u8, &.{ icmp_hdr_bytes[0..], payload });
            defer alloc.free(icmp_bytes);

            self.checksum = calcChecksum(icmp_bytes);
        }

        pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ 
            .kind = BFG.Kind.HEADER, 
            .layer = 3 
        });
    };

    pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ 
        .kind = BFG.Kind.PACKET, 
        .layer = 4, 
        .name = "ICMP_Packet" 
    });
};

/// UDP Packet - [IETF RFC 768](https://datatracker.ietf.org/doc/html/rfc768)
pub const UDPPacket = packed struct{
    // Layer 3
    ip_header: IPPacket.Header = .{
        .version = 4,
        .protocol = IPPacket.Header.Protocols.UDP,
    },
    // Layer 4
    header: UDPPacket.Header = .{},

    /// UDP Header
    pub const Header = packed struct(u64) {
        src_port: u16 = 0,
        dst_port: u16 = 0,

        length: u16 = 8,
        checksum: u16 = 0,

        /// Calculates the total Length (in Bytes) and the Checksum (from 16-bit words) of this UDP Header with the given payload.
        pub fn calcLengthAndChecksum(self: *@This(), alloc: mem.Allocator, pseudo_header: ?[]const u8, _: u16, payload: []const u8) !void {
            const pseudo_hdr = pseudo_header orelse return error.MissingSegmentHeader;
            self.length = @intCast(@bitSizeOf(@This()) / 8 + payload.len);
            var udp_hdr_bytes = try self.asNetBytesBFG(alloc);
            const udp_bytes = try mem.concat(alloc, u8, &.{ pseudo_hdr, udp_hdr_bytes[4..6], udp_hdr_bytes[0..], payload });
            defer alloc.free(udp_bytes);

            self.checksum = calcChecksum(udp_bytes);
        }

        pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ 
            .kind = BFG.Kind.HEADER, 
            .layer = 4,
        });
    };

    pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ 
        .kind = BFG.Kind.PACKET, 
        .layer = 4, 
        .name = "UDP_Packet" 
    });
};

/// TCP Packet - [IETF RFC 9293](https://www.ietf.org/rfc/rfc9293.html)
pub const TCPPacket = struct{
    // Layer 3
    ip_header: IPPacket.Header = .{
        .version = 4,
        .protocol = IPPacket.Header.Protocols.TCP,
    },
    // Layer 4
    header: Header = .{},
    options: ?[]Option = null,
    len: u16 = 20,

    /// TCP Header
    pub const Header = packed struct{
        src_port: u16 = 0,
        dst_port: u16 = 0,

        seq_num: u32 = 0,

        ack_num: u32 = 0,

        data_offset: u4 = 5,
        reserved: u4 = 0,
        flags: Flag = .{},
        window: u16 = 0,

        checksum: u16 = 0,
        urg_pointer: u16 = 0,

        pub const Flag = packed struct(u8) {
            cwr: bool = false,
            ece: bool = false,
            urg: bool = false,
            ack: bool = false,
            psh: bool = false,
            rst: bool = false,
            syn: bool = false,
            fin: bool = true,

            pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{});
        };
        pub const Flags = struct{
            pub const CWR: u8 = @bitReverse(@as(u8, 0b10000000));
            pub const ECE: u8 = @bitReverse(@as(u8, 0b01000000));
            pub const URG: u8 = @bitReverse(@as(u8, 0b00100000));
            pub const ACK: u8 = @bitReverse(@as(u8, 0b00010000));
            pub const PSH: u8 = @bitReverse(@as(u8, 0b00001000));
            pub const RST: u8 = @bitReverse(@as(u8, 0b00000100));
            pub const SYN: u8 = @bitReverse(@as(u8, 0b00000010));
            pub const FIN: u8 = @bitReverse(@as(u8, 0b00000001));
        };

        
        /// Calculates the total Length (in Bytes) and the Checksum (from 16-bit words) of this UDP Header with the given payload.
        pub fn calcLengthAndChecksum(self: *@This(), alloc: mem.Allocator, pseudo_header: ?[]const u8, opts_len: u16, payload: []const u8) !void {
            const pseudo_hdr = pseudo_header orelse return error.MissingSegmentHeader;

            self.data_offset = @as(u4, @intCast(@bitSizeOf(@This()) / 32)) + if (opts_len > 0) @as(u4, @truncate(opts_len / 4)) else 0;
            var tcp_hdr_bytes = try self.asNetBytesBFG(alloc);
            const tcp_hdr_len: u16 = mem.nativeToBig(u16, @as(u16, @truncate(tcp_hdr_bytes.len)) + @as(u16, @truncate(payload.len)));

            const tcp_bytes = try mem.concat(alloc, u8, &.{ pseudo_hdr, &@as([2]u8, @bitCast(tcp_hdr_len)), tcp_hdr_bytes[0..], payload });
            defer alloc.free(tcp_bytes);

            self.checksum = calcChecksum(tcp_bytes);
        }

        pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ 
            .kind = BFG.Kind.HEADER, 
            .layer = 4 
        });
    };

    /// TCP Option
    pub const Option = struct{
        kind: u8 = 0,
        len: ?u8 = null,
        data: ?[]const u8 = null,

        /// Create a new TCP Option from the provided Byte Buffer (`byte_buf`).
        pub fn from(byte_buf: []const u8) !@This() {
            if (byte_buf.len == 0) return error.EmptyByteBuffer;
            return switch (@as(OptionKinds.Enum(), @enumFromInt(byte_buf[0]))) {
                .END_OF_OPTS, .NO_OP => .{ .kind = @bitCast(byte_buf[0]) },
                else =>  .{
                    .kind = @bitCast(byte_buf[0]),
                    .len = byte_buf[1],
                    .data = byte_buf[2..(byte_buf[1] + (4 - (byte_buf[1] % 4 )))],
                }
            };
        }

        pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ 
            .kind = BFG.Kind.OPTION, 
            .layer = 4,
        });
    };
    /// TCP Option Kinds
    pub const OptionKinds = struct{
        pub const END_OF_OPTS: u8 = 0;
        pub const NO_OP: u8 = 1;
        pub const MAX_SEG_SIZE: u8 = 2;

        pub usingnamespace utils.ImplEnumerable(@This());
    };

    /// Create a new TCP Packet from the provided Byte Buffer (`byte_buf`) using the provided Allocator (`alloc`).
    pub fn from(alloc: mem.Allocator, byte_buf: []const u8) !@This() {
        const hdr_end = @bitSizeOf(Header) / 8;
        if (byte_buf.len < hdr_end) return error.UnexpectedlySmallBuffer;
        var size_buf: [@sizeOf(Header)]u8 = .{ 0 } ** @sizeOf(Header);
        for (size_buf[0..hdr_end], byte_buf[0..hdr_end]) |*s, b| s.* = b;
        var hdr: Header = mem.bytesToValue(Header, size_buf[0..]);
        try hdr.toLSB();
        const tcp_end = hdr.data_offset * @as(u16, 4);
        return .{
            .header = hdr,
            .options = 
                if (hdr_end > 20) opts: {
                    const opts_raw_buf = byte_buf[hdr_end..tcp_end];
                    var opts_list = std.ArrayList(Option).init(alloc);
                    var idx: u16 = 0;
                    while (idx < opts_raw_buf.len) {
                        const opt = try Option.from(opts_raw_buf[idx..]);
                        idx += @bitSizeOf(@TypeOf(opt));
                        try opts_list.append(opt);
                    }
                    break :opts try opts_list.toOwnedSlice();
                }
                else null,
            .len = tcp_end,
        };
    }

    pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ 
        .kind = BFG.Kind.PACKET, 
        .layer = 4, 
        .name = "TCP_Packet", 
    });
};


// Calculate the Checksum from the given bytes. TODO - Handle bit carryovers
pub fn calcChecksum(bytes: []u8) u16 {
    const buf_end = if (bytes.len % 2 == 0) bytes.len else bytes.len - 1;
    const words = mem.bytesAsSlice(u16, bytes[0..buf_end]);
    var sum: u32 = 0;
    for (words) |word| sum += word;
    if (buf_end < bytes.len) sum += @intCast(bytes[bytes.len - 1]);
    while ((sum >> 16) > 0) sum = (sum & 0xFFFF) + (sum >> 16);
    return mem.nativeToBig(u16, @as(u16, @truncate(~sum)));
    //return @as(u16, @truncate(~sum));
}
