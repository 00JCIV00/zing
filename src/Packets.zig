//! Components of the base Packet structure for IP, ICMP, TCP, and UDP packets.

const std = @import("std");
const mem = std.mem;

const BFG = @import("BitFieldGroup.zig");
const Addr = @import("Addresses.zig");

/// IP Packet - [IETC RFC 791](https://datatracker.ietf.org/doc/html/rfc791#section-3.1)
pub const IPPacket = packed struct {
    header: Header = .{},
    pseudo_header: SegmentPseudoHeader = .{},

    /// IP Header
    pub const Header = packed struct(u192) {
        version: u4 = 4,
        ip_header_len: u4 = 6,
        service_type: ServiceType = .{},
        total_len: u16 = 24,

        id: u16 = 0,
        flags: Flags = .{},
        frag_offset: u13 = 0,

        time_to_live: u8 = 0,
        protocol: u8 = Protocols.UDP, 
        header_checksum: u16 = 0,

        src_ip_addr: Addr.IPv4 = .{},

        dst_ip_addr: Addr.IPv4 = .{},

        options: u24 = 0, // TODO Create Options packed struct. Probably as a separate struct outside of the Header.
        padding: u8 = 0,

        /// IP Header Service Type Info
        pub const ServiceType = packed struct(u8) {
            precedence: u3 = ServicePrecedence.ROUTINE,
            delay: u1 = 0,
            throughput: u1 = 0,
            relibility: u1 = 0,
            reserved: u2 = 0,

            pub usingnamespace BFG.implBitFieldGroup(@This(), .{});
        };

        /// IP Header Flags Info
        pub const Flags = packed struct(u3) {
            reserved: bool = false,
            dont_frag: bool = false,
            more_frags: bool = true,

            pub usingnamespace BFG.implBitFieldGroup(@This(), .{});
        };


        // IP Packet Service Precedence Levels
        pub const ServicePrecedence = struct {
            const ROUTINE: u3 = 0;
            const PRIORITY: u3 = 1;
            const IMMEDIATE: u3 = 2;
            const FLASH: u3 = 3;
            const FLASH_OVERRIDE: u3 = 4;
            const CRITIC: u3 = 5;
            const INTERNETWORK_CONTROL: u3 = 6;
            const NETWORK_CONTROL: u3 = 7;
        };

        /// IP Protocols
        pub const Protocols = struct {
            const ICMP: u8 = 1;
            const IGMP: u8 = 2;
            const TCP: u8 = 6;
            const UDP: u8 = 17;
            const ENCAP: u8 = 41;
            const OSPF: u8 = 89;
            const SCTP: u8 = 132;
        };


        /// Calculate the Total Length and Checksum of this IP Packet
        pub fn calcLengthAndChecksum(self: *@This(), alloc: mem.Allocator, payload: []const u8) !void {
            self.total_len = (@bitSizeOf(IPPacket.Header) / 8) + @intCast(u16, payload.len);

            self.header_checksum = 0;
            var header_bytes = try self.asNetBytesBFG(alloc);
            self.header_checksum = calcChecksum(header_bytes);
        }

        pub usingnamespace BFG.implBitFieldGroup(@This(), .{ 
            .kind = BFG.Kind.HEADER, 
            .layer = 3,
        });
    };

    /// Segment Pseudo Header
    /// Does NOT include the Segment Length, which is handled at the Segment level.
    pub const SegmentPseudoHeader = packed struct(u80) {
        src_ip_addr: Addr.IPv4 = .{},
        
        dst_ip_addr: Addr.IPv4 = .{},
        
        protocol: u16 = Header.Protocols.UDP,

        pub usingnamespace BFG.implBitFieldGroup(@This(), .{ 
            .kind = BFG.Kind.HEADER, 
            .layer = 3,
        });
    };


    pub usingnamespace BFG.implBitFieldGroup(@This(), .{ 
        .kind = BFG.Kind.PACKET, 
        .layer = 3, 
        .name = "IP_Packet" 
    });
};

/// ICMP Packet - [IETF RFC 792](https://datatracker.ietf.org/doc/html/rfc792)
pub const ICMPPacket = packed struct {
    // Layer 3 (ICMP is a little odd)
    ip_header: IPPacket.Header = .{
        .version = 4,
        .protocol = IPPacket.Header.Protocols.ICMP,
    },
    // Layer 3
    header: ICMPPacket.Header = .{},

    /// ICMP Header
    pub const Header = packed struct(u64) {
        icmp_type: u8 = @enumToInt(Types.DEST_UNREACHABLE),
        code: u8 = @enumToInt(Codes.DEST_UNREACHABLE.PROTOCOL),
        checksum: u16 = 0,

        pointer: u8 = 0,
        unused: u24 = 0,

        /// ICMP Types
        pub const Types = enum(u8) {
            ECHO_REPLY = 0,
            DEST_UNREACHABLE = 3,
            SRC_QUENCH = 4,
            REDIRECT = 5,
            ECHO = 8,
            TIME_EXCEEDED = 11,
            PARAM_PROBLEM = 12,
            TIMESTAMP = 13,
            TIMESTAMP_REPLY = 14,
            INFO_REQUEST = 15,
            INFO_REPLY = 16,
        };

        /// ICMP Codes
        pub const Codes = struct {
            pub const DEST_UNREACHABLE = enum(u8) {
                NET,
                HOST,
                PROTOCOL,
                PORT,
                FRAG_NEEDED,
                SRC_ROUTE_FAILED,
            };
            pub const TIME_EXCEEDED = enum(u8) {
                TTL,
                FRAG_REASSEMBLY,
            };
            pub const REDIRECT = enum(u8) {
                NETWORK,
                HOST,
                TOS_AND_NETWORK,
                TOS_AND_HOST,
            };
        };

        pub usingnamespace BFG.implBitFieldGroup(@This(), .{ 
            .kind = BFG.Kind.HEADER, 
            .layer = 3 
        });
    };

    pub usingnamespace BFG.implBitFieldGroup(@This(), .{ 
        .kind = BFG.Kind.PACKET, 
        .layer = 3, 
        .name = "ICMP_Packet" 
    });
};

/// UDP Packet - [IETF RFC 768](https://datatracker.ietf.org/doc/html/rfc768)
pub const UDPPacket = packed struct {
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
        /// User must free.
        pub fn calcLengthAndChecksum(self: *@This(), alloc: mem.Allocator,  payload: []const u8) !void {
            const pseudo_end = @bitSizeOf(IPPacket.SegmentPseudoHeader) / 8;
            var pseudo_hdr_bytes = payload[0..pseudo_end];
            var udp_payload = payload[pseudo_end..];

            self.length = @intCast(u16, @bitSizeOf(UDPPacket.Header) / 8 + udp_payload.len);
            
            var udp_hdr_bytes = try self.asNetBytesBFG(alloc);
            var udp_bytes = try mem.concat(alloc, u8, &.{ pseudo_hdr_bytes, udp_hdr_bytes[4..6], udp_hdr_bytes[0..], udp_payload });

            self.checksum = calcChecksum(udp_bytes);
        }

        pub usingnamespace BFG.implBitFieldGroup(@This(), .{ 
            .kind = BFG.Kind.HEADER, 
            .layer = 4,
        });
    };

    pub usingnamespace BFG.implBitFieldGroup(@This(), .{ 
        .kind = BFG.Kind.PACKET, 
        .layer = 4, 
        .name = "UDP_Packet" 
    });
};

/// TCP Packet - [IETF RFC 9293](https://www.ietf.org/rfc/rfc9293.html)
pub const TCPPacket = packed struct {
    // Layer 3
    ip_header: IPPacket.Header = .{
        .version = 4,
        .protocol = IPPacket.Header.Protocols.TCP,
    },
    // Layer 4
    header: TCPPacket.Header = .{},

    /// TCP Header
    pub const Header = packed struct {
        src_port: u16 = 0,
        dst_port: u16 = 0,

        seq_num: u32 = 0,

        ack_num: u32 = 0,

        data_offset: u4 = 0,
        reserved: u4 = 0,
        flags: Flag = .{},
        window: u16 = 0,

        checksum: u16 = 0,
        urg_pointer: u16 = 0,

        option1: Option = .{ .kind = OptionKinds.NO_OP },
        option2: Option = .{ .kind = OptionKinds.NO_OP },
        option3: Option = .{ .kind = OptionKinds.END_OF_OPTS },

        const Flag = packed struct(u8) {
            cwr: bool = false,
            ece: bool = false,
            urg: bool = false,
            ack: bool = false,
            psh: bool = false,
            rst: bool = false,
            syn: bool = false,
            fin: bool = true,

            pub usingnamespace BFG.implBitFieldGroup(@This(), .{});
        };
        const Flags = struct {
            pub const CWR: u8 = 0b10000000;
            pub const ECE: u8 = 0b01000000;
            pub const URG: u8 = 0b00100000;
            pub const ACK: u8 = 0b00010000;
            pub const PSH: u8 = 0b00001000;
            pub const RST: u8 = 0b00000100;
            pub const SYN: u8 = 0b00000010;
            pub const FIN: u8 = 0b00000001;
        };

        const Option = packed struct {
            kind: u8 = 0,
            len: u8 = 0,
            max_seg_size: u16 = 0,

            pub usingnamespace BFG.implBitFieldGroup(@This(), .{});
        };
        const OptionKinds = struct {
            pub const END_OF_OPTS: u8 = 0;
            pub const NO_OP: u8 = 1;
            pub const MAX_SEG_SIZE: u8 = 2;
        };

        pub usingnamespace BFG.implBitFieldGroup(@This(), .{ 
            .kind = BFG.Kind.HEADER, 
            .layer = 4 
        });
    };

    pub usingnamespace BFG.implBitFieldGroup(@This(), .{ 
        .kind = BFG.Kind.PACKET, 
        .layer = 4, 
        .name = "TCP_Packet" 
    });
};


// Calculate the Checksum from the given bytes. TODO - Handle bit carryovers
pub fn calcChecksum(bytes: []u8) u16 {
    const buf_end = if (bytes.len % 2 == 0) bytes.len else bytes.len - 1;
    var words = mem.bytesAsSlice(u16, bytes[0..buf_end]);
    var sum: u32 = 0;
    for (words) |word| sum += word;
    if (buf_end < bytes.len) sum += @intCast(u16, bytes[bytes.len - 1]);
    while ((sum >> 16) > 0) sum = (sum & 0xFFFF) + (sum >> 16);
    return mem.nativeToBig(u16, @truncate(u16, ~sum));
}
