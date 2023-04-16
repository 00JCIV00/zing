//! Components of the base Packet structure for IP, ICMP, TCP, and UDP packets.

const std = @import("std");
const mem = std.mem;

const BFG = @import("BitFieldGroup.zig");
const Addr = @import("Addresses.zig");

/// IP Packet - [IETC RFC 791](https://datatracker.ietf.org/doc/html/rfc791#section-3.1)
pub const IPPacket = packed struct {
    header: Header = .{},

    /// IP Header
    pub const Header = packed struct(u192) {
        version: u4 = 0,
        ip_header_len: u4 = 6,
        service_type: ServiceType = .{},
        total_len: u16 = 24,

        id: u16 = 0,
        flags: Flags = .{},
        frag_offset: u13 = 0,

        time_to_live: u8 = 0,
        protocol: u8 = 17, // TODO Convert Enums to Structs and use them normally
        header_checksum: u16 = 0,

        src_ip_addr: Addr.IPv4 = .{},

        dst_ip_addr: Addr.IPv4 = .{},

        options: u24 = 0, // TODO Create Options packed struct
        padding: u8 = 0,

        pub const ServiceType = packed struct(u8) {
            precedence: u3 = 0,
            delay: u1 = 0,
            throughput: u1 = 0,
            relibility: u1 = 0,
            reserved: u2 = 0,

            pub usingnamespace BFG.implBitFieldGroup(@This(), .{});
        };

        pub const Flags = packed struct(u3) {
            reserved: u1 = 0,
            dont_frag: bool = false,
            more_frags: bool = true,

            pub usingnamespace BFG.implBitFieldGroup(@This(), .{});
        };

        pub const ServicePrecedence = enum(u3) {
            ROUTINE,
            PRIORITY,
            IMMEDIATE,
            FLASH,
            FLASH_OVERRIDE,
            CRITIC,
            INTERNETWORK_CONTROL,
            NETWORK_CONTROL,
        };

        pub const Protocols = enum(u8) {
            ICMP = 1,
            IGMP = 2,
            TCP = 6,
            UDP = 17,
            ENCAP = 41,
            OSPF = 89,
            SCTP = 132,
        };

        pub fn calcLengthAndHeaderChecksum(self: *@This(), payload: []const u8) void {
            var header_bytes = mem.asBytes(self);

            self.total_len = @intCast(u8, header_bytes.len) + @intCast(u15, payload.len);
            self.header_checksum = calcChecksum(header_bytes);
        }

        pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.HEADER, .layer = 3 });
    };

    pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.PACKET, .layer = 3, .name = "IP_Packet" });
};

/// ICMP Packet - [IETF RFC 792](https://datatracker.ietf.org/doc/html/rfc792)
pub const ICMPPacket = packed struct {
    // Layer 3 (ICMP is a little odd)
    ip_header: IPPacket.Header = .{
        .version = 4,
        .protocol = @enumToInt(IPPacket.Header.Protocols.ICMP),
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

        pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.HEADER, .layer = 3 });
    };

    pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.PACKET, .layer = 3, .name = "ICMP_Packet" });
};

/// UDP Packet - [IETF RFC 768](https://datatracker.ietf.org/doc/html/rfc768)
pub const UDPPacket = packed struct {
    // Layer 3
    ip_header: IPPacket.Header = .{
        .version = 4,
        .protocol = @enumToInt(IPPacket.Header.Protocols.UDP),
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
        pub fn calcLengthAndChecksum(self: *@This(), alloc: mem.Allocator, payload: []const u8) !void {
            var udp_bytes = try mem.concat(alloc, u8, &[_][]const u8{ mem.asBytes(self), payload });
            defer alloc.free(udp_bytes);

            self.length = @intCast(u16, udp_bytes.len);
            self.checksum = calcChecksum(udp_bytes);
        }

        pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.HEADER, .layer = 4 });
    };

    pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.PACKET, .layer = 4, .name = "UDP_Packet" });
};

/// TCP Packet - [IETF RFC 9293](https://www.ietf.org/rfc/rfc9293.html)
pub const TCPPacket = packed struct {
    // Layer 3
    ip_header: IPPacket.Header = .{
        .version = 4,
        .protocol = @enumToInt(IPPacket.Header.Protocols.TCP),
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

        option1: Option = .{ .kind = @enumToInt(OptionKinds.NO_OP) },
        option2: Option = .{ .kind = @enumToInt(OptionKinds.NO_OP) },
        option3: Option = .{ .kind = @enumToInt(OptionKinds.END_OF_OPTS) },

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
        const Flags = enum(u8) {
            CWR = 0b10000000,
            ECE = 0b01000000,
            URG = 0b00100000,
            ACK = 0b00010000,
            PSH = 0b00001000,
            RST = 0b00000100,
            SYN = 0b00000010,
            FIN = 0b00000001,
        };

        const Option = packed struct {
            kind: u8 = 0,
            len: u8 = 0,
            max_seg_size: u16 = 0,

            pub usingnamespace BFG.implBitFieldGroup(@This(), .{});
        };
        const OptionKinds = enum(u8) {
            END_OF_OPTS,
            NO_OP,
            MAX_SEG_SIZE,
        };

        pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.HEADER, .layer = 4 });
    };

    pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.PACKET, .layer = 4, .name = "TCP_Packet" });
};

// Calculate the Checksum from the given bytes. TODO - Handle bit carryovers
pub fn calcChecksum(bytes: []u8) u16 {
    const words = mem.bytesAsSlice(u16, bytes);
    var sum: u32 = 0;
    for (words) |word| sum += word;
    return @truncate(u16, ~sum);
}
