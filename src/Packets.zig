//! Components of the base Packet structure for IP, ICMP, TCP, and UDP packets.

/// Ethernet Header
const EthHeader = packed struct {
    // TODO - Add Eth Header
    eth_frame_data: u128,
};

/// IP Header - [IETC RFC 791](https://datatracker.ietf.org/doc/html/rfc791#section-3.1)
const IPHeader = packed struct {
    version: u4,
    ip_header_len: u4 = 5,
    service_type = packed struct {
        precedence: u3 = 0,
        delay: u1 = 0,
        throughput: u1 = 0,
        relibility: u1 = 0,
        reserved: u2 = 0,
    },
    total_len: u16,
    id: u16,
    flags = packed struct {
        reserved: u1 = 0,
        dont_frag: bool = false,
        more_frags: bool = true,
    },
    frag_offset: u13,
    time_to_live: u8,
    protocol: u8,
    header_checksum: u16,
    src_addr: u32,
    dest_addr: u32,

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
};

/// BitFieldGroup - Common-to-All functionality for BitFieldGroups (Packets, Headers, etc).
const BitFieldGroup = union(enum) {
    icmp: ICMPPacket,
    udp: UDPPacket,
    tcp: TCPPacket,

    const bit_info_header =
        \\               B               B               B               B
        \\ 0             |     1         |         2     |             3 |
        \\ 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        \\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        \\
    ;

    fn writeBitInfo(bfg: *BitFieldGroup, writer: anytype) !void {
        writer.writeAll(bit_info_header);
        switch (bfg.*) {
            inline else => |*self| {
                writer.print(); // TODO
            },
        }
    }
};

/// ICMP Packet - [IETF RFC 792](https://datatracker.ietf.org/doc/html/rfc792)
const ICMPPacket = struct {
    header: ICMP.Header,
    ip_header = IPHeader{
        .version = 4,
        .protocol = IPHeader.Protocols.ICMP,
    },

    /// ICMP Header
    const Header = packed struct(u96) {
        icmp_type: u8,
        code: u8 = 0,
        checksum: u16,
        unused: u32 = 0,
    };
};

/// UDP Packet - [IETF RFC 768](https://datatracker.ietf.org/doc/html/rfc768)
const UDPPacket = struct {
    ip_header = IPHeader{
        .version = 4,
        .protocol = IPHeader.Protocols.UDP,
    },
    header: UDP.Header,
    data: []u8,

    /// UDP Header
    const Header = packed struct {
        src_port: u16,
        dest_port: u16,
        length: u16,
        checksum: u16,
    };
};

/// TCP Packet - [IETF RFC 9293](https://www.ietf.org/rfc/rfc9293.html)
const TCPPacket = struct {
    ip_header = IPHeader{
        .version = 4,
        .protocol = IPHeader.Protocols.TCP,
    },
    header: TCP.Header,
    data: []u8,

    /// TCP Header
    const Header = packed struct {
        src_port: u16,
        dest_port: u16,
        seq_num: u32,
        ack_num: u32,
        data_offset: u4,
        reserved: u4 = 0,
        flags: packed struct {
            cwr: bool,
            ece: bool,
            urg: bool,
            ack: bool,
            psh: bool,
            rst: bool,
            syn: bool,
            fin: bool,
        },
        window: u16,
        checksum: u16,
        urg_pointer: u16,
        option1: Option = .{ .kind = OptionKinds.NO_OP },
        option2: Option = .{ .kind = OptionKinds.NO_OP },
        option3: Option = .{ .kind = OptionKinds.END_OF_OPTS },

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
        };

        const OptionKinds = enum(u8) {
            END_OF_OPTS,
            NO_OP,
            MAX_SEG_SIZE,
        };
    };
};
