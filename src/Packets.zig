//! Components of the base Packet structure for IP, ICMP, TCP, and UDP packets.

const BFG = @import("BitFieldGroup.zig");


/// IP Header - [IETC RFC 791](https://datatracker.ietf.org/doc/html/rfc791#section-3.1)
pub const IPHeader = packed struct (u192) {
    version: u4 = 0,
    ip_header_len: u4 = 6,
    service_type: ServiceType = .{},
    total_len: u16 = 24,

    id: u16 = 0,
    flags: Flags = .{},
    frag_offset: u13 = 0,
    
	time_to_live: u8 = 0,
    protocol: u8 = 0,
    header_checksum: u16 = 0,
    
	src_addr: u32 = 0,
    
	dest_addr: u32 = 0,
	
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

	pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.HEADER });
};

/// ICMP Packet - [IETF RFC 792](https://datatracker.ietf.org/doc/html/rfc792)
pub const ICMPPacket = struct {
    header: ICMPPacket.Header = .{},
    ip_header: IPHeader = .{
        .version = 4,
        .protocol = @enumToInt(IPHeader.Protocols.ICMP),
    },

    /// ICMP Header
    const Header = packed struct(u64) {
        icmp_type: u8 = 0,
        code: u8 = 0,
        checksum: u16 = 0,
        unused: u32 = 0,

		pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.HEADER });
    };

	// TODO Add ICMP types


	pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.PACKET });
};

/// UDP Packet - [IETF RFC 768](https://datatracker.ietf.org/doc/html/rfc768)
pub const UDPPacket = struct {
    ip_header: IPHeader = .{
        .version = 4,
        .protocol = @enumToInt(IPHeader.Protocols.UDP),
    },
    header: UDPPacket.Header = .{},

    /// UDP Header
    pub const Header = packed struct(u64) {
        src_port: u16 = 0,
        dest_port: u16 = 0,
        length: u16 = 0,
        checksum: u16 = 0,

		pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.HEADER });
    };

	pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.PACKET });
};

/// TCP Packet - [IETF RFC 9293](https://www.ietf.org/rfc/rfc9293.html)
pub const TCPPacket = struct {
    ip_header: IPHeader = .{
        .version = 4,
        .protocol = @enumToInt(IPHeader.Protocols.TCP),
    },
    header: TCPPacket.Header,

    /// TCP Header
    const Header = packed struct {
        src_port: u16 = 0,
        dest_port: u16 = 0,
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

		pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.HEADER });
    };

	pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.PACKET });
};
