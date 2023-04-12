//! Components of basic frame types. (Currently just Ethernet)

const Addr = @import("Addresses.zig");
const BFG = @import("BitFieldGroup.zig");
const Packets = @import("Packets.zig");

/// Ethernet Frame [Wikipedia - Ethernet Frame](https://en.wikipedia.org/wiki/Ethernet_frame#Header)
pub const EthFrame = packed struct {
    header: Header = .{},

    /// Ethernet Header
    pub const Header = packed struct(u112) {
        // Layer 1 Header
        //preamble: u56 = 0,
        //sfd: u8 = 0,

        // Layer 2 Header
        src_mac_addr: Addr.MAC = .{},
        dst_mac_addr: Addr.MAC = .{},
        ether_type: u16 = 0x0800, //TODO Add EtherTypes [Wikipedia - EtherType Values](https://en.wikipedia.org/wiki/EtherType#Values)

        pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.HEADER });
    };

    /// Ethernet Footer
    pub const Footer = packed struct(u32) {
        eth_frame_check_seq: u32 = 0,

        pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.HEADER });
    };

    pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.FRAME, .layer = 2, .name = "Eth_Frame", });
};

/// Wifi Frame TODO Add Frame Control constants
/// [IETF - RFC 5416](https://www.rfc-editor.org/rfc/rfc5416)
/// [Cisco - Wifi Knowledge](https://community.cisco.com/t5/wireless-mobility-knowledge-base/802-11-frames-a-starter-guide-to-learn-wireless-sniffer-traces/ta-p/3110019)
pub const WifiFrame = packed struct {
    header: Header =.{},

    /// Wifi Header
    pub const Header = packed struct {
        frame_control: FrameControl = .{},
        duration: u16 = 0,

        src_mac_addr: Addr.MAC = .{},
        src_dst_mac: Addr.MAC = .{},

        rx_addr: Addr.MAC = .{},

        seq_control: u16 = 0,

        tx_addr: Addr.MAC = .{},

        qos_control: u16 = 0,


        pub const FrameControl = packed struct(u16) {
            proto_version: u2 = 0,
            wifi_frame_type: u2 = 0,
            wifi_frame_subtype: u4 = 0,
            to_DS: u1 = 0,
            from_DS: u1 = 0,
            more_frag: bool = false,
            retry: bool = false,
            pwr_mgmt: bool = false,
            more_data: bool = false,
            protected: bool = false,
            ordered: bool = false,

            pub usingnamespace BFG.implBitFieldGroup(@This(), .{}); 
        };

        pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.HEADER });
    };
    
    /// Wifi Footer
    pub const Footer = packed struct(u32) {
        wifi_frame_check_seq: u32 = 0,

        pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.HEADER });
    };


    pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.FRAME, .layer = 2, .name = "Wifi_Frame", });
};
