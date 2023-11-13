//! Components of basic frame types. (Currently just Ethernet)

const std = @import("std");
const mem = std.mem;

const Addr = @import("Addresses.zig");
const BFG = @import("BitFieldGroup.zig");
const Packets = @import("Packets.zig");
const utils = @import("utils.zig");

/// Ethernet Frame
/// Reference: [Wikipedia - Ethernet Frame](https://en.wikipedia.org/wiki/Ethernet_frame#Header)
pub const EthFrame = packed struct{
    header: Header = .{},

    /// Ethernet Header
    pub const Header = packed struct(u112){
        // Layer 1 Header
        //preamble: u56 = 0,
        //sfd: u8 = 0,

        // Layer 2 Header
        dst_mac_addr: Addr.MAC = .{},
        src_mac_addr: Addr.MAC = .{},
        ether_type: u16 = EtherTypes.IPv4, 
        
        /// Ether Types
        /// Reference: [Wikipedia - EtherType Values](https://en.wikipedia.org/wiki/EtherType#Values)
        pub const EtherTypes = struct{
            pub const IPv4: u16 = 0x0800;
            pub const ARP: u16 = 0x0806;
            pub const IPv6: u16 = 0x86DD;

            pub usingnamespace utils.ImplEnumerable(@This());
        };

        pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ .kind = BFG.Kind.HEADER });
    };

    /// Ethernet Footer
    pub const Footer = packed struct(u32){
        eth_frame_check_seq: u32 = 0,
        
        /// Calculate the Cyclic Redundancy Check (CRC) and set it as the Frame Check Sequence (FCS) of this Ethernet Frame Footer.
        pub fn calcCRC(self: *@This(), alloc: mem.Allocator, payload: []u8) !void {
            const poly = 0xEDB88320;
            var crc: u32 = 0xFFFFFFFF;
            _ = alloc;

            //var frame_bytes = try mem.concat(alloc, u8, &.{ try self.asNetBytesBFG(alloc), payload });

            for (payload) |byte| {
                crc ^= byte;
                var i: u4 = 0;
                while (i < 8) : (i += 1) {
                    const mask: u32 = @bitCast(-(@as(i32, @bitCast(crc)) & 1));
                    crc = (crc >> 1) ^ (poly & mask);
                }
            }
            self.eth_frame_check_seq = mem.nativeToBig(u32, ~crc);
        }

        pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ .kind = BFG.Kind.HEADER });
    };

    pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ .kind = BFG.Kind.FRAME, .layer = 2, .name = "Eth_Frame", });
};

/// Wifi Frame TODO Add Frame Control constants
/// [IETF - RFC 5416](https://www.rfc-editor.org/rfc/rfc5416)
/// [Cisco - Wifi Knowledge](https://community.cisco.com/t5/wireless-mobility-knowledge-base/802-11-frames-a-starter-guide-to-learn-wireless-sniffer-traces/ta-p/3110019)
pub const WifiFrame = packed struct{
    header: Header = .{},

    /// Wifi Header
    pub const Header = packed struct{
        frame_control: FrameControl = .{},
        duration: u16 = 0,

        dst_mac_addr: Addr.MAC = .{},
        src_mac_addr: Addr.MAC = .{},

        rx_addr: Addr.MAC = .{},

        seq_control: u16 = 0,

        tx_addr: Addr.MAC = .{},

        qos_control: u16 = 0,


        pub const FrameControl = packed struct(u16) {
            proto_version: u2 = 0,
            wifi_frame_type: u2 = 0,
            wifi_frame_subtype: u4 = 0,
            to_DS: bool = false,
            from_DS: bool = false,
            more_frag: bool = false,
            retry: bool = false,
            pwr_mgmt: bool = false,
            more_data: bool = false,
            protected: bool = false,
            ordered: bool = false,

            pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{}); 
        };

        pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ .kind = BFG.Kind.HEADER });
    };
    
    /// Wifi Footer
    pub const Footer = packed struct(u32) {
        wifi_frame_check_seq: u32 = 0,
        
        /// Calculate the Cyclic Redundancy Check (CRC) and set it as the Frame Check Sequence (FCS) of this Wifi Frame Footer.
        pub fn calcCRC(self: *@This(), alloc: mem.Allocator, frame_bytes: []u8) !void {
            _ = self;
            _ = alloc;
            _ = frame_bytes;
            // TODO
        }


        pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ .kind = BFG.Kind.HEADER });
    };


    pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ .kind = BFG.Kind.FRAME, .layer = 2, .name = "Wifi_Frame", });
};
