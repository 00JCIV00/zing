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
        ether_type: u16 = 0,

        pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.HEADER });
    };

    pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.FRAME, .name = "Eth_Frame" });
};
