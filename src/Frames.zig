//! Components of basic frame types. (Currently just Ethernet)

const Addr = @import("Addresses.zig");
const BFG = @import("BitFieldGroup.zig");

/// Ethernet Frame [Wikipedia - Ethernet Frame](https://en.wikipedia.org/wiki/Ethernet_frame#Header)
pub const EthFrame = packed struct {
    header: EthHeader = .{},

    /// Ethernet Header
    pub const EthHeader = packed struct(u176) {
        preamble: u56 = 0,
        sfd: u8 = 0,
        src_mac_addr: Addr.MAC = .{},
        dst_mac_addr: Addr.MAC = .{},
        ether_type: u16 = 0,

        pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.HEADER });
    };

    pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = BFG.Kind.FRAME });
};
