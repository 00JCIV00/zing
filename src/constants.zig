//! Linux Constants required for various System Control and Networking functions.

const std = @import("std");
const mem = std.mem;

// Linux Interface Constants. Found in .../linux/if_ether.h, if_arp.h, if_socket.h, etc
// TODO: Get these straight from libc if available?
pub const ETH_P_ALL = mem.nativeToBig(u16, 0x03);
pub const PACKET_HOST = 0;
pub const SIOCGIFHWADDR = 0x8927;
pub const ARPHRD_ETHER: u16 = 1;
pub const ARPHRD_IEEE80211: u16 = 801;
pub const PACKET_BROADCAST = mem.nativeToBig(u8, 1);
pub const IFF_ALLMULTI: i16 = 0x200;//mem.nativeToBig(i16, 0x200);
pub const SIOCSIFFLAGS: u32 = 0x8914;//mem.nativeToBig(u32, 0x8914);
