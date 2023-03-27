//! PacketBitFieldGroup - Common-to-All functionality for Packet BitField Groups (Packets, Headers, etc).

const std = import("std");

/// Implementation function to be called with 'usingnamespace'.
fn implPacketBitFieldGroup(comptime T: type) type {
    return struct {
        /// Write the bits of each bitfield within a Packet BitField Group in an IETF-like format.
        fn writeBitInfo(self: *T, alloc: std.mem.Allocator, writer: anytype, init_config: WriteBitInfoConfig) !void {
            var config = init_config;
            if (config.add_header) try writer.print("{s}", .{config.bit_info_header});
            try writer.print("    |-=-=-={s: ^52}=-=-=-|\n", .{@typeName(T)});

            const fields = std.meta.fields(T);
            inline for (fields) |field| {
                const f_self = @field(self.*, field.name);
                if (@hasDecl(field.type, "writeBitInfo")) @constCast(&f_self).writeBitInfo(alloc, writer, config) else {
                    if (config.col_idx == 0) try writer.print("{d:0>4}", .{config.row_idx});
                    try writer.writeAll("|");

                    const bits_str = try std.fmt.allocPrint(alloc, "{b}", .{f_self});
                    for (bits_str) |bit| {
                        const gap = gapBlk: {
                            if (config.field_idx < bits_str.len - 1) break :gapBlk ' ';
                            config.field_idx = 0;
                            break :gapBlk '|';
                        };
                        try writer.print("{c}{c}", .{ bit, gap });

                        config.col_idx += 1;
                        config.field_idx += 1;

                        if (config.col_idx == 31) {
                            config.row_idx += 1;
                            config.col_idx = 0;
                            writer.writeAll("\n");
                        }
                    }
                }
            }
        }
    };
}

/// Config Struct for writeBitInfo()
const WriteBitInfoConfig = struct {
    add_header: bool = false,
    row_idx: u16 = 0,
    col_idx: u6 = 0,
    field_idx: u16 = 0,
    bit_info_header: []const u8 =
        \\                   B               B               B               B
        \\     0             |     1         |         2     |             3 |
        \\     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        \\    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        \\
    ,
};