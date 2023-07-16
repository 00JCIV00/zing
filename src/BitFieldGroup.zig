//! BitFieldGroup - Common-to-All functionality for BitField Groups (Frames, Packets, Headers, etc).

const builtin = @import("builtin");
const cpu_endian = builtin.target.cpu.arch.endian();
const std = @import("std");
const fmt = std.fmt;
const math = std.math;
const mem = std.mem;
const meta = std.meta;

/// Implementation function to be called with 'usingnamespace'.
pub fn implBitFieldGroup(comptime T: type, comptime impl_config: ImplConfig) type {
    return struct {
        pub const bfg_kind: Kind = impl_config.kind;
        pub const bfg_layer: u3 = impl_config.layer;
        pub const bfg_name: []const u8 = impl_config.name;
        pub const bfg_byte_bounds: []const u8 = impl_config.byte_bounds;
        pub const bfg_bounds_types: []type = boundTypes: {
            var bounds_types: [bfg_byte_bounds.len]type = undefined;
            var prev_b = @as(u8, 0);
            inline for (bfg_byte_bounds, bounds_types[0..]) |cur_b, *b_type| {
                b_type.* = meta.Int(.unsigned, 8 * (cur_b - prev_b));
                prev_b = cur_b;
            }
            break :boundTypes bounds_types[0..];
        };
            
        /// Initialize a copy of the BitFieldGroup with an Encapsulated Header.
        pub fn initBFGEncapHeader(comptime header: T.Header, comptime encap_header: anytype) !type {
            if (!@hasDecl(T, "Header")) {
                std.debug.print("The provided type '{s}' does not implement a 'Header'.\n", .{@typeName(T)});
                return error.NoHeaderImplementation;
            }

            const encap_type = @TypeOf(encap_header);

            if (T.Header.bfg_layer > encap_type.bfg_layer) {
                //std.debug.print("Higher type '{s} (L{d})' should not encapsulate the lower type '{s} (L{d})'!\n", .{ @typeName(T.Header), T.Header.bfg_layer, @typeName(encap_type), encap_type.bfg_layer });
               return error.CannotEncapsulateLowerBFGType; 
            }

            return packed struct {
                header: T.Header = header,
                encap_header: encap_type = encap_header,

                pub usingnamespace implBitFieldGroup(@This(), .{ .kind = T.bfg_kind, .layer = T.bfg_layer, .name = T.bfg_name });
            };
        }

        /// Initialize a copy of the BitFieldGroup with the Header, an Encapsulated Header, Data (<= 1500B), and the Footer.
        pub fn initBFG(comptime header: T.Header, comptime encap_header: anytype, comptime data: anytype, comptime footer: ?T.Footer) !type {
            const data_type = @TypeOf(data);
            if (@sizeOf(data_type) > 1500) {
                std.debug.print("The size ({d}B) of '{s}' is greater than the allowed 1500B\n", .{ @sizeOf(data_type), @typeName(data_type) });
                return error.DataTooLarge;
            }
            const headers = (try initBFGEncapHeader(header, encap_header)){};
            const encap_type = @TypeOf(headers.encap_header);
            return if (@hasDecl(T, "Footer")) packed struct {
                header: T.Header = headers.header,
                encap_header: encap_type = headers.encap_header,
                data: data_type = data,
                footer: T.Footer = footer orelse .{},

                pub usingnamespace implBitFieldGroup(@This(), .{ .kind = T.bfg_kind, .layer = T.bfg_layer, .name = T.bfg_name });
            } else packed struct {
                header: T.Header = headers.header,
                encap_header: encap_type = headers.encap_header,
                data: data_type = data,

                pub usingnamespace implBitFieldGroup(@This(), .{ .kind = T.bfg_kind, .layer = T.bfg_layer, .name = T.bfg_name });
            };
        }

        /// Returns this BitFieldGroup as a Byte Array Slice based on its bit-width (not its byte-width, which can differ for packed structs).
        pub fn asBytes(self: *T, alloc: mem.Allocator) ![]u8 {
            return try alloc.dupe(u8, mem.asBytes(self)[0..(@bitSizeOf(T) / 8)]);
        }

        /// (NEEDS FIX!!!) Returns this BitFieldGroup as a Byte Array based on its bit-width (not its byte-width, which can differ for packed structs).
        pub fn asBytesBuf(self: *T, buf: []const u8) [@bitSizeOf(T) / 8]u8 {
            _ = buf;
            return mem.asBytes(self)[0..(@bitSizeOf(T) / 8)].*;
        }

        /// (WIP - Probably not needed) Returns this BitFieldGroup as a Byte Array in Network Byte Order / Big Endian. Network Byte Order words are 32-bits.
        /// User must free. TODO - Determine if freeing the returned slice also frees out_buf.
        pub fn asNetBytes32bWords(self: *T, alloc: mem.Allocator) ![]u8 {
            var byte_buf = self.asBytes(alloc);
            var word_buf = mem.bytesAsSlice(u32, byte_buf); 
            var out_buf = std.ArrayList(u8).init(alloc);
            for (word_buf) |word| try out_buf.appendSlice(mem.asBytes(&mem.nativeToBig(u32, word)));
            return out_buf.toOwnedSlice();
        }

        /// Returns this BitFieldGroup as a Byte Array Slice with all Fields in Network Byte Order / Big Endian
        pub fn asNetBytesBFG(self: *T, alloc: mem.Allocator) ![]u8 {
            //if(cpu_endian == .Little) try self.byteSwap();
            if(cpu_endian == .Little) {
                var be_bits = try toBitsMSB(self.*);
                const be_bits_type = @TypeOf(be_bits);
                var be_buf: [@bitSizeOf(be_bits_type) / 8]u8 = undefined;
                mem.writeIntSliceBig(be_bits_type, be_buf[0..], be_bits);
                return try alloc.dupe(u8, be_buf[0..]);
            } 
            return self.asBytes(alloc); // TODO - change this to take the bits in LSB order
        }

        /// (WIP - Probably not needed) Returns this BitFieldGroup from the provided Tagged Union.
        pub fn getSelf(self: *T, tagged_union: anytype) T {
            _ = self;
            return switch (meta.activeTag(tagged_union)) {
                inline else => |tag| @constCast(&@field(tagged_union, @tagName(tag))),
            };
        }

        /// Byte Swap the BitFieldGroup's fields from Little Endian to Big Endian - TODO Allow this to switch to either Endianness
        pub fn byteSwap(self: *T) !void {
            // Check for and Handle provided Byte Bounds
            if (T.bfg_byte_bounds.len > 0) {
                var bytes = mem.asBytes(self)[0..(@bitSizeOf(T) / 8)];
                const self_int_type = meta.Int(.unsigned, @bitSizeOf(T));
                var bits: self_int_type = 0;
                var prev_bound = @as(u8, 0);
                inline for (T.bfg_byte_bounds, T.bfg_bounds_types) |bound, int_type| {
                    var bytes_slice = if (bound < bytes.len) bytes[prev_bound..bound] else bytes[prev_bound..];
                    var int_bits: int_type = mem.readIntSlice(int_type, bytes_slice, .Big); 
                    bits |= @as(self_int_type, @intCast(int_bits)) << (prev_bound * 8); // TODO - Fix this to work with lower bit-width ints (Currently breaks with a u64 UDP Header)

                    prev_bound = bound;
                }
                self.* = @as(T, @bitCast(bits));
                return;
            }

            // Handle all other scenarios - TODO Test this more thoroughly
            const fields = meta.fields(T);
            var skip: u16 = 0;
            inline for (fields, 0..) |field, idx| {
                _ = idx;
                if (skip > 0) {
                    skip -= 1;
                    //continue;
                }
                var field_self = @field(self.*, field.name);
                var field_ptr = &@field(self.*, field.name);
                const field_info = @typeInfo(field.type);
                switch (field_info) {
                    .Struct => {},//if(@hasDecl(field.type, "byteSwap")) try field_ptr.*.byteSwap(),
                    .Int => field_ptr.* = if (@bitSizeOf(field.type) % 8 == 0) @byteSwap(field_self) else field_self,
                    .Bool => {},
                    else => {
                        std.debug.print("Couldn't Byte Swap: {any}", .{ field_self });
                        return error.CouldNotByteSwap;
                    }
                }
            }
            return;
        }

        /// Checks if all the fields of this BitFieldGroup are Integers
        pub fn allInts(self: *T) bool {
            _ = self;
            const fields = meta.fields(T);
            inline for (fields) |field| if (@typeInfo(field.type) != .Int and @typeInfo(field.type) != .Bool) return false;
            return true;   
        }

        /// Format the bits of each bitfield within a BitField Group to an IETF-like format.
        pub fn formatToText(self: *T, writer: anytype, init_config: FormatToTextConfig) !FormatToTextConfig {
            const seps = FormatToTextSeparators{};
            var config = init_config;
            if (config.add_bit_ruler) {
                try writer.print("{s}", .{seps.bit_ruler_bin});
                config.add_bit_ruler = false;
            }
            if (!config.add_bitfield_title) {
                config.add_bitfield_title = switch (T.bfg_kind) {
                    Kind.BASIC => false,
                    else => true,
                };
            }
            if (config.add_bitfield_title) {
                const name = if (T.bfg_name.len > 0) T.bfg_name else @typeName(T);
                var ns_buf: [100]u8 = undefined;
                const name_and_size = try fmt.bufPrint(ns_buf[0..], "{s} ({d}b | {d}B)", .{ name, @bitSizeOf(T), @sizeOf(T) });
                const prefix = setPrefix: {
                    if (config.col_idx != 0) {
                        config.col_idx = 0;
                        break :setPrefix "\n";
                    } else break :setPrefix "";
                };
                try writer.print(seps.bitfield_header, .{ prefix, name_and_size });
            }
            config.add_bitfield_title = false;

            const fields = meta.fields(T);
            inline for (fields) |field| {
                const field_self = @field(self.*, field.name);
                const field_info = @typeInfo(field.type);
                switch (field_info) {
                    .Struct => config = try fmtStruct(@constCast(&field_self), writer, config),
                    .Union => {
                        switch (meta.activeTag(field_self)) {
                            inline else => |tag| config = try fmtStruct(@constCast(&@field(field_self, @tagName(tag))), writer, config)
                        }
                    },
                    .Pointer => { //TODO Properly add support for Arrays?
                        try writer.print(seps.raw_data_bin, .{"START RAW DATA"});
                        var data_window = mem.window(u8, field_self, 53, 53);
                        while (data_window.next()) |data| try writer.print(seps.raw_data_win_bin, .{ data });
                        for (field_self, 0..) |elem, idx| {
                            const elem_out = switch (elem) {
                                '\n' => " NEWLINE",
                                '\t' => " TAB",
                                '\r' => " CARRIAGE RETURN",
                                ' ' => " SPACE",
                                '\u{0}' => " NULL",
                                else => &[_:0]u8{ elem },
                            };
                            try writer.print(seps.raw_data_elem_bin, .{ idx, elem, elem, elem_out });
                        } 
                        try writer.print(seps.raw_data_bin, .{"END RAW DATA"});
                    },
                    .Optional => { // TODO - Refactor this to properly handle .Struct, .Union, and .Int/.Bool 
                        _ = isNull: {
                            var field_raw = field_self orelse {
                                //try writer.print("\nNULL BFG: {s}\n", .{ field.name });
                                break :isNull true; 
                            };
                            config = switch (@typeInfo(@TypeOf(field_raw))) {
                                .Struct => try fmtStruct(&field_raw, writer, config),
                                .Union => switch (meta.activeTag(field_raw)) {
                                    inline else => |tag| try fmtStruct(&@field(field_raw, @tagName(tag)), writer, config),
                                },
                                else => break :isNull true,
                            };
                            //config = try fmtStruct(@constCast(&f_struct), writer, config);
                            break :isNull false;
                        };
                    },
                    .Int, .Bool => {
                        const bits = try intToBitArray(field_self);
                        for (bits) |bit| {
                            if (config.col_idx == 0) try writer.print("{d:0>4}|", .{config.row_idx});
                            const gap: u8 = gapBlk: {
                                if (config.field_idx < bits.len - 1) {
                                    config.field_idx += 1;
                                    break :gapBlk ' ';
                                }
                                config.field_idx = 0;
                                break :gapBlk '|';
                            };
                            try writer.print("{b}{c}", .{ bit, gap });

                            config.col_idx += 1;

                            if (config.col_idx == 32) {
                                config.row_idx += 1;
                                config.col_idx = 0;
                                try writer.writeAll("\n");
                            }
                        }
                    },
                    else => continue,
                }
            }
            if (config.depth == 0) {
                const line_sep = if (config.col_idx != 0) "\n" else "";
                try writer.print("{s}{s}", .{ line_sep, seps.bitfield_cutoff_bin });
            } else config.depth -= 1;
            return config;
        }

        // Help function for Structs
        fn fmtStruct(field: anytype, writer: anytype, config: FormatToTextConfig) !FormatToTextConfig {
            if (!@hasDecl(@TypeOf(field.*), "formatToText")) return config;
            var conf = config;
            conf.depth += 1;
            return try @constCast(field).formatToText(writer, conf);
        }
    };
}

/// Convert an Integer to a BitArray of equivalent bits in MSB Format.
pub fn intToBitArray(int: anytype) ![@bitSizeOf(@TypeOf(int))]u1 {
    const int_type = @TypeOf(int);
    if (int_type == bool or int_type == u1) return [_]u1{ @bitCast(int) };
    if ((@typeInfo(int_type) != .Int)) {
        std.debug.print("\nType '{s}' is not an Integer.\n", .{@typeName(int_type)});
        return error.NotAnInteger;
    }
    var bit_ary: [@bitSizeOf(int_type)]u1 = undefined;
    inline for (&bit_ary, 0..) |*bit, idx|
        bit.* = @as(u1, @truncate((@bitReverse(int)) >> idx));
    return bit_ary;
}

/// Convert the provided Struct, Int, or Bool to an Int in MSB format
pub fn toBitsMSB(obj: anytype) !meta.Int(.unsigned, @bitSizeOf(@TypeOf(obj))) {
    const obj_type = @TypeOf(obj);
    return switch (@typeInfo(obj_type)) {
        .Bool => @bitCast(obj),
        .Int => obj,//@bitReverse(obj), 
        .Struct => structInt: {
            const obj_size = @bitSizeOf(obj_type);
            var bits_int: meta.Int(.unsigned, obj_size) = 0;
            var bits_width: math.Log2IntCeil(@TypeOf(bits_int)) = obj_size;
            const fields = meta.fields(obj_type);
            inline for (fields) |field| {
                var field_self = @field(obj, field.name);
                bits_width -= @bitSizeOf(@TypeOf(field_self));
                bits_int |= @as(@TypeOf(bits_int), @intCast(try toBitsMSB(field_self))) << @as(math.Log2Int(@TypeOf(bits_int)), @intCast(bits_width));
            }
            break :structInt bits_int;
        },
        else => {
            std.debug.print("\nType '{s}' is not an Integer, Bool, or Struct.\n", .{@typeName(obj_type)});
            return error.NoConversionToMSB;
        },
    };
}

/// Implementation Config
const ImplConfig = struct {
    kind: Kind = Kind.BASIC,
    layer: u3 = 7,
    name: []const u8 = "",
    byte_bounds: []const u8 = "",
};

/// Kinds of BitField Groups
pub const Kind = enum {
    BASIC,
    HEADER,
    PACKET,
    FRAME,
};

/// Config Struct for formatToText()
const FormatToTextConfig = struct {
    add_bit_ruler: bool = false,
    add_bitfield_title: bool = false,
    row_idx: u16 = 0,
    col_idx: u6 = 0,
    field_idx: u16 = 0,
    depth: u8 = 0,
};

/// Struct of Separators for formatToText()
const FormatToTextSeparators = struct {
    // Binary Separators
    bit_ruler_bin: []const u8 =
        \\     0                   1                   2                   3   
        \\     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        \\WORD+---------------+---------------+---------------+---------------+
        \\
    ,
    bitfield_break_bin: []const u8 = "    +---------------+---------------+---------------+---------------+\n",
    bitfield_cutoff_bin: []const u8 = "END>+---------------+---------------+---------------+---------------+\n",
    bitfield_header: []const u8 = "{s}    |-+-+-+{s: ^51}+-+-+-|\n",
    raw_data_bin: []const u8 = "\n    |{s: ^63}|\n\n",
    raw_data_elem_bin: []const u8 = "     > {d:0>4}: 0b{b:0>8} 0x{X:0>2} {s: <39}<\n",
    raw_data_win_bin: []const u8 = "     > DATA: \"{s}\"\n",
    // Decimal Separators - TODO
    // Hexadecimal Separators - TODO
    
    bit_ruler_bin_old: []const u8 =
        \\                    B               B               B               B
        \\     0              |    1          |        2      |            3  |
        \\     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        \\    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        \\
    ,
    bitfield_cutoff_bin_old: []const u8 = "END>+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n",
};
