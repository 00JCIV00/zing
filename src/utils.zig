//! Utility functions for the Zing Library

const std = @import("std");
const meta = std.meta;

/// Create an `Enumerable` Implementation for any struct whose fields are all of the same Type.
pub fn ImplEnumerable(comptime T: type) type {
    const type_info = @typeInfo(T);
    if (type_info == .Enum) return T;
    if (type_info != .Struct and type_info != .Union) @compileError("The Enumerable Implementation can only be applied to Structs and Unions.");
    const type_decls = meta.declarations(T);
    const TagT = @TypeOf(@field(T, type_decls[0].name));
    if (@typeInfo(TagT) != .Int) @compileError("The Enumerable Implementation requires that all declarations be an Integer (any signedness) of the same Type.");
    for (type_decls) |decl| {
        const decl_val = @field(T, decl.name);
        if (@TypeOf(decl_val) != TagT) 
            @compileError("The Enumerable Implementation requires that all declarations be an Integer (any signedness) of the same Type.");
    }
    return struct{
        /// Return this Struct or Union as an Enum.
        pub fn Enum() type {
            var enum_fields: [type_decls.len]std.builtin.Type.EnumField = undefined;
            for (type_decls, enum_fields[0..]) |decl, *field| {
                field.* = .{
                    .name = decl.name,
                    .value = @field(T, decl.name),
                };
            }
            return @Type(std.builtin.Type{
                .Enum = .{
                    .tag_type = TagT,
                    .fields = enum_fields[0..],
                    .decls = &.{},
                    .is_exhaustive = true,
                }
            });
        }

        pub fn inEnum(value: TagT) bool {
            return for (std.enums.values(Enum())) |e_val| {
                if (value == @intFromEnum(e_val)) break true;
            }
            else false;
        }
    };
}
