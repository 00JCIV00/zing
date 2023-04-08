const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addSharedLibrary(.{
        .name = "zacket-lib",
        .root_source_file = .{ .path = "src/lib.zig" },
        .target = target,
        .optimize = optimize,
    });
    lib.install();

    // Add Library files as Modules
    std.debug.print("Adding Library Files as Modules...\n", .{});
    var src_dir = (std.fs.cwd()).openIterableDir("src/", .{}) catch return;
    defer src_dir.close();
    var src_dir_iter = src_dir.iterate();
    var mod_count: u16 = 0;
    while (src_dir_iter.next()) |next_file| {
        const file = next_file orelse break;
        if (!(file.kind == .File and std.mem.indexOf(u8, file.name, ".zig") == file.name.len - 4) or (std.mem.eql(u8, file.name, "lib.zig"))) continue;

        const mod_name = @constCast(&std.mem.tokenize(u8, file.name, ".")).peek() orelse {
            std.debug.print("There was an issue getting the module name of '{s}'.\n", .{ file.name });
            return;
        };
        const path = std.fmt.allocPrint(b.allocator, "src/{s}", .{ file.name }) catch |err| {
            std.debug.print("There was an issue making the relative path for '{s}':\n{}\n", .{ file.name, err });
            return;    
        };
        defer b.allocator.free(path);
        _ = b.addModule(mod_name, .{ .source_file = .{ .path = path } });
        std.debug.print("- Added > Module: {s}, File: {s}\n", .{ mod_name, path, });
        mod_count += 1;
    }
    else |err| { 
        std.debug.print("\nThere was an error while traversing the 'src' directory:\n{}\n", .{ err });
        return;
    }
    std.debug.print("Added {d} Library Files as Modules.\n", .{ mod_count });

    // Tests
    // - Datagram
    const datagram_test = b.addTest(.{
        .root_source_file = .{ .path = "src/datagram_tests.zig" },
        .target = target,
        .optimize = optimize,
    });
    const datagram_test_step = b.step("datagram-test", "Run the Datagram tests.");
    datagram_test_step.dependOn(&datagram_test.step);
    // - All
    const test_step = b.step("test", "Run all tests.");
    test_step.dependOn(@constCast(datagram_test_step));

    // Docs
    const lib_docs = b.addTest(.{
        .root_source_file = .{ .path = "src/lib.zig" },
        .target = target,
        .optimize = optimize,
    });
    lib_docs.emit_docs = .emit;
    const lib_docs_step = b.step("gen-docs", "Generate docs.");
    lib_docs_step.dependOn(&lib_docs.step);

    // Install
    // - Tested (Default)
    const install_tested_step = b.step("install-tested", "Run library tests, then install.");
    install_tested_step.dependOn(@constCast(test_step));
    install_tested_step.dependOn(b.getInstallStep());
    b.default_step = @constCast(install_tested_step); // <- DEFAULT STEP

    // - Full
    const install_full_step = b.step("install-full", "Run library tests, generate docs, then install.");
    install_full_step.dependOn(@constCast(test_step));
    install_full_step.dependOn(@constCast(lib_docs_step));
    install_full_step.dependOn(b.getInstallStep());
}
