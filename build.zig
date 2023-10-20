const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    b.exe_dir = "./bin";

    // Tests
    // - Datagram
    const datagram_test = b.addTest(.{
        .root_source_file = .{ .path = "src/datagram_tests.zig" },
        .target = target,
        .optimize = optimize,
    });
    const datagram_test_step = b.step("datagram-test", "Run the Datagram tests");
    datagram_test_step.dependOn(&datagram_test.step);
    // - All
    const test_step = b.step("test", "Run all tests.");
    test_step.dependOn(&datagram_test.step);

    // Lib Module
    const zing_lib_mod = b.addModule("zinglib", .{
        .source_file = std.Build.FileSource.relative("src/zinglib.zig"),
    });

    // Dependencies
    // - Cova
    const cova_dep = b.dependency("cova", .{ .target = target, .optimize = optimize });
    const cova_mod = cova_dep.module("cova");

    // Exe
    const zing_exe = b.addExecutable(.{
        .name = "zing",
        .root_source_file = .{ .path = "zing.zig" },
        .target = target,
        .optimize = optimize,
    });
    zing_exe.addModule("zinglib", zing_lib_mod);
    zing_exe.addModule("cova", cova_mod);
    const build_zing_exe = b.addInstallArtifact(zing_exe, .{});
    const build_zing_exe_step = b.step("exe", "Build the zing exe");
    build_zing_exe_step.dependOn(&build_zing_exe.step);
    b.default_step = &build_zing_exe.step; // <- DEFAULT STEP

    // Docs
    // - Library
    //const 
    //const zing_lib_docs = b.addInstallDirectory(.{
    //    .source_dir = 
    //    .target = target,
    //    .optimize = optimize,
    //});
    //zing_lib_docs.emit_docs = .emit;
    //const build_lib_docs = b.addRunArtifact(zing_lib_docs);
    //build_lib_docs.has_side_effects = true;
    //const build_lib_docs_step = b.step("docs", "Build the zing library docs");
    //build_lib_docs_step.dependOn(&zing_lib_docs.step);

    // Install (WIP)
    // - Tested (Default)
    //const install_tested_step = b.step("install-tested", "Run library tests, then install");
    //for (test_step.dependencies.allocatedSlice()) |dep| install_tested_step.dependOn(dep);
    //install_tested_step.dependOn(b.getInstallStep());

    //// - Full
    //const install_full_step = b.step("install-full", "Run library tests, build docs, then install");
    //for (test_step.dependencies.allocatedSlice()) |dep| install_full_step.dependOn(dep);
    //install_full_step.dependOn(&build_lib_docs.step);
    //install_full_step.dependOn(b.getInstallStep());
}
