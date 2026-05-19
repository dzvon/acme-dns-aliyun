const std = @import("std");
const Translator = @import("translate_c").Translator;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const openssl_include = b.option([]const u8, "openssl-include", "OpenSSL include path (default: /usr/local/include)") orelse "/usr/local/include";
    const openssl_lib = b.option([]const u8, "openssl-lib", "OpenSSL library path (default: /usr/local/lib)") orelse "/usr/local/lib";

    // Translate OpenSSL C headers into a Zig module to avoid @cImport issues
    // with FreeBSD's sys/time.h inline macros that Zig's C translator cannot handle.
    const translate_c = b.dependency("translate_c", .{});
    const openssl_translated: Translator = .init(translate_c, .{
        .name = "openssl",
        .c_source_file = b.path("src/openssl.h"),
        .target = target,
        .optimize = optimize,
    });
    openssl_translated.run.addArg(b.fmt("-I{s}", .{openssl_include}));
    openssl_translated.mod.addLibraryPath(.{ .cwd_relative = openssl_lib });
    openssl_translated.mod.linkSystemLibrary("ssl", .{});
    openssl_translated.mod.linkSystemLibrary("crypto", .{});

    // Executable
    const exe = b.addExecutable(.{
        .name = "acme-dns-aliyun",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "openssl", .module = openssl_translated.mod },
            },
        }),
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    const run_step = b.step("run", "Run the webhook server");
    run_step.dependOn(&run_cmd.step);

    // Manifest generator
    const manifest_exe = b.addExecutable(.{
        .name = "manifest",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/manifest.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_manifest = b.addRunArtifact(manifest_exe);
    run_manifest.addArg(b.path("zig-out/manifests").getPath(b));
    // inherit lets prompts reach the terminal interactively.
    run_manifest.stdio = .inherit;
    const manifest_step = b.step("manifest", "Interactively generate Kubernetes manifests into zig-out/manifests/");
    manifest_step.dependOn(&run_manifest.step);

    // Tests
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);
}
