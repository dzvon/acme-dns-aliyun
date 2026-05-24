/// ACME DNS01 Solver Webhook for Alibaba Cloud (Aliyun) DNS
/// Compatible with cert-manager's webhook DNS01 solver protocol.
///
/// Supports two credential modes:
///   1. AccessKey/SecretKey  – set via env vars or config JSON
///   2. RRSA (RAM Roles for Service Accounts) – OIDC-based, no static keys
///
/// Environment variables (all optional, can also come from the JSON body):
///   ALIBABA_CLOUD_ACCESS_KEY_ID       – AK for static-key mode
///   ALIBABA_CLOUD_ACCESS_KEY_SECRET   – SK for static-key mode
///   ALIBABA_CLOUD_ROLE_ARN            – RRSA: role ARN
///   ALIBABA_CLOUD_OIDC_PROVIDER_ARN   – RRSA: OIDC IdP ARN
///   ALIBABA_CLOUD_OIDC_TOKEN_FILE     – RRSA: path to projected SA token
///   ALIBABA_CLOUD_REGION              – e.g. "cn-hangzhou" (default)
///   WEBHOOK_PORT                      – listening port (default 8080)
///   WEBHOOK_GROUP_NAME                – solver group name
///   WEBHOOK_SOLVER_NAME               – solver name (default "alidns")
///   WEBHOOK_TLS_CERT_FILE             – TLS cert file path (default "/etc/tls.crt")
///   WEBHOOK_TLS_KEY_FILE              – TLS key file path (default "/etc/tls.key")
const std = @import("std");
const config = @import("config.zig");
const server = @import("server.zig");
const sig = @import("signature.zig");

var shutdown_event: std.Io.Event = .unset;
var shutdown_event_io: std.Io = undefined;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const environ = &init.minimal.environ;
    const io = init.io;

    // Parse config from environment
    const cfg = try config.Config.fromEnviron(gpa, environ);
    defer cfg.deinit(gpa);

    const port_str = environ.getPosix("WEBHOOK_PORT") orelse "8080";
    const port = std.fmt.parseInt(u16, port_str, 10) catch |err| {
        std.log.err("invalid WEBHOOK_PORT: {}", .{err});
        return error.InvalidPort;
    };

    std.log.info("acme-dns-aliyun webhook starting on :{}", .{port});
    std.log.info("solver group={s} name={s}", .{ cfg.group_name, cfg.solver_name });
    if (cfg.credentials == .rrsa) {
        std.log.info("credential mode: RRSA (OIDC)", .{});
    } else {
        std.log.info("credential mode: AccessKey", .{});
    }

    shutdown_event_io = io;
    // Install signal handlers before doing anything else.
    const sa: std.posix.Sigaction = .{
        .handler = .{ .handler = struct {
            fn handler(_: std.posix.SIG) callconv(.c) void {
                std.log.info("shutdown signal received, stopping listener", .{});
                shutdown_event.set(shutdown_event_io);
            }
        }.handler },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &sa, null);
    std.posix.sigaction(std.posix.SIG.TERM, &sa, null);

    // Start HTTP server
    var server_future = try io.concurrent(server.run, .{ io, gpa, port, cfg });
    defer {
        std.log.info("shutting down the server", .{});
        server_future.cancel(io) catch {};
    }

    std.log.info("Server started, send SIGINT or SIGTERM to shutdown", .{});
    shutdown_event.waitUncancelable(io);
}

test {
    _ = sig;
}
