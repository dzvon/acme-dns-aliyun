/// HTTPS server for the cert-manager DNS01 webhook.
///
/// TLS is MANDATORY: cert-manager routes ChallengePayload requests through the
/// Kubernetes API aggregation layer, which opens a TLS connection to our Service
/// and verifies the serving certificate against the caBundle stored in the
/// APIService object.  Plain HTTP is never accepted.
///
/// We use OpenSSL (libssl + libcrypto) for TLS because Zig 0.16's standard
/// library only ships std.crypto.tls.Client — there is no std.crypto.tls.Server
/// yet (tracked in ziglang/zig#14171).
///
/// TLS certificate / key loading:
///   cert-manager's cainjector provisions a TLS cert for us via a Certificate
///   resource and stores it in a Kubernetes Secret.  We mount that Secret as a
///   volume and read two files:
///     WEBHOOK_TLS_CERT_FILE  (default: /tls/tls.crt)
///     WEBHOOK_TLS_KEY_FILE   (default: /tls/tls.key)
///
/// Routes:
///   POST /apis/<groupName>/v1alpha1/<solverName>  – present or cleanup a challenge
///                                                   (action is a field in the request body)
///   GET  /healthz                                 – liveness probe
///
/// cert-manager calls the webhook via the Kubernetes API aggregation layer:
///   cert-manager → kube-apiserver → POST /apis/<groupName>/v1alpha1/<solverName>
///
/// The groupName and solverName come from WEBHOOK_GROUP_NAME and WEBHOOK_SOLVER_NAME
/// environment variables and must match the APIService and ClusterIssuer manifests.
///
/// Request / Response shape (cert-manager ChallengePayload):
///   Request body (JSON):
///     {
///       "apiVersion": "acme.cert-manager.io/v1alpha1",
///       "kind": "ChallengePayload",
///       "request": {
///         "uid":           "<uuid>",
///         "action":        "Present" | "CleanUp",
///         "type":          "dns-01",
///         "dnsName":       "example.com",
///         "resolvedFQDN":  "_acme-challenge.example.com.",
///         "resolvedZone":  "example.com.",
///         "key":           "<token>",
///         "resourceNamespace": "cert-manager",
///         "allowAmbientCredentials": false,
///         "config": { /* solver-specific JSON */ }
///       }
///     }
///
///   Success response body (JSON):
///     {
///       "apiVersion": "acme.cert-manager.io/v1alpha1",
///       "kind": "ChallengePayload",
///       "response": {
///         "uid":     "<same uid>",
///         "success": true
///       }
///     }
///
///   Failure response body (JSON):
///     {
///       "apiVersion": "acme.cert-manager.io/v1alpha1",
///       "kind": "ChallengePayload",
///       "response": {
///         "uid":    "<same uid>",
///         "status": { "status": "Failed", "message": "<reason>" }
///       }
///     }
const std = @import("std");
const config = @import("config.zig");
const dns = @import("dns.zig");
const rrsa = @import("rrsa.zig");

const ssl_h = @import("openssl");
const SSL_CTX = ssl_h.SSL_CTX;
const SSL = ssl_h.SSL;

/// Transient credentials resolved per-request (from static AK or RRSA STS).
pub const ResolvedCreds = struct {
    access_key_id: []const u8,
    access_key_secret: []const u8,
    security_token: ?[]const u8, // only for RRSA
    allocator: std.mem.Allocator,

    pub fn deinit(self: ResolvedCreds) void {
        self.allocator.free(self.access_key_id);
        self.allocator.free(self.access_key_secret);
        if (self.security_token) |token| self.allocator.free(token);
    }
};

const ChallengeRequest = struct {
    uid: []const u8 = "",
    action: []const u8 = "",
    type: []const u8 = "", // "dns-01"
    dnsName: []const u8 = "",
    resolvedFQDN: []const u8 = "",
    resolvedZone: []const u8 = "",
    key: []const u8 = "",
    resourceNamespace: []const u8 = "",
    allowAmbientCredentials: bool = false,
    // Solver-specific config (we ignore it; creds come from env only)
};

const ChallengePayloadIn = struct {
    apiVersion: []const u8 = "",
    kind: []const u8 = "",
    request: ChallengeRequest = .{},
};

/// Holds the SSL_CTX and tracks the cert file mtime for in-process hot reload.
/// A mutex serialises reloads so concurrent connection tasks see a consistent ctx.
const TlsContext = struct {
    ctx: *SSL_CTX,
    mutex: std.Io.Mutex,
    cert_mtime: i96,

    fn init(io: std.Io, method: *const ssl_h.SSL_METHOD, cfg: config.Config) !TlsContext {
        const ctx = ssl_h.SSL_CTX_new(method) orelse {
            logOpenSSLError("SSL_CTX_new");
            return error.OpenSSLInit;
        };
        _ = ssl_h.SSL_CTX_set_min_proto_version(ctx, ssl_h.TLS1_2_VERSION);
        try loadCerts(ctx, cfg);
        const mtime = try certMtime(io, cfg.cert_file_path);
        std.log.info("TLS: loaded cert={s} key={s}", .{ cfg.cert_file_path, cfg.key_file_path });
        return .{ .ctx = ctx, .mutex = .init, .cert_mtime = mtime };
    }

    fn deinit(self: *TlsContext) void {
        ssl_h.SSL_CTX_free(self.ctx);
    }

    /// Reloads cert/key into the SSL_CTX if the cert file mtime has changed.
    fn reloadIfChanged(self: *TlsContext, io: std.Io, cfg: config.Config) void {
        const mtime = certMtime(io, cfg.cert_file_path) catch return;
        if (mtime == self.cert_mtime) return;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        // Re-check under lock — another task may have already reloaded.
        if (mtime == self.cert_mtime) return;
        loadCerts(self.ctx, cfg) catch |err| {
            std.log.err("TLS reload failed: {}", .{err});
            return;
        };
        self.cert_mtime = mtime;
        std.log.info("TLS: reloaded cert={s} key={s}", .{ cfg.cert_file_path, cfg.key_file_path });
    }
};

fn certMtime(io: std.Io, cert_path: []const u8) !i96 {
    const stat = try std.Io.Dir.statFile(std.Io.Dir.cwd(), io, cert_path, .{});
    return stat.mtime.nanoseconds;
}

fn loadCerts(ctx: *SSL_CTX, cfg: config.Config) !void {
    if (ssl_h.SSL_CTX_use_certificate_chain_file(ctx, cfg.cert_file_path.ptr) != 1) {
        logOpenSSLError("SSL_CTX_use_certificate_chain_file");
        std.log.err("Failed to load TLS cert from {s}", .{cfg.cert_file_path});
        return error.TlsCertLoad;
    }
    if (ssl_h.SSL_CTX_use_PrivateKey_file(ctx, cfg.key_file_path.ptr, ssl_h.SSL_FILETYPE_PEM) != 1) {
        logOpenSSLError("SSL_CTX_use_PrivateKey_file");
        std.log.err("Failed to load TLS key from {s}", .{cfg.key_file_path});
        return error.TlsKeyLoad;
    }
    if (ssl_h.SSL_CTX_check_private_key(ctx) != 1) {
        logOpenSSLError("SSL_CTX_check_private_key");
        return error.TlsKeyMismatch;
    }
}

pub fn run(
    io: std.Io,
    allocator: std.mem.Allocator,
    port: u16,
    cfg: config.Config,
    group: *std.Io.Group,
) !void {
    // Initialize OpenSSL
    _ = ssl_h.OPENSSL_init_ssl(0, null);
    ssl_h.ERR_clear_error();

    const method = ssl_h.TLS_server_method() orelse {
        std.log.err("OpenSSL: TLS_server_method() return null", .{});
        return error.OpenSSLInit;
    };

    var tls = try TlsContext.init(io, method, cfg);
    defer tls.deinit();

    const addr = try std.Io.net.IpAddress.parseIp4("0.0.0.0", port);
    var listener = try addr.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    std.log.info("listening on 0.0.0.0:{d} HTTPS", .{port});

    while (true) {
        const conn = listener.accept(io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => {
                std.log.warn("accept failed: {t}", .{err});
                continue;
            },
        };

        tls.reloadIfChanged(io, cfg);

        try group.concurrent(io, handleConnectionTask, .{ io, allocator, conn, tls.ctx, cfg });
    }
}

// Wrapper task matching the signature required by `std.Io.Group`
fn handleConnectionTask(
    io: std.Io,
    allocator: std.mem.Allocator,
    conn: std.Io.net.Stream,
    ctx: *SSL_CTX,
    cfg: config.Config,
) std.Io.Cancelable!void {
    handleConnection(io, allocator, conn, ctx, cfg) catch |err| {
        if (err == error.Canceled) return error.Canceled;
        std.log.err("connection handler error: {}", .{err});
    };
}

/// Bridges OpenSSL SSL_read / SSL_write to the std.Io Reader / Writer interfaces
/// that std.http.Server expects.
///
/// Layout note: `reader` and `writer` are embedded fields so that
/// @fieldParentPtr can recover the SslStream pointer from either vtable callback.
const SslStream = struct {
    ssl: *SSL,
    reader: std.Io.Reader,
    writer: std.Io.Writer,

    // Reader VTable: pull bytes from SSL into w's available buffer space, or into
    // r.buffer when w is full. Returning 0 with no progress while `limit` is
    // .unlimited causes callers like appendRemainingAligned to spin at 100% CPU,
    // so we must store data somewhere (w or r.buffer) before returning 0.
    fn sslStreamFn(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *SslStream = @fieldParentPtr("reader", r);

        const w_avail = w.buffer[w.end..];
        if (w_avail.len > 0) {
            // Fast path: write directly into w's unused space.
            const max: usize = if (limit.toInt()) |l| @min(l, w_avail.len) else w_avail.len;
            const n = ssl_h.SSL_read(self.ssl, w_avail.ptr, @intCast(max));
            if (n > 0) {
                w.end += @intCast(n);
                return @intCast(n);
            }
            const ssl_err = ssl_h.SSL_get_error(self.ssl, n);
            return switch (ssl_err) {
                ssl_h.SSL_ERROR_ZERO_RETURN => error.EndOfStream,
                ssl_h.SSL_ERROR_SYSCALL => if (n == 0) error.EndOfStream else error.ReadFailed,
                else => error.ReadFailed,
            };
        }

        // w is full: store into r.buffer and return 0 so the caller can drain w
        // first. The vtable contract allows this — returning 0 is only safe when
        // data was buffered in r.buffer (otherwise callers spin).
        const r_avail = r.buffer[r.end..];
        if (r_avail.len == 0) return error.ReadFailed; // both buffers full, cannot make progress
        const max: usize = if (limit.toInt()) |l| @min(l, r_avail.len) else r_avail.len;
        const n = ssl_h.SSL_read(self.ssl, r_avail.ptr, @intCast(max));
        if (n > 0) {
            r.end += @intCast(n);
            return 0; // data is in r.buffer; caller will see it via the buffered path
        }
        const ssl_err = ssl_h.SSL_get_error(self.ssl, n);
        return switch (ssl_err) {
            ssl_h.SSL_ERROR_ZERO_RETURN => error.EndOfStream,
            ssl_h.SSL_ERROR_SYSCALL => if (n == 0) error.EndOfStream else error.ReadFailed,
            else => error.ReadFailed,
        };
    }

    // Writer VTable: flush buffered bytes + `data` slices through SSL_write.
    fn sslDrainFn(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *SslStream = @fieldParentPtr("writer", w);
        // Flush the writer's internal buffer first.
        if (w.end > 0) {
            const n = ssl_h.SSL_write(self.ssl, w.buffer.ptr, @intCast(w.end));
            if (n <= 0) return error.WriteFailed;
            w.end = 0;
        }
        // Write each slice in `data`; the last one is repeated `splat` times.
        var total: usize = 0;
        for (data, 0..) |slice, i| {
            const count: usize = if (i == data.len - 1) splat else 1;
            const s = slice;
            for (0..count) |_| {
                if (s.len == 0) continue;
                const n = ssl_h.SSL_write(self.ssl, s.ptr, @intCast(s.len));
                if (n <= 0) return error.WriteFailed;
                total += @intCast(n);
            }
        }
        return total;
    }

    const reader_vtable: std.Io.Reader.VTable = .{ .stream = sslStreamFn };
    const writer_vtable: std.Io.Writer.VTable = .{ .drain = sslDrainFn };

    fn init(ssl: *SSL, read_buf: []u8, write_buf: []u8) SslStream {
        return .{
            .ssl = ssl,
            .reader = .{
                .vtable = &reader_vtable,
                .buffer = read_buf,
                .seek = 0,
                .end = 0,
            },
            .writer = .{
                .vtable = &writer_vtable,
                .buffer = write_buf,
                .end = 0,
            },
        };
    }
};

// TLS + HTTP handling
fn handleConnection(
    io: std.Io,
    allocator: std.mem.Allocator,
    conn: std.Io.net.Stream,
    ctx: *SSL_CTX,
    cfg: config.Config,
) !void {
    defer conn.close(io);

    // Wrap the raw TCP file descriptor in an OpenSSL SSL object
    const ssl = ssl_h.SSL_new(ctx) orelse {
        logOpenSSLError("SSL_new");
        return error.SslNew;
    };
    // Send TLS close_notify before freeing — prevents "unexpected eof" on the client.
    defer _ = ssl_h.SSL_shutdown(ssl);
    defer ssl_h.SSL_free(ssl);

    const fd = conn.socket.handle;
    if (ssl_h.SSL_set_fd(ssl, fd) != 1) {
        logOpenSSLError("SSL_set_fd");
        return error.SslSetFd;
    }

    // Perform TLS handshake
    const accept_ret = ssl_h.SSL_accept(ssl);
    if (accept_ret != 1) {
        const err = ssl_h.SSL_get_error(ssl, accept_ret);
        std.log.warn("SSL_accept failed: SSL_error={d}", .{err});
        return error.SslHandshake;
    }

    var read_buf: [4096]u8 = undefined;
    var write_buf: [4096]u8 = undefined;
    var ssl_stream = SslStream.init(ssl, &read_buf, &write_buf);

    var http_server = std.http.Server.init(&ssl_stream.reader, &ssl_stream.writer);

    while (true) {
        var request = http_server.receiveHead() catch |err| switch (err) {
            error.HttpConnectionClosing => return, // client closed connection
            else => {
                std.log.err("receiveHead: {}", .{err});
                return err;
            },
        };

        handleRequest(io, allocator, &request, cfg) catch |err| {
            std.log.err("handleRequest: {}", .{err});
            request.respond("Internal Server Error\n", .{
                .status = .internal_server_error,
                .extra_headers = &.{.{
                    .name = "Content-Type",
                    .value = "text/plain",
                }},
            }) catch {};
            return;
        };

        if (!request.head.keep_alive) return;
    }
}

fn handleRequest(
    io: std.Io,
    gpa: std.mem.Allocator,
    req: *std.http.Server.Request,
    cfg: config.Config,
) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const allocator = arena.allocator();

    const target = req.head.target;

    // Health check endpoint
    if (std.mem.startsWith(u8, target, "/healthz")) {
        if (req.head.method.requestHasBody()) {
            var buf: [4096]u8 = undefined;
            const body_reader = req.readerExpectNone(&buf);
            _ = body_reader.discardRemaining() catch {};
        }
        try req.respond("ok\n", .{
            .status = .ok,
            .extra_headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
        });
        return;
    }

    // cert-manager calls POST /apis/<groupName>/v1alpha1/<solverName>
    const solver_path = try std.fmt.allocPrint(
        allocator,
        "/apis/{s}/v1alpha1/{s}",
        .{ cfg.group_name, cfg.solver_name },
    );

    if (std.mem.startsWith(u8, target, solver_path)) {
        if (req.head.method != .POST) {
            try req.respond("Method Not Allowed\n", .{ .status = .method_not_allowed });
            return;
        }

        // Read body
        var body_buf: [4096]u8 = undefined;
        const body_reader = try req.readerExpectContinue(&body_buf);

        const body = body_reader.allocRemaining(allocator, .limited(256 * 1024)) catch |err| {
            std.log.err("allocRemaining failed: {}", .{err});
            return err;
        };

        // Parse JSON
        const parsed = std.json.parseFromSliceLeaky(ChallengePayloadIn, allocator, body, .{ .ignore_unknown_fields = true }) catch |err| {
            std.log.err("JSON parse error: {}", .{err});
            const resp = try std.fmt.allocPrint(allocator, "{{\"error\":\"bad json: {}\"}}", .{err});
            try req.respond(resp, .{
                .status = .bad_request,
                .extra_headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
            });
            return;
        };

        const challenge = parsed.request;
        const uid = challenge.uid;

        // Action is a body field: "Present" or "CleanUp" (cert-manager types.go)
        const action: dns.Action = if (std.mem.eql(u8, challenge.action, "Present"))
            .present
        else if (std.mem.eql(u8, challenge.action, "CleanUp"))
            .cleanup
        else {
            std.log.err("unknown action: {s}", .{challenge.action});
            return sendError(allocator, req, uid, "unknown action");
        };

        std.log.info("action={s} dnsName={s} resolvedFQDN={s}", .{ challenge.action, challenge.dnsName, challenge.resolvedFQDN });

        // Resolve credentials (static AK or RRSA)
        const creds = resolveCreds(io, allocator, cfg) catch |err| {
            std.log.err("credential resolution failed: {}", .{err});
            return sendError(allocator, req, uid, "credential error");
        };
        defer creds.deinit();

        // Perform DNS operation
        dns.perform(io, allocator, action, challenge.resolvedFQDN, challenge.resolvedZone, challenge.key, creds, cfg) catch |err| {
            std.log.err("DNS operation failed: {}", .{err});
            return sendError(allocator, req, uid, "dns error");
        };

        // Success response
        const resp_body = try std.fmt.allocPrint(allocator,
            \\{{
            \\  "apiVersion": "acme.cert-manager.io/v1alpha1",
            \\  "kind": "ChallengePayload",
            \\  "response": {{
            \\    "uid": "{s}",
            \\    "success": true
            \\  }}
            \\}}
        , .{uid});

        try req.respond(resp_body, .{
            .status = .ok,
            .extra_headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        });
        return;
    }

    // Discovery: GET /apis/<group>/v1alpha1 — kube-apiserver polls this to check APIService availability.
    const version_path = try std.fmt.allocPrint(allocator, "/apis/{s}/v1alpha1", .{cfg.group_name});

    if (std.mem.eql(u8, target, version_path)) {
        const body = try std.fmt.allocPrint(allocator,
            \\{{
            \\  "kind": "APIResourceList",
            \\  "apiVersion": "v1",
            \\  "groupVersion": "{s}/v1alpha1",
            \\  "resources": [
            \\    {{
            \\      "name": "{1s}",
            \\      "singularName": "{1s}",
            \\      "namespaced": false,
            \\      "kind": "ChallengePayload",
            \\      "verbs": ["create"]
            \\    }}
            \\  ]
            \\}}
        , .{ cfg.group_name, cfg.solver_name });
        try req.respond(body, .{
            .status = .ok,
            .extra_headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        });
        return;
    }

    // Discovery: GET /apis/<group> — kube-apiserver polls this for group metadata.
    const group_path = try std.fmt.allocPrint(allocator, "/apis/{s}", .{cfg.group_name});

    if (std.mem.eql(u8, target, group_path)) {
        if (req.head.method.requestHasBody()) {
            var buf: [4096]u8 = undefined;
            _ = req.readerExpectNone(&buf).discardRemaining() catch {};
        }
        const body = try std.fmt.allocPrint(allocator,
            \\{{
            \\  "kind": "APIGroup",
            \\  "apiVersion": "v1",
            \\  "name": "{0s}",
            \\  "versions": [
            \\    {{"groupVersion": "{0s}/v1alpha1", "version": "v1alpha1"}}
            \\  ],
            \\  "preferredVersion": {{"groupVersion": "{0s}/v1alpha1", "version": "v1alpha1"}}
            \\}}
        , .{cfg.group_name});
        try req.respond(body, .{
            .status = .ok,
            .extra_headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        });
        return;
    }

    // Aggregated discovery: GET /apis — modern kube-aggregator tries this first with
    // Accept: application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList
    // We respond with APIGroupDiscoveryList regardless of Accept to satisfy both
    // the aggregated-discovery manager and legacy discovery fallback.
    if (std.mem.eql(u8, target, "/apis")) {
        if (req.head.method.requestHasBody()) {
            var buf: [4096]u8 = undefined;
            _ = req.readerExpectNone(&buf).discardRemaining() catch {};
        }
        const body = try std.fmt.allocPrint(allocator,
            \\{{
            \\  "metadata": {{}},
            \\  "kind": "APIGroupDiscoveryList",
            \\  "apiVersion": "apidiscovery.k8s.io/v2",
            \\  "items": [
            \\    {{
            \\      "metadata": {{"name": "{0s}"}},
            \\      "versions": [
            \\        {{
            \\          "version": "v1alpha1",
            \\          "resources": [
            \\            {{
            \\              "resource": "{1s}",
            \\              "responseKind": {{"group": "{0s}", "version": "v1alpha1", "kind": "ChallengePayload"}},
            \\              "scope": "Cluster",
            \\              "singularResource": "{1s}",
            \\              "verbs": ["create"]
            \\            }}
            \\          ]
            \\        }}
            \\      ]
            \\    }}
            \\  ]
            \\}}
        , .{ cfg.group_name, cfg.solver_name });
        try req.respond(body, .{
            .status = .ok,
            .extra_headers = &.{.{
                .name = "Content-Type",
                // kube-aggregator checks for this exact content-type to recognize v2 aggregated discovery
                .value = "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList",
            }},
        });
        return;
    }

    try req.respond("Not Found\n", .{
        .status = .not_found,
        .extra_headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
    });
    return;
}

fn sendError(
    allocator: std.mem.Allocator,
    req: *std.http.Server.Request,
    uid: []const u8,
    errorMsg: []const u8,
) !void {
    const resp_body = try std.fmt.allocPrint(allocator,
        \\{{
        \\  "apiVersion": "acme.cert-manager.io/v1alpha1",
        \\  "kind": "ChallengePayload",
        \\  "response": {{
        \\    "uid": "{s}",
        \\    "status": {{ "status": "Failed", "message": "{s}" }}
        \\  }}
        \\}}
    , .{ uid, errorMsg });
    defer allocator.free(resp_body);

    try req.respond(resp_body, .{
        .status = .ok,
        .extra_headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    });
}

/// Resolve temporary credentials.
/// In RRSA mode this calls STS AssumeRoleWithOIDC.
/// In static mode it just wraps the configured AK/SK.
fn resolveCreds(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: config.Config,
) !ResolvedCreds {
    switch (cfg.credentials) {
        .access_key => |ak| {
            return .{
                .access_key_id = try allocator.dupe(u8, ak.access_key_id),
                .access_key_secret = try allocator.dupe(u8, ak.access_key_secret),
                .security_token = null,
                .allocator = allocator,
            };
        },
        .rrsa => |r| {
            return rrsa.assumeRoleWithOidc(io, allocator, r, cfg.sts_endpoint);
        },
    }
}

/// OpenSSL error logging
fn logOpenSSLError(context: []const u8) void {
    var err_buf: [256]u8 = undefined;
    const code = ssl_h.ERR_get_error();
    ssl_h.ERR_error_string_n(code, &err_buf, err_buf.len);
    // err_buf is now a null-terminated C string
    const msg = std.mem.sliceTo(&err_buf, 0);
    std.log.err("OpenSSL {s}: {s}", .{ context, msg });
}
