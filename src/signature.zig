/// Alibaba Cloud V3 request signing (ACS3-HMAC-SHA256).
///
/// Algorithm:
///   1. Build CanonicalRequest:
///        HTTPMethod + '\n' +
///        CanonicalURI + '\n' +
///        CanonicalQueryString + '\n' +
///        CanonicalHeaders + '\n' +
///        SignedHeaders + '\n' +
///        HashedRequestPayload
///   2. Build StringToSign:
///        "ACS3-HMAC-SHA256\n" + hex(SHA256(CanonicalRequest))
///   3. signature = hex(HMAC-SHA256(AccessKeySecret, StringToSign))
///   4. Authorization header:
///        "ACS3-HMAC-SHA256 Credential=<AK>,SignedHeaders=<list>,Signature=<sig>"
///
/// Reference: https://www.alibabacloud.com/help/en/sdk/product-overview/v3-request-structure-and-signature
const std = @import("std");

pub const Param = struct {
    key: []const u8,
    value: []const u8,
};

pub const V3Headers = struct {
    authorization: []const u8,
    x_acs_date: []const u8,
    x_acs_nonce: []const u8,
    x_acs_content_sha256: []const u8,
    /// Present only when using STS temporary credentials.
    x_acs_security_token: ?[]const u8,

    pub fn deinit(self: V3Headers, allocator: std.mem.Allocator) void {
        allocator.free(self.authorization);
        allocator.free(self.x_acs_date);
        allocator.free(self.x_acs_nonce);
        allocator.free(self.x_acs_content_sha256);
        if (self.x_acs_security_token) |token| allocator.free(token);
    }
};

/// Build the V3 signed headers for an AliCloud API call.
///
/// `query_params` are the API-specific parameters (e.g. Action, DomainName…).
/// They must NOT include auth/signing fields — those go in headers now.
/// `action` is the API operation name (e.g. "DescribeDomainRecords").
/// `version` is the API version string (e.g. "2015-01-09").
/// `host` is the service hostname (e.g. "alidns.aliyuncs.com").
/// `body` is the raw request body bytes; pass "" for GET requests with no body.
/// `security_token` is only set when using STS temporary credentials.
///
/// Returns owned strings; call V3Headers.deinit() when done.
pub fn buildV3Headers(
    io: std.Io,
    allocator: std.mem.Allocator,
    method: []const u8,
    host: []const u8,
    action: []const u8,
    version: []const u8,
    query_params: []const Param,
    body: []const u8,
    security_token: ?[]const u8,
    access_key_id: []const u8,
    access_key_secret: []const u8,
) !V3Headers {
    const date = try iso8601Timestamp(io, allocator);
    errdefer allocator.free(date);

    const nonce = try randomNonce(io, allocator);
    errdefer allocator.free(nonce);

    const body_hash = hexSha256(body);
    const content_sha256 = try allocator.dupe(u8, &body_hash);
    errdefer allocator.free(content_sha256);

    // Build CanonicalQueryString from sorted query params
    const canonical_query = try buildCanonicalQuery(allocator, query_params);
    defer allocator.free(canonical_query);

    // Build CanonicalHeaders and SignedHeaders.
    // Always sign: host, x-acs-action, x-acs-content-sha256, x-acs-date,
    //              x-acs-signature-nonce, x-acs-version
    // Conditionally add: x-acs-security-token (when STS creds are used)
    const signed_headers_str, const canonical_headers_str = blk: {
        if (security_token) |token| {
            const sh = "host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-security-token;x-acs-signature-nonce;x-acs-version";
            const ch = try std.fmt.allocPrint(
                allocator,
                "host:{s}\nx-acs-action:{s}\nx-acs-content-sha256:{s}\nx-acs-date:{s}\nx-acs-security-token:{s}\nx-acs-signature-nonce:{s}\nx-acs-version:{s}\n",
                .{ host, action, content_sha256, date, token, nonce, version },
            );
            break :blk .{ sh, ch };
        } else {
            const sh = "host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version";
            const ch = try std.fmt.allocPrint(
                allocator,
                "host:{s}\nx-acs-action:{s}\nx-acs-content-sha256:{s}\nx-acs-date:{s}\nx-acs-signature-nonce:{s}\nx-acs-version:{s}\n",
                .{ host, action, content_sha256, date, nonce, version },
            );
            break :blk .{ sh, ch };
        }
    };
    defer allocator.free(canonical_headers_str);

    // CanonicalRequest
    const canonical_request = try std.fmt.allocPrint(
        allocator,
        "{s}\n/\n{s}\n{s}\n{s}\n{s}",
        .{ method, canonical_query, canonical_headers_str, signed_headers_str, content_sha256 },
    );
    defer allocator.free(canonical_request);

    // StringToSign
    const cr_hash = hexSha256(canonical_request);
    const string_to_sign = try std.fmt.allocPrint(
        allocator,
        "ACS3-HMAC-SHA256\n{s}",
        .{&cr_hash},
    );
    defer allocator.free(string_to_sign);

    // HMAC-SHA256 signature
    var hmac_out: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&hmac_out, string_to_sign, access_key_secret);
    const signature = std.fmt.bytesToHex(hmac_out, .lower);

    // Authorization header value
    const authorization = try std.fmt.allocPrint(
        allocator,
        "ACS3-HMAC-SHA256 Credential={s},SignedHeaders={s},Signature={s}",
        .{ access_key_id, signed_headers_str, &signature },
    );

    const security_token_owned = if (security_token) |t| try allocator.dupe(u8, t) else null;

    return .{
        .authorization = authorization,
        .x_acs_date = date,
        .x_acs_nonce = nonce,
        .x_acs_content_sha256 = content_sha256,
        .x_acs_security_token = security_token_owned,
    };
}

/// Build sorted, RFC3986-encoded canonical query string.
pub fn buildCanonicalQuery(allocator: std.mem.Allocator, params: []const Param) ![]const u8 {
    const sorted = try allocator.dupe(Param, params);
    defer allocator.free(sorted);
    std.mem.sort(Param, sorted, {}, paramLessThan);

    var parts: std.ArrayList(u8) = .empty;
    defer parts.deinit(allocator);

    for (sorted, 0..) |p, i| {
        if (i != 0) try parts.append(allocator, '&');
        const ek = try rfc3986Encode(allocator, p.key);
        defer allocator.free(ek);
        const ev = try rfc3986Encode(allocator, p.value);
        defer allocator.free(ev);
        try parts.appendSlice(allocator, ek);
        try parts.append(allocator, '=');
        try parts.appendSlice(allocator, ev);
    }

    return parts.toOwnedSlice(allocator);
}

/// Generate an ISO 8601 UTC timestamp: "2024-01-15T10:30:00Z"
pub fn iso8601Timestamp(io: std.Io, allocator: std.mem.Allocator) ![]const u8 {
    const epoch_secs = std.Io.Clock.real.now(io).toSeconds();
    const epoch = std.time.epoch.EpochSeconds{ .secs = @intCast(epoch_secs) };
    const day = epoch.getEpochDay();
    const year_day = day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs = epoch.getDaySeconds();
    return std.fmt.allocPrint(
        allocator,
        "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z",
        .{
            year_day.year,
            month_day.month.numeric(),
            month_day.day_index + 1,
            day_secs.getHoursIntoDay(),
            day_secs.getMinutesIntoHour(),
            day_secs.getSecondsIntoMinute(),
        },
    );
}

/// Generate a random nonce string (16 bytes, hex-encoded → 32 chars).
pub fn randomNonce(io: std.Io, allocator: std.mem.Allocator) ![]const u8 {
    var buf: [16]u8 = undefined;
    try io.randomSecure(&buf);
    const hex = std.fmt.bytesToHex(buf, .lower);
    return try allocator.dupe(u8, &hex);
}

/// RFC3986 percent-encoding. Unreserved: A-Z a-z 0-9 - _ . ~
pub fn rfc3986Encode(allocator: std.mem.Allocator, input: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    for (input) |c| {
        if (isUnreserved(c)) {
            try out.append(allocator, c);
        } else {
            try out.print(allocator, "%{X:0>2}", .{c});
        }
    }

    return out.toOwnedSlice(allocator);
}

fn isUnreserved(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '_', '.', '~' => true,
        else => false,
    };
}

fn paramLessThan(_: void, a: Param, b: Param) bool {
    return std.mem.lessThan(u8, a.key, b.key);
}

fn hexSha256(input: []const u8) [64]u8 {
    var hash: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(input, &hash, .{});
    return std.fmt.bytesToHex(hash, .lower);
}

test "rfc3986Encode basic" {
    const allocator = std.testing.allocator;
    const out = try rfc3986Encode(allocator, "hello world/foo+bar");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("hello%20world%2Ffoo%2Bbar", out);
}

test "rfc3986Encode unreserved passthrough" {
    const allocator = std.testing.allocator;
    const out = try rfc3986Encode(allocator, "abc-123_test.value~");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("abc-123_test.value~", out);
}

test "iso8601Timestamp format" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const ts = try iso8601Timestamp(io, allocator);
    defer allocator.free(ts);
    try std.testing.expect(ts.len == 20);
    try std.testing.expectEqual('T', ts[10]);
    try std.testing.expectEqual('Z', ts[19]);
}

test "randomNonce length" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const nonce = try randomNonce(io, allocator);
    defer allocator.free(nonce);
    try std.testing.expectEqual(@as(usize, 32), nonce.len);
}

test "buildV3Headers produces Authorization header" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const params = [_]Param{
        .{ .key = "DomainName", .value = "example.com" },
    };
    const hdrs = try buildV3Headers(
        io,
        allocator,
        "GET",
        "alidns.aliyuncs.com",
        "DescribeDomainRecords",
        "2015-01-09",
        &params,
        "",
        null,
        "testid",
        "testsecret",
    );
    defer hdrs.deinit(allocator);
    try std.testing.expect(std.mem.startsWith(u8, hdrs.authorization, "ACS3-HMAC-SHA256 "));
    try std.testing.expect(std.mem.indexOf(u8, hdrs.authorization, "Credential=testid") != null);
    try std.testing.expect(std.mem.indexOf(u8, hdrs.authorization, "Signature=") != null);
}

test "buildCanonicalQuery sorts and encodes" {
    const allocator = std.testing.allocator;
    const params = [_]Param{
        .{ .key = "Zoo", .value = "bar" },
        .{ .key = "Action", .value = "Describe Records" },
    };
    const q = try buildCanonicalQuery(allocator, &params);
    defer allocator.free(q);
    try std.testing.expectEqualStrings("Action=Describe%20Records&Zoo=bar", q);
}
