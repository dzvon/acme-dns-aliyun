/// Alibaba Cloud DNS (AliDNS) API client.
///
/// Uses the V3 signing (ACS3-HMAC-SHA256) via HTTP headers.
///
/// Reference: https://www.alibabacloud.com/help/en/dns/api-overview
const std = @import("std");
const server = @import("server.zig");
const sig = @import("signature.zig");
const config = @import("config.zig");

pub const Action = enum { present, cleanup };

/// create (present) or delete (cleanup) the _acme-challenge TXT record for the given request.
pub fn perform(
    io: std.Io,
    allocator: std.mem.Allocator,
    action: Action,
    fqdn: []const u8,
    zone: []const u8,
    key: []const u8,
    creds: server.ResolvedCreds,
    cfg: config.Config,
) !void {
    switch (action) {
        .present => try addTxtRecord(io, allocator, fqdn, zone, key, creds, cfg),
        .cleanup => try deleteTxtRecord(io, allocator, fqdn, zone, key, creds, cfg),
    }
}

/// Extract the RR sub-label from a resolved FQDN and a zone.
/// E.g.: fqdn="_acme-challenge.example.com." zone="example.com."  → "_acme-challenge"
/// E.g.: fqdn="_acme-challenge.sub.example.com." zone="example.com." → "_acme-challenge.sub"
fn extractRR(allocator: std.mem.Allocator, fqdn: []const u8, zone: []const u8) ![]const u8 {
    const f = std.mem.trimEnd(u8, fqdn, ".");
    const z = std.mem.trimEnd(u8, zone, ".");

    if (!std.mem.endsWith(u8, f, z)) {
        std.log.err("FQDN '{s}' does not end with zone '{s}'", .{ f, z });
        return error.FqdnZoneMismatch;
    }

    const rr_len = f.len - z.len;
    if (rr_len == 0) return try allocator.dupe(u8, "@");
    const rr = f[0 .. rr_len - 1];
    return try allocator.dupe(u8, rr);
}

/// The AliDNS hostname extracted from the endpoint URL.
/// e.g. "https://alidns.aliyuncs.com" → "alidns.aliyuncs.com"
fn hostFromEndpoint(endpoint: []const u8) []const u8 {
    if (std.mem.startsWith(u8, endpoint, "https://")) return endpoint["https://".len..];
    if (std.mem.startsWith(u8, endpoint, "http://")) return endpoint["http://".len..];
    return endpoint;
}

const dns_api_version = "2015-01-09";

/// Find existing TXT records matching the given RR and value (for cleanup).
/// Returns a slice of owned RecordId strings; caller must free each entry and the slice.
fn describeRecords(
    io: std.Io,
    allocator: std.mem.Allocator,
    domain_name: []const u8,
    rr: []const u8,
    value: []const u8,
    creds: server.ResolvedCreds,
    cfg: config.Config,
) ![][]const u8 {
    var ids = std.ArrayList([]const u8).empty;
    errdefer {
        for (ids.items) |id| allocator.free(id);
        ids.deinit(allocator);
    }

    const host = hostFromEndpoint(cfg.dns_endpoint);
    var page_num: i64 = 1;
    while (true) : (page_num += 1) {
        var params = std.ArrayList(sig.Param).empty;
        defer params.deinit(allocator);

        try params.append(allocator, .{ .key = "DomainName", .value = domain_name });
        try params.append(allocator, .{ .key = "RRKeyWord", .value = rr });
        try params.append(allocator, .{ .key = "Type", .value = "TXT" });
        try params.append(allocator, .{ .key = "PageSize", .value = "20" });

        const body = try callApi(io, allocator, "GET", host, "DescribeDomainRecords",
            dns_api_version, cfg.dns_endpoint, params.items, creds);
        defer allocator.free(body);

        std.log.debug("DescribeDomainRecords response: {s}", .{body});

        const parsed = try std.json.parseFromSlice(
            DescribeResponse,
            allocator,
            body,
            .{ .ignore_unknown_fields = true },
        );
        defer parsed.deinit();

        const records = parsed.value.DomainRecords.Record;
        if (records.len == 0) break;

        for (records) |rec| {
            if (std.mem.eql(u8, rec.Value, value))
                try ids.append(allocator, try allocator.dupe(u8, rec.RecordId));
        }

        if (page_num * parsed.value.PageSize >= parsed.value.TotalCount) break;
    }
    return ids.toOwnedSlice(allocator);
}

fn addTxtRecord(
    io: std.Io,
    allocator: std.mem.Allocator,
    fqdn: []const u8,
    zone: []const u8,
    key: []const u8,
    creds: server.ResolvedCreds,
    cfg: config.Config,
) !void {
    const domain_name = std.mem.trimEnd(u8, zone, ".");
    const rr = try extractRR(allocator, fqdn, zone);
    defer allocator.free(rr);

    std.log.info("AddDomainRecord domain={s} rr={s}", .{ domain_name, rr });

    var params = std.ArrayList(sig.Param).empty;
    defer params.deinit(allocator);

    try params.append(allocator, .{ .key = "DomainName", .value = domain_name });
    try params.append(allocator, .{ .key = "RR", .value = rr });
    try params.append(allocator, .{ .key = "Type", .value = "TXT" });
    try params.append(allocator, .{ .key = "Value", .value = key });
    try params.append(allocator, .{ .key = "TTL", .value = "600" });

    const host = hostFromEndpoint(cfg.dns_endpoint);
    std.log.info("AddDomainRecord httpGet starting", .{});
    const body = try callApi(io, allocator, "GET", host, "AddDomainRecord",
        dns_api_version, cfg.dns_endpoint, params.items, creds);
    defer allocator.free(body);
    std.log.info("AddDomainRecord httpGet done: {s}", .{body});
    try checkApiError(allocator, body);
}

fn deleteTxtRecord(
    io: std.Io,
    allocator: std.mem.Allocator,
    fqdn: []const u8,
    zone: []const u8,
    key: []const u8,
    creds: server.ResolvedCreds,
    cfg: config.Config,
) !void {
    const domain_name = std.mem.trimEnd(u8, zone, ".");
    const rr = try extractRR(allocator, fqdn, zone);
    defer allocator.free(rr);

    std.log.info("DeleteDomainRecord domain={s} rr={s}", .{ domain_name, rr });

    const record_ids = try describeRecords(io, allocator, domain_name, rr, key, creds, cfg);
    defer {
        for (record_ids) |id| allocator.free(id);
        allocator.free(record_ids);
    }

    if (record_ids.len == 0) {
        std.log.warn("no matching TXT records to delete", .{});
        return;
    }

    const host = hostFromEndpoint(cfg.dns_endpoint);
    for (record_ids) |record_id| {
        var params = std.ArrayList(sig.Param).empty;
        defer params.deinit(allocator);

        try params.append(allocator, .{ .key = "RecordId", .value = record_id });

        const body = try callApi(io, allocator, "GET", host, "DeleteDomainRecord",
            dns_api_version, cfg.dns_endpoint, params.items, creds);
        defer allocator.free(body);

        std.log.debug("DeleteDomainRecord RecordId={s} response: {s}", .{ record_id, body });
        try checkApiError(allocator, body);
    }
}

/// Sign and execute a V3 API call, returning the response body.
/// Caller owns the returned slice.
fn callApi(
    io: std.Io,
    allocator: std.mem.Allocator,
    method: []const u8,
    host: []const u8,
    action: []const u8,
    version: []const u8,
    endpoint: []const u8,
    query_params: []const sig.Param,
    creds: server.ResolvedCreds,
) ![]const u8 {
    const hdrs = try sig.buildV3Headers(
        io,
        allocator,
        method,
        host,
        action,
        version,
        query_params,
        "", // no body for GET requests
        creds.security_token,
        creds.access_key_id,
        creds.access_key_secret,
    );
    defer hdrs.deinit(allocator);

    const canonical_query = try sig.buildCanonicalQuery(allocator, query_params);
    defer allocator.free(canonical_query);

    const url = if (canonical_query.len > 0)
        try std.fmt.allocPrint(allocator, "{s}/?{s}", .{ endpoint, canonical_query })
    else
        try std.fmt.allocPrint(allocator, "{s}/", .{endpoint});
    defer allocator.free(url);

    return httpGetV3(io, allocator, url, action, version, hdrs);
}

/// Plain unauthenticated GET — used by rrsa.zig for anonymous STS calls.
pub fn httpGet(io: std.Io, allocator: std.mem.Allocator, url: []const u8) ![]const u8 {
    var client = std.http.Client{ .allocator = allocator, .io = io };
    defer client.deinit();

    var response_list: std.ArrayListUnmanaged(u8) = .empty;
    var response_writer = std.Io.Writer.Allocating.fromArrayList(allocator, &response_list);
    defer response_writer.deinit();

    const result = try client.fetch(.{
        .method = .GET,
        .location = .{ .url = url },
        .response_writer = &response_writer.writer,
    });

    var body = response_writer.toArrayList();
    errdefer body.deinit(allocator);

    if (result.status != .ok) {
        std.log.err("HTTP GET {}: {s}", .{ result.status, body.items });
        return error.HttpError;
    }

    return body.toOwnedSlice(allocator);
}

pub fn httpGetV3(
    io: std.Io,
    allocator: std.mem.Allocator,
    url: []const u8,
    action: []const u8,
    version: []const u8,
    hdrs: sig.V3Headers,
) ![]const u8 {
    var client = std.http.Client{
        .allocator = allocator,
        .io = io,
    };
    defer client.deinit();

    var response_list: std.ArrayListUnmanaged(u8) = .empty;
    var response_writer = std.Io.Writer.Allocating.fromArrayList(allocator, &response_list);
    defer response_writer.deinit();

    var extra_headers_buf: [7]std.http.Header = undefined;
    extra_headers_buf[0] = .{ .name = "x-acs-action", .value = action };
    extra_headers_buf[1] = .{ .name = "x-acs-version", .value = version };
    extra_headers_buf[2] = .{ .name = "x-acs-date", .value = hdrs.x_acs_date };
    extra_headers_buf[3] = .{ .name = "x-acs-signature-nonce", .value = hdrs.x_acs_nonce };
    extra_headers_buf[4] = .{ .name = "x-acs-content-sha256", .value = hdrs.x_acs_content_sha256 };
    extra_headers_buf[5] = .{ .name = "Authorization", .value = hdrs.authorization };

    // When using STS temporary credentials, the SignedHeaders list includes
    // x-acs-security-token — it MUST be sent in the request.
    var extra_headers_len: usize = 6;
    if (hdrs.x_acs_security_token) |token| {
        extra_headers_buf[6] = .{ .name = "x-acs-security-token", .value = token };
        extra_headers_len = 7;
    }

    const extra_headers = extra_headers_buf[0..extra_headers_len];

    const result = try client.fetch(.{
        .method = .GET,
        .location = .{ .url = url },
.extra_headers = extra_headers,
        .response_writer = &response_writer.writer,
    });

    var body = response_writer.toArrayList();
    errdefer body.deinit(allocator);

    if (result.status != .ok) {
        std.log.err("AliDNS API HTTP {}: {s}", .{ result.status, body.items });
        return error.AliDnsApiError;
    }

    return body.toOwnedSlice(allocator);
}

// JSON types for AliDNS responses

const ApiErrorResponse = struct {
    Code: ?[]const u8 = null,
    Message: ?[]const u8 = null,
};

const DnsRecord = struct {
    RecordId: []const u8 = "",
    Value: []const u8 = "",
    RR: []const u8 = "",
    Type: []const u8 = "",
};

const DescribeResponse = struct {
    TotalCount: i64 = 0,
    PageSize: i64 = 20,
    PageNumber: i64 = 1,
    DomainRecords: struct {
        Record: []DnsRecord = &.{},
    } = .{},
};

fn checkApiError(
    allocator: std.mem.Allocator,
    body: []const u8,
) !void {
    const parsed = std.json.parseFromSlice(
        ApiErrorResponse,
        allocator,
        body,
        .{ .ignore_unknown_fields = true },
    ) catch return;
    defer parsed.deinit();

    if (parsed.value.Code) |code| {
        std.log.err("AliDNS API error code={s} message={s}", .{
            code,
            parsed.value.Message orelse "(none)",
        });
        return error.AliDnsApiError;
    }
}
