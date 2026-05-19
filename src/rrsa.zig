/// RRSA (RAM Roles for Service Accounts) credential provider.
///
/// Flow:
///   1. Read the OIDC token from the file at ALIBABA_CLOUD_OIDC_TOKEN_FILE.
///   2. POST https://sts.<region>.aliyuncs.com/ with form-urlencoded body:
///        Action=AssumeRoleWithOIDC&Format=JSON
///        &Version=2015-04-01&Timestamp=...&SignatureNonce=...
///        &RoleArn=...&OIDCProviderArn=...&OIDCToken=...
///        &RoleSessionName=acme-dns-aliyun&DurationSeconds=3600
///      This call is ANONYMOUS – no AccessKeyId or Signature required.
///      STS validates the OIDC token itself.
///   3. Return the temporary AccessKeyId, AccessKeySecret, SecurityToken.
///
/// Reference:
///   https://www.alibabacloud.com/help/en/ram/developer-reference/api-sts-2015-04-01-assumerolewithoidc
const std = @import("std");
const server = @import("server.zig");
const config = @import("config.zig");
const sig = @import("signature.zig");

const sts_api_version = "2015-04-01";

/// Exchange an OIDC service-account token for temporary STS credentials.
pub fn assumeRoleWithOidc(
    io: std.Io,
    allocator: std.mem.Allocator,
    rrsa: config.RrsaCredentials,
    sts_endpoint: []const u8,
) !server.ResolvedCreds {
    // 1. Read the projected OIDC token from the file.
    const token = try readOidcToken(io, allocator, rrsa.oidc_token_file);
    defer allocator.free(token);

    std.log.info("RRSA: assuming role {s}", .{rrsa.role_arn});

    // 2. Build form-urlencoded request body (RPC/V2 style).
    // The official Python SDK uses RpcRequest with add_query_param,
    // so parameters are sent as application/x-www-form-urlencoded.
    // Reference: https://www.alibabacloud.com/help/en/ram/developer-reference/api-sts-2015-04-01-assumerolewithoidc
    const date = try sig.iso8601Timestamp(io, allocator);
    defer allocator.free(date);

    const nonce = try sig.randomNonce(io, allocator);
    defer allocator.free(nonce);

    const encoded_token = try sig.rfc3986Encode(allocator, token);
    defer allocator.free(encoded_token);
    const encoded_role_arn = try sig.rfc3986Encode(allocator, rrsa.role_arn);
    defer allocator.free(encoded_role_arn);
    const encoded_provider_arn = try sig.rfc3986Encode(allocator, rrsa.oidc_provider_arn);
    defer allocator.free(encoded_provider_arn);

    const body = try std.fmt.allocPrint(
        allocator,
        "Action={s}&Format={s}&Version={s}&Timestamp={s}&SignatureNonce={s}&RoleArn={s}&OIDCProviderArn={s}&OIDCToken={s}&RoleSessionName={s}&DurationSeconds={d}",
        .{
            "AssumeRoleWithOIDC",
            "JSON",
            sts_api_version,
            date,
            nonce,
            encoded_role_arn,
            encoded_provider_arn,
            encoded_token,
            "acme-dns-aliyun",
            @as(u32, 3600),
        },
    );
    defer allocator.free(body);

    // 3. POST to the STS endpoint.
    const url = try std.fmt.allocPrint(allocator, "{s}/", .{sts_endpoint});
    defer allocator.free(url);

    const response = try httpPostForm(io, allocator, url, body);
    defer allocator.free(response);

    std.log.debug("AssumeRoleWithOIDC response: {s}", .{response});

    // 4. Parse credentials from the response JSON.
    return parseCredentials(allocator, response);
}

fn readOidcToken(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
) ![]const u8 {
    const content = try std.Io.Dir.readFileAlloc(
        std.Io.Dir.cwd(),
        io,
        path,
        allocator,
        .unlimited,
    );

    const trimmed = std.mem.trimEnd(u8, content, "\n\r");
    if (trimmed.len < content.len) {
        return try allocator.realloc(content, trimmed.len);
    }
    return content;
}

fn httpPostForm(
    io: std.Io,
    allocator: std.mem.Allocator,
    url: []const u8,
    body: []const u8,
) ![]const u8 {
    var client = std.http.Client{ .allocator = allocator, .io = io };
    defer client.deinit();

    var response_list: std.ArrayListUnmanaged(u8) = .empty;
    var response_writer = std.Io.Writer.Allocating.fromArrayList(allocator, &response_list);
    defer response_writer.deinit();

    const extra_headers = [_]std.http.Header{
        .{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" },
    };

    const result = try client.fetch(.{
        .method = .POST,
        .location = .{ .url = url },
        .extra_headers = &extra_headers,
        .payload = body,
        .response_writer = &response_writer.writer,
    });

    var resp_body = response_writer.toArrayList();
    errdefer resp_body.deinit(allocator);

    if (result.status != .ok) {
        std.log.err("STS API HTTP {}: {s}", .{ result.status, resp_body.items });
        return error.StsHttpError;
    }

    return resp_body.toOwnedSlice(allocator);
}

// JSON types for STS response
//
// {
//   "RequestId": "...",
//   "AssumedRoleUser": { ... },
//   "Credentials": {
//     "AccessKeyId":     "STS.xxx",
//     "AccessKeySecret": "yyy",
//     "SecurityToken":   "zzz",
//     "Expiration":      "2024-01-01T11:00:00Z"
//   }
// }

const StsCredentials = struct {
    AccessKeyId: []const u8 = "",
    AccessKeySecret: []const u8 = "",
    SecurityToken: []const u8 = "",
    Expiration: []const u8 = "",
};

const StsResponse = struct {
    Credentials: StsCredentials = .{},
    Code: ?[]const u8 = null,
    Message: ?[]const u8 = null,
};

fn parseCredentials(
    allocator: std.mem.Allocator,
    body: []const u8,
) !server.ResolvedCreds {
    const parsed = try std.json.parseFromSlice(
        StsResponse,
        allocator,
        body,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    if (parsed.value.Code) |code| {
        std.log.err("STS error code={s} message={s}", .{
            code,
            parsed.value.Message orelse "(none)",
        });
        return error.StsError;
    }

    const creds = parsed.value.Credentials;
    if (creds.AccessKeyId.len == 0) {
        std.log.err("STS response missing AccessKeyId", .{});
        return error.StsEmptyCredentials;
    }

    std.log.info("RRSA: obtained STS credentials, expires={s}", .{creds.Expiration});

    return .{
        .access_key_id = try allocator.dupe(u8, creds.AccessKeyId),
        .access_key_secret = try allocator.dupe(u8, creds.AccessKeySecret),
        .security_token = if (creds.SecurityToken.len > 0) try allocator.dupe(u8, creds.SecurityToken) else null,
        .allocator = allocator,
    };
}
