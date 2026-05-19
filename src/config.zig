/// Configuration for the webhook server.
/// Credentials can come from environment variables or from the JSON body
/// of each request (cert-manager passes solver-specific config in the body).
const std = @import("std");

pub const CredentialMode = enum {
    access_key, // use static Access Key and Secret
    rrsa, // use RAM Role for Service Accounts (ECS)
};

pub const AccessKeyCredentials = struct {
    access_key_id: []const u8,
    access_key_secret: []const u8,
};

pub const RrsaCredentials = struct {
    role_arn: []const u8,
    oidc_provider_arn: []const u8,
    oidc_token_file: []const u8,

    /// Optional: override STS endpoint region
    region: []const u8,
};

pub const Credentials = union(CredentialMode) {
    access_key: AccessKeyCredentials,
    rrsa: RrsaCredentials,
};

pub const Config = struct {
    credentials: Credentials,
    region: []const u8,
    group_name: []const u8,
    solver_name: []const u8,
    /// Aliyun DNS API endpoint (default: https://alidns.aliyuncs.com)
    dns_endpoint: []const u8,
    /// STS endpoint for RRSA token exchange
    sts_endpoint: []const u8,

    cert_file_path: []const u8,
    key_file_path: []const u8,

    allocator: std.mem.Allocator,

    /// Build config from environment variables.
    pub fn fromEnviron(allocator: std.mem.Allocator, environ: *const std.process.Environ) !Config {
        const region = try allocator.dupe(
            u8,
            environ.getPosix("ALIBABA_CLOUD_REGION") orelse "cn-hangzhou",
        );
        errdefer allocator.free(region);

        const group_name = try allocator.dupe(
            u8,
            environ.getPosix("WEBHOOK_GROUP_NAME") orelse "default",
        );
        errdefer allocator.free(group_name);

        const solver_name = try allocator.dupe(
            u8,
            environ.getPosix("WEBHOOK_SOLVER_NAME") orelse "alidns",
        );
        errdefer allocator.free(solver_name);

        const dns_endpoint = try allocator.dupe(
            u8,
            environ.getPosix("ALIDNS_ENDPOINT") orelse "https://alidns.aliyuncs.com",
        );
        errdefer allocator.free(dns_endpoint);

        // STS endpoint: regional or global
        const sts_endpoint = blk: {
            if (environ.getPosix("ALICLOUD_STS_ENDPOINT")) |ep| {
                break :blk try allocator.dupe(u8, ep);
            }
            // Build regional STS endpoint: https://sts.<region>.aliyuncs.com
            const ep = try std.fmt.allocPrint(
                allocator,
                "https://sts.{s}.aliyuncs.com",
                .{region},
            );
            break :blk ep;
        };
        errdefer allocator.free(sts_endpoint);

        // Detect credential mode
        const role_arn = environ.getPosix("ALIBABA_CLOUD_ROLE_ARN");
        const oidc_provider_arn = environ.getPosix("ALIBABA_CLOUD_OIDC_PROVIDER_ARN");
        const oidc_token_file = environ.getPosix("ALIBABA_CLOUD_OIDC_TOKEN_FILE");

        const credentials: Credentials = if (role_arn != null and
            oidc_provider_arn != null and
            oidc_token_file != null)
        blk: {
            // RRSA mode
            break :blk .{ .rrsa = .{
                .role_arn = try allocator.dupe(u8, role_arn.?),
                .oidc_provider_arn = try allocator.dupe(u8, oidc_provider_arn.?),
                .oidc_token_file = try allocator.dupe(u8, oidc_token_file.?),
                .region = region,
            } };
        } else blk: {
            // Static Access Key mode
            const ak = environ.getPosix("ALIBABA_CLOUD_ACCESS_KEY_ID") orelse {
                std.log.err("neither RRSA env vars (ALIBABA_CLOUD_ROLE_ARN, " ++
                    "ALIBABA_CLOUD_OIDC_PROVIDER_ARN, ALIBABA_CLOUD_OIDC_TOKEN_FILE) " ++
                    "nor ALIBABA_CLOUD_ACCESS_KEY_ID are set", .{});
                return error.MissingCredentials;
            };
            const sk = environ.getPosix("ALIBABA_CLOUD_ACCESS_KEY_SECRET") orelse {
                std.log.err("ALIBABA_CLOUD_ACCESS_KEY_SECRET is not set", .{});
                return error.MissingCredentials;
            };
            break :blk .{ .access_key = .{
                .access_key_id = try allocator.dupe(u8, ak),
                .access_key_secret = try allocator.dupe(u8, sk),
            } };
        };

        const cert_file_path = try allocator.dupe(
            u8,
            environ.getPosix("WEBHOOK_TLS_CERT_FILE") orelse "/etc/tls.crt",
        );
        const key_file_path = try allocator.dupe(
            u8,
            environ.getPosix("WEBHOOK_TLS_KEY_FILE") orelse "/etc/tls.key",
        );

        return .{
            .credentials = credentials,
            .region = region,
            .group_name = group_name,
            .solver_name = solver_name,
            .dns_endpoint = dns_endpoint,
            .sts_endpoint = sts_endpoint,
            .cert_file_path = cert_file_path,
            .key_file_path = key_file_path,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: Config, allocator: std.mem.Allocator) void {
        allocator.free(self.region);
        allocator.free(self.group_name);
        allocator.free(self.solver_name);
        allocator.free(self.dns_endpoint);
        allocator.free(self.sts_endpoint);

        switch (self.credentials) {
            .access_key => |ak| {
                allocator.free(ak.access_key_id);
                allocator.free(ak.access_key_secret);
            },
            .rrsa => |rrsa| {
                allocator.free(rrsa.role_arn);
                allocator.free(rrsa.oidc_provider_arn);
                allocator.free(rrsa.oidc_token_file);
                // .region points to the same allocation as Config.region,
                // already freed above.
            },
        }
    }
};
