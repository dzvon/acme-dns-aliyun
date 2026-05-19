const std = @import("std");

pub const Creds = struct {
    access_key_id: [:0]const u8,
    access_key_secret: [:0]const u8,

    pub fn fromEnv() !Creds {
        return .{
            .access_key_id = std.mem.sliceTo(
                std.c.getenv("ALIDNS_ACCESS_KEY_ID") orelse return error.MissingAccessKeyId,
                0,
            ),
            .access_key_secret = std.mem.sliceTo(
                std.c.getenv("ALIDNS_ACCESS_KEY_SECRET") orelse return error.MissingAccessKeySecret,
                0,
            ),
        };
    }
};
