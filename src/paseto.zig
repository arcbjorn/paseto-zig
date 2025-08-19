const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;

pub const errors = @import("errors.zig");
pub const v4 = @import("v4/mod.zig");
pub const paserk = @import("paserk/mod.zig");
pub const utils = @import("utils.zig");

pub const Error = errors.Error;

// Re-export common types and functions
pub const Token = v4.Token;
pub const KeyPair = v4.KeyPair;
pub const LocalKey = v4.LocalKey;
pub const PasetoBuilder = v4.PasetoBuilder;
pub const PasetoParser = v4.PasetoParser;
pub const Validator = v4.Validator;

// Re-export PASERK types
pub const PaserkType = paserk.PaserkType;
pub const LocalKeyId = paserk.LocalKeyId;
pub const SecretKeyId = paserk.SecretKeyId;

pub fn createLocalBuilder(allocator: std.mem.Allocator) v4.PasetoBuilder {
    return v4.PasetoBuilder.initLocal(allocator);
}

pub fn createPublicBuilder(allocator: std.mem.Allocator) v4.PasetoBuilder {
    return v4.PasetoBuilder.initPublic(allocator);
}

pub fn createParser(allocator: std.mem.Allocator) v4.PasetoParser {
    return v4.PasetoParser.init(allocator);
}

test {
    _ = errors;
    _ = v4;
    _ = paserk;
    _ = utils;
}