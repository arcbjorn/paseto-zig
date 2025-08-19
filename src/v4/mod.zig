const std = @import("std");

pub const keys = @import("keys.zig");
pub const local = @import("local.zig");
pub const public = @import("public.zig");
pub const builder = @import("builder.zig");
pub const parser = @import("parser.zig");

// Re-export common types
pub const LocalKey = keys.LocalKey;
pub const SecretKey = keys.SecretKey;
pub const PublicKey = keys.PublicKey;
pub const KeyPair = keys.KeyPair;
pub const Token = keys.Token;

pub const PasetoBuilder = builder.PasetoBuilder;
pub const PasetoParser = parser.PasetoParser;
pub const Validator = parser.Validator;

// Re-export main functions
pub const encryptLocal = local.encrypt;
pub const decryptLocal = local.decrypt;
pub const signPublic = public.sign;
pub const verifyPublic = public.verify;

test {
    _ = keys;
    _ = local;
    _ = public;
    _ = builder;
    _ = parser;
}