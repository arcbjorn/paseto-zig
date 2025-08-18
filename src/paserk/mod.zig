const std = @import("std");

pub const types = @import("types.zig");
pub const lid = @import("lid.zig");
pub const sid = @import("sid.zig");
pub const wrap = @import("wrap.zig");
pub const seal = @import("seal.zig");
pub const password = @import("password.zig");

// Re-export common types
pub const PaserkType = types.PaserkType;
pub const PaserkHeader = types.PaserkHeader;
pub const LocalKeyId = types.LocalKeyId;
pub const SecretKeyId = types.SecretKeyId;

// Re-export serialization functions
pub const serializeLocalKey = lid.serializeLocalKey;
pub const deserializeLocalKey = lid.deserializeLocalKey;
pub const serializePublicKey = sid.serializePublicKey;
pub const deserializePublicKey = sid.deserializePublicKey;
pub const serializeSecretKey = sid.serializeSecretKey;
pub const deserializeSecretKey = sid.deserializeSecretKey;

test {
    _ = types;
    _ = lid;
    _ = sid;
    _ = wrap;
    _ = seal;
    _ = password;
}