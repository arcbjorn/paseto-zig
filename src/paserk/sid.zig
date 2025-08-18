const std = @import("std");
const mem = std.mem;
const Allocator = std.mem.Allocator;
const testing = std.testing;

const errors = @import("../errors.zig");
const utils = @import("../utils.zig");
const types = @import("types.zig");
const v4 = @import("../v4/mod.zig");

const PaserkHeader = types.PaserkHeader;
const PublicKey = v4.PublicKey;
const SecretKey = v4.SecretKey;

/// Serialize a public key to PASERK format (k4.public.base64url(key))
pub fn serializePublicKey(allocator: Allocator, key: *const PublicKey) ![]u8 {
    const header = PaserkHeader{ .version = 4, .type = .public };
    const header_str = try header.format(allocator);
    defer allocator.free(header_str);
    
    const encoded_key = try utils.base64urlEncode(allocator, key.bytes());
    defer allocator.free(encoded_key);
    
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ header_str, encoded_key });
}

/// Deserialize a public key from PASERK format
pub fn deserializePublicKey(allocator: Allocator, paserk: []const u8) !PublicKey {
    const header = try PaserkHeader.parse(paserk);
    if (header.version != 4 or header.type != .public) {
        return errors.Error.InvalidPaserkType;
    }
    
    const prefix = "k4.public.";
    if (!mem.startsWith(u8, paserk, prefix)) {
        return errors.Error.InvalidPaserkFormat;
    }
    
    const data = paserk[prefix.len..];
    const decoded = try utils.base64urlDecode(allocator, data);
    defer allocator.free(decoded);
    
    return PublicKey.fromBytes(decoded);
}

/// Serialize a secret key to PASERK format (k4.secret.base64url(seed))
pub fn serializeSecretKey(allocator: Allocator, key: *const SecretKey) ![]u8 {
    const header = PaserkHeader{ .version = 4, .type = .secret };
    const header_str = try header.format(allocator);
    defer allocator.free(header_str);
    
    // Use the seed (first 32 bytes) for serialization
    const encoded_key = try utils.base64urlEncode(allocator, key.seed());
    defer allocator.free(encoded_key);
    
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ header_str, encoded_key });
}

/// Deserialize a secret key from PASERK format
pub fn deserializeSecretKey(allocator: Allocator, paserk: []const u8) !SecretKey {
    const header = try PaserkHeader.parse(paserk);
    if (header.version != 4 or header.type != .secret) {
        return errors.Error.InvalidPaserkType;
    }
    
    const prefix = "k4.secret.";
    if (!mem.startsWith(u8, paserk, prefix)) {
        return errors.Error.InvalidPaserkFormat;
    }
    
    const data = paserk[prefix.len..];
    const decoded = try utils.base64urlDecode(allocator, data);
    defer allocator.free(decoded);
    
    return SecretKey.fromSeed(decoded);
}

test "public key serialization" {
    const allocator = testing.allocator;
    
    var key_pair = v4.KeyPair.generate();
    defer key_pair.deinit();
    
    // Serialize
    const serialized = try serializePublicKey(allocator, &key_pair.public);
    defer allocator.free(serialized);
    
    try testing.expect(mem.startsWith(u8, serialized, "k4.public."));
    
    // Deserialize
    const deserialized = try deserializePublicKey(allocator, serialized);
    
    // Verify round trip
    try testing.expectEqualSlices(u8, key_pair.public.bytes(), deserialized.bytes());
}

test "secret key serialization" {
    const allocator = testing.allocator;
    
    var key_pair = v4.KeyPair.generate();
    defer key_pair.deinit();
    
    // Serialize
    const serialized = try serializeSecretKey(allocator, &key_pair.secret);
    defer allocator.free(serialized);
    
    try testing.expect(mem.startsWith(u8, serialized, "k4.secret."));
    
    // Deserialize
    const deserialized = try deserializeSecretKey(allocator, serialized);
    
    // Verify round trip by comparing seeds
    try testing.expectEqualSlices(u8, key_pair.secret.seed(), deserialized.seed());
    
    // Also verify public keys match
    const original_public = key_pair.secret.publicKey();
    const deserialized_public = deserialized.publicKey();
    try testing.expectEqualSlices(u8, original_public.bytes(), deserialized_public.bytes());
}