const std = @import("std");
const testing = std.testing;
const mem = std.mem;

const v4 = @import("../src/v4/mod.zig");
const paserk = @import("../src/paserk/mod.zig");
const errors = @import("../src/errors.zig");

test "serialize local key basic" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    const serialized = try paserk.serializeLocalKey(allocator, &local_key);
    defer allocator.free(serialized);
    
    try testing.expect(mem.startsWith(u8, serialized, "k4.local."));
    
    // Deserialize and verify
    const deserialized = try paserk.deserializeLocalKey(serialized);
    try testing.expectEqualSlices(u8, local_key.bytes(), deserialized.bytes());
}

test "serialize local key deterministic" {
    const allocator = testing.allocator;
    
    const key_bytes = [_]u8{0x42} ** 32;
    const local_key = try v4.LocalKey.fromBytes(&key_bytes);
    
    const serialized1 = try paserk.serializeLocalKey(allocator, &local_key);
    defer allocator.free(serialized1);
    
    const serialized2 = try paserk.serializeLocalKey(allocator, &local_key);
    defer allocator.free(serialized2);
    
    try testing.expectEqualStrings(serialized1, serialized2);
}

test "deserialize local key invalid format" {
    // Wrong version
    try testing.expectError(errors.Error.InvalidPaserkType,
        paserk.deserializeLocalKey("k3.local.dGVzdA"));
    
    // Wrong type
    try testing.expectError(errors.Error.InvalidPaserkType,
        paserk.deserializeLocalKey("k4.public.dGVzdA"));
    
    // Invalid base64url
    try testing.expectError(error.InvalidCharacter,
        paserk.deserializeLocalKey("k4.local.invalid+base64"));
    
    // Wrong length
    try testing.expectError(errors.Error.InvalidKeyLength,
        paserk.deserializeLocalKey("k4.local.dGVzdA")); // Too short
}

test "serialize public key basic" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const serialized = try paserk.serializePublicKey(allocator, &keypair.public);
    defer allocator.free(serialized);
    
    try testing.expect(mem.startsWith(u8, serialized, "k4.public."));
    
    const deserialized = try paserk.deserializePublicKey(serialized);
    try testing.expectEqualSlices(u8, keypair.public.bytes(), deserialized.bytes());
}

test "serialize public key from secret key" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const public_from_public = try paserk.serializePublicKey(allocator, &keypair.public);
    defer allocator.free(public_from_public);
    
    const public_from_secret = try paserk.serializePublicKeyFromSecret(allocator, &keypair.secret);
    defer allocator.free(public_from_secret);
    
    // Should be identical
    try testing.expectEqualStrings(public_from_public, public_from_secret);
}

test "deserialize public key invalid format" {
    try testing.expectError(errors.Error.InvalidPaserkType,
        paserk.deserializePublicKey("k4.secret.dGVzdA"));
    
    try testing.expectError(errors.Error.InvalidPaserkType,
        paserk.deserializePublicKey("k3.public.dGVzdA"));
    
    try testing.expectError(errors.Error.InvalidKeyLength,
        paserk.deserializePublicKey("k4.public.dGVzdA"));
}

test "serialize secret key basic" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const serialized = try paserk.serializeSecretKey(allocator, &keypair.secret);
    defer allocator.free(serialized);
    
    try testing.expect(mem.startsWith(u8, serialized, "k4.secret."));
    
    const deserialized = try paserk.deserializeSecretKey(serialized);
    try testing.expectEqualSlices(u8, keypair.secret.bytes(), deserialized.bytes());
}

test "serialize secret key from seed" {
    const allocator = testing.allocator;
    
    const seed = [_]u8{0x33} ** 32;
    const secret_key = try v4.SecretKey.fromSeed(&seed);
    
    const serialized1 = try paserk.serializeSecretKey(allocator, &secret_key);
    defer allocator.free(serialized1);
    
    const serialized2 = try paserk.serializeSecretKey(allocator, &secret_key);
    defer allocator.free(serialized2);
    
    try testing.expectEqualStrings(serialized1, serialized2);
}

test "deserialize secret key invalid format" {
    try testing.expectError(errors.Error.InvalidPaserkType,
        paserk.deserializeSecretKey("k4.local.dGVzdA"));
    
    try testing.expectError(errors.Error.InvalidKeyLength,
        paserk.deserializeSecretKey("k4.secret.dGVzdA"));
}

test "key serialization round trip comprehensive" {
    const allocator = testing.allocator;
    
    // Test with multiple different keys
    for (0..5) |i| {
        var seed: [32]u8 = undefined;
        std.mem.writeInt(u64, seed[0..8], @as(u64, @intCast(i)), .little);
        @memset(seed[8..], @intCast(i % 256));
        
        // Local key
        const local_key = try v4.LocalKey.fromBytes(&seed);
        const local_ser = try paserk.serializeLocalKey(allocator, &local_key);
        defer allocator.free(local_ser);
        const local_deser = try paserk.deserializeLocalKey(local_ser);
        try testing.expectEqualSlices(u8, local_key.bytes(), local_deser.bytes());
        
        // Secret key
        const secret_key = try v4.SecretKey.fromSeed(&seed);
        const secret_ser = try paserk.serializeSecretKey(allocator, &secret_key);
        defer allocator.free(secret_ser);
        const secret_deser = try paserk.deserializeSecretKey(secret_ser);
        try testing.expectEqualSlices(u8, secret_key.bytes(), secret_deser.bytes());
        
        // Public key
        const public_key = secret_key.publicKey();
        const public_ser = try paserk.serializePublicKey(allocator, &public_key);
        defer allocator.free(public_ser);
        const public_deser = try paserk.deserializePublicKey(public_ser);
        try testing.expectEqualSlices(u8, public_key.bytes(), public_deser.bytes());
    }
}

test "serialized key format validation" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const local_ser = try paserk.serializeLocalKey(allocator, &local_key);
    defer allocator.free(local_ser);
    const public_ser = try paserk.serializePublicKey(allocator, &keypair.public);
    defer allocator.free(public_ser);
    const secret_ser = try paserk.serializeSecretKey(allocator, &keypair.secret);
    defer allocator.free(secret_ser);
    
    // Verify correct headers
    try testing.expect(mem.startsWith(u8, local_ser, "k4.local."));
    try testing.expect(mem.startsWith(u8, public_ser, "k4.public."));
    try testing.expect(mem.startsWith(u8, secret_ser, "k4.secret."));
    
    // Verify no padding characters
    try testing.expect(mem.indexOf(u8, local_ser, "=") == null);
    try testing.expect(mem.indexOf(u8, public_ser, "=") == null);
    try testing.expect(mem.indexOf(u8, secret_ser, "=") == null);
    
    // Verify no regular base64 characters
    try testing.expect(mem.indexOf(u8, local_ser, "+") == null);
    try testing.expect(mem.indexOf(u8, local_ser, "/") == null);
    try testing.expect(mem.indexOf(u8, public_ser, "+") == null);
    try testing.expect(mem.indexOf(u8, public_ser, "/") == null);
    try testing.expect(mem.indexOf(u8, secret_ser, "+") == null);
    try testing.expect(mem.indexOf(u8, secret_ser, "/") == null);
}

test "serialized key length validation" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const local_ser = try paserk.serializeLocalKey(allocator, &local_key);
    defer allocator.free(local_ser);
    const public_ser = try paserk.serializePublicKey(allocator, &keypair.public);
    defer allocator.free(public_ser);
    const secret_ser = try paserk.serializeSecretKey(allocator, &keypair.secret);
    defer allocator.free(secret_ser);
    
    // Local: k4.local. (9) + base64url(32 bytes) = 9 + 43 = 52
    try testing.expectEqual(@as(usize, 52), local_ser.len);
    
    // Public: k4.public. (10) + base64url(32 bytes) = 10 + 43 = 53
    try testing.expectEqual(@as(usize, 53), public_ser.len);
    
    // Secret: k4.secret. (10) + base64url(64 bytes) = 10 + 86 = 96
    try testing.expectEqual(@as(usize, 96), secret_ser.len);
}

test "key serialization edge cases" {
    const allocator = testing.allocator;
    
    // All-zero keys
    const zero_local = try v4.LocalKey.fromBytes(&([_]u8{0} ** 32));
    const zero_local_ser = try paserk.serializeLocalKey(allocator, &zero_local);
    defer allocator.free(zero_local_ser);
    const zero_local_deser = try paserk.deserializeLocalKey(zero_local_ser);
    try testing.expectEqualSlices(u8, zero_local.bytes(), zero_local_deser.bytes());
    
    // All-max keys
    const max_local = try v4.LocalKey.fromBytes(&([_]u8{0xFF} ** 32));
    const max_local_ser = try paserk.serializeLocalKey(allocator, &max_local);
    defer allocator.free(max_local_ser);
    const max_local_deser = try paserk.deserializeLocalKey(max_local_ser);
    try testing.expectEqualSlices(u8, max_local.bytes(), max_local_deser.bytes());
    
    // Pattern keys
    var pattern_bytes: [32]u8 = undefined;
    for (pattern_bytes, 0..) |*byte, i| {
        byte.* = @intCast(i % 256);
    }
    const pattern_local = try v4.LocalKey.fromBytes(&pattern_bytes);
    const pattern_local_ser = try paserk.serializeLocalKey(allocator, &pattern_local);
    defer allocator.free(pattern_local_ser);
    const pattern_local_deser = try paserk.deserializeLocalKey(pattern_local_ser);
    try testing.expectEqualSlices(u8, pattern_local.bytes(), pattern_local_deser.bytes());
}

test "cross-validation between keys and IDs" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    // Serialize keys
    const local_ser = try paserk.serializeLocalKey(allocator, &local_key);
    defer allocator.free(local_ser);
    const public_ser = try paserk.serializePublicKey(allocator, &keypair.public);
    defer allocator.free(public_ser);
    const secret_ser = try paserk.serializeSecretKey(allocator, &keypair.secret);
    defer allocator.free(secret_ser);
    
    // Generate IDs
    const lid = paserk.LocalKeyId.fromLocalKey(local_key.bytes());
    const pid = paserk.PublicKeyId.fromPublicKey(keypair.public.bytes());
    const sid = paserk.SecretKeyId.fromSecretKey(keypair.secret.bytes());
    
    // Serialize IDs
    const lid_ser = try lid.serialize(allocator);
    defer allocator.free(lid_ser);
    const pid_ser = try pid.serialize(allocator);
    defer allocator.free(pid_ser);
    const sid_ser = try sid.serialize(allocator);
    defer allocator.free(sid_ser);
    
    // Keys and IDs should have different formats
    try testing.expect(!mem.eql(u8, local_ser, lid_ser));
    try testing.expect(!mem.eql(u8, public_ser, pid_ser));
    try testing.expect(!mem.eql(u8, secret_ser, sid_ser));
    
    // But IDs should be derivable from deserialized keys
    const local_deser = try paserk.deserializeLocalKey(local_ser);
    const public_deser = try paserk.deserializePublicKey(public_ser);
    const secret_deser = try paserk.deserializeSecretKey(secret_ser);
    
    const lid_from_deser = paserk.LocalKeyId.fromLocalKey(local_deser.bytes());
    const pid_from_deser = paserk.PublicKeyId.fromPublicKey(public_deser.bytes());
    const sid_from_deser = paserk.SecretKeyId.fromSecretKey(secret_deser.bytes());
    
    try testing.expectEqualSlices(u8, lid.bytes(), lid_from_deser.bytes());
    try testing.expectEqualSlices(u8, pid.bytes(), pid_from_deser.bytes());
    try testing.expectEqualSlices(u8, sid.bytes(), sid_from_deser.bytes());
}

test "serialization with malformed input" {
    // Test various malformed PASERK strings
    const malformed_inputs = [_][]const u8{
        "",
        "k4",
        "k4.",
        "k4.local",
        "k4.local.",
        "k4.local..", // Double dots
        "K4.LOCAL.ABC", // Wrong case
        "k4.local.ABC DEF", // Spaces
        "k4.local.ABC\n", // Newlines
        "k4.local.ABC\x00", // Null bytes
    };
    
    for (malformed_inputs) |input| {
        const result = paserk.deserializeLocalKey(input);
        try testing.expect(std.meta.isError(result));
    }
}

test "serialize performance consistency" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    // Multiple serializations should be fast and consistent
    var results: [10][]u8 = undefined;
    for (results, 0..) |*result, i| {
        result.* = try paserk.serializeLocalKey(allocator, &local_key);
        
        // All should be identical
        if (i > 0) {
            try testing.expectEqualStrings(results[0], result.*);
        }
    }
    
    // Cleanup
    for (results) |result| {
        allocator.free(result);
    }
}

test "base64url encoding consistency in PASERK" {
    const allocator = testing.allocator;
    
    // Create a key with known bytes that would use base64url-specific characters
    var key_bytes: [32]u8 = undefined;
    @memset(key_bytes[0..8], 0xFF); // Will likely generate - and _ in base64url
    @memset(key_bytes[8..16], 0x3E); // > in ASCII
    @memset(key_bytes[16..24], 0x3F); // ? in ASCII
    @memset(key_bytes[24..], 0);
    
    const local_key = try v4.LocalKey.fromBytes(&key_bytes);
    const serialized = try paserk.serializeLocalKey(allocator, &local_key);
    defer allocator.free(serialized);
    
    // Should not contain regular base64 characters
    try testing.expect(mem.indexOf(u8, serialized, "+") == null);
    try testing.expect(mem.indexOf(u8, serialized, "/") == null);
    try testing.expect(mem.indexOf(u8, serialized, "=") == null);
    
    // Should deserialize correctly
    const deserialized = try paserk.deserializeLocalKey(serialized);
    try testing.expectEqualSlices(u8, key_bytes, deserialized.bytes());
}