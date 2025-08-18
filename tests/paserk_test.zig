const std = @import("std");
const testing = std.testing;
const mem = std.mem;

const paseto = @import("paseto");

test "PASERK local key serialization" {
    const allocator = testing.allocator;
    
    var key = paseto.LocalKey.generate();
    defer key.deinit();
    
    // Serialize key
    const serialized = try paseto.paserk.serializeLocalKey(allocator, &key);
    defer allocator.free(serialized);
    
    try testing.expect(mem.startsWith(u8, serialized, "k4.local."));
    
    // Deserialize key
    const deserialized = try paseto.paserk.deserializeLocalKey(allocator, serialized);
    
    // Verify round trip
    try testing.expectEqualSlices(u8, key.bytes(), deserialized.bytes());
}

test "PASERK public/secret key serialization" {
    const allocator = testing.allocator;
    
    var key_pair = paseto.KeyPair.generate();
    defer key_pair.deinit();
    
    // Serialize public key
    const public_serialized = try paseto.paserk.serializePublicKey(allocator, &key_pair.public);
    defer allocator.free(public_serialized);
    
    try testing.expect(mem.startsWith(u8, public_serialized, "k4.public."));
    
    // Serialize secret key
    const secret_serialized = try paseto.paserk.serializeSecretKey(allocator, &key_pair.secret);
    defer allocator.free(secret_serialized);
    
    try testing.expect(mem.startsWith(u8, secret_serialized, "k4.secret."));
    
    // Deserialize and verify
    const public_deserialized = try paseto.paserk.deserializePublicKey(allocator, public_serialized);
    const secret_deserialized = try paseto.paserk.deserializeSecretKey(allocator, secret_serialized);
    
    try testing.expectEqualSlices(u8, key_pair.public.bytes(), public_deserialized.bytes());
    try testing.expectEqualSlices(u8, key_pair.secret.seed(), secret_deserialized.seed());
}

test "PASERK key identifiers" {
    const allocator = testing.allocator;
    
    var local_key = paseto.LocalKey.generate();
    defer local_key.deinit();
    
    var key_pair = paseto.KeyPair.generate();
    defer key_pair.deinit();
    
    // Generate identifiers
    const lid = paseto.LocalKeyId.fromLocalKey(local_key.bytes());
    const sid = paseto.SecretKeyId.fromSecretKey(key_pair.secret.bytes());
    
    // Serialize identifiers
    const lid_serialized = try lid.serialize(allocator);
    defer allocator.free(lid_serialized);
    
    const sid_serialized = try sid.serialize(allocator);
    defer allocator.free(sid_serialized);
    
    try testing.expect(mem.startsWith(u8, lid_serialized, "k4.lid."));
    try testing.expect(mem.startsWith(u8, sid_serialized, "k4.sid."));
    
    // Deserialize and verify
    const lid_deserialized = try paseto.LocalKeyId.deserialize(allocator, lid_serialized);
    const sid_deserialized = try paseto.SecretKeyId.deserialize(allocator, sid_serialized);
    
    try testing.expectEqualSlices(u8, lid.bytes(), lid_deserialized.bytes());
    try testing.expectEqualSlices(u8, sid.bytes(), sid_deserialized.bytes());
    
    // Identifiers should be deterministic
    const lid2 = paseto.LocalKeyId.fromLocalKey(local_key.bytes());
    try testing.expectEqualSlices(u8, lid.bytes(), lid2.bytes());
}