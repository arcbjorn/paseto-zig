const std = @import("std");
const testing = std.testing;
const mem = std.mem;

const paseto = @import("paseto");

test "v4.local end-to-end" {
    const allocator = testing.allocator;
    
    // Generate a key
    var key = paseto.LocalKey.generate();
    defer key.deinit();
    
    // Create a token using the builder
    var builder = paseto.createLocalBuilder(allocator);
    defer builder.deinit();
    
    try builder.withDefaults();
    try builder.setIssuer("test-issuer");
    try builder.setSubject("test-user");
    try builder.setFooter("test-footer");
    
    const token = try builder.buildLocal(&key);
    defer allocator.free(token);
    
    try testing.expect(mem.startsWith(u8, token, "v4.local."));
    try testing.expect(mem.endsWith(u8, token, "test-footer"));
    
    // Parse the token
    var parser = paseto.createParser(allocator);
    parser.setValidateTime(false); // Skip time validation for test
    
    var claims = try parser.parseLocal(token, &key, "test-footer", null);
    defer claims.deinit(allocator);
    
    try testing.expectEqualStrings("test-issuer", claims.issuer.?);
    try testing.expectEqualStrings("test-user", claims.subject.?);
    try testing.expect(claims.issued_at != null);
    try testing.expect(claims.expiration != null);
}

test "v4.public end-to-end" {
    const allocator = testing.allocator;
    
    // Generate a key pair
    var key_pair = paseto.KeyPair.generate();
    defer key_pair.deinit();
    
    // Create a token using the builder
    var builder = paseto.createPublicBuilder(allocator);
    defer builder.deinit();
    
    try builder.setIssuer("api-server");
    try builder.setSubject("user-123");
    try builder.setAudience("client-app");
    try builder.setClaimNumber("user_id", 12345);
    try builder.setClaimBool("admin", true);
    
    const token = try builder.buildPublic(&key_pair.secret);
    defer allocator.free(token);
    
    try testing.expect(mem.startsWith(u8, token, "v4.public."));
    
    // Verify the token
    var parser = paseto.createParser(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parsePublic(token, &key_pair.public, null, null);
    defer claims.deinit(allocator);
    
    try testing.expectEqualStrings("api-server", claims.issuer.?);
    try testing.expectEqualStrings("user-123", claims.subject.?);
    try testing.expectEqualStrings("client-app", claims.audience.?);
    
    // Check custom claims
    const user_id = claims.custom.get("user_id").?;
    try testing.expectEqual(@as(f64, 12345), user_id.float);
    
    const admin = claims.custom.get("admin").?;
    try testing.expectEqual(true, admin.bool);
}

test "token verification with wrong key should fail" {
    const allocator = testing.allocator;
    
    var key1 = paseto.LocalKey.generate();
    defer key1.deinit();
    
    var key2 = paseto.LocalKey.generate();
    defer key2.deinit();
    
    var builder = paseto.createLocalBuilder(allocator);
    defer builder.deinit();
    
    try builder.setIssuer("test");
    const token = try builder.buildLocal(&key1);
    defer allocator.free(token);
    
    var parser = paseto.createParser(allocator);
    try testing.expectError(paseto.Error.InvalidSignature,
        parser.parseLocal(token, &key2, null, null));
}

test "implicit assertion validation" {
    const allocator = testing.allocator;
    
    var key = paseto.LocalKey.generate();
    defer key.deinit();
    
    var builder = paseto.createLocalBuilder(allocator);
    defer builder.deinit();
    
    try builder.setIssuer("test");
    try builder.setImplicit("secret-context");
    
    const token = try builder.buildLocal(&key);
    defer allocator.free(token);
    
    var parser = paseto.createParser(allocator);
    parser.setValidateTime(false);
    
    // Should succeed with correct implicit
    var claims = try parser.parseLocal(token, &key, null, "secret-context");
    claims.deinit(allocator);
    
    // Should fail with wrong implicit
    try testing.expectError(paseto.Error.InvalidSignature,
        parser.parseLocal(token, &key, null, "wrong-context"));
    
    // Should fail with no implicit
    try testing.expectError(paseto.Error.InvalidSignature,
        parser.parseLocal(token, &key, null, null));
}