const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const json = std.json;

const v4 = @import("../src/v4/mod.zig");
const errors = @import("../src/errors.zig");

test "Parser basic local token parsing" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Create a token
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    _ = try builder.setIssuer("test-issuer");
    _ = try builder.setClaimString("custom", "value");
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    // Parse it
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parseLocal(token, &key, null, null);
    defer claims.deinit(allocator);
    
    try testing.expectEqualStrings("test-issuer", claims.issuer.?);
    try testing.expectEqualStrings("value", claims.custom.get("custom").?.string);
}

test "Parser basic public token parsing" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    // Create a token
    var builder = v4.PublicBuilder.init(allocator);
    defer builder.deinit();
    
    _ = try builder.setSubject("test-subject");
    _ = try builder.setClaimNumber("id", 123);
    
    const token = try builder.build(&keypair.secret);
    defer allocator.free(token);
    
    // Parse it
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parsePublic(token, &keypair.public, null, null);
    defer claims.deinit(allocator);
    
    try testing.expectEqualStrings("test-subject", claims.subject.?);
    try testing.expectEqual(@as(f64, 123), claims.custom.get("id").?.float);
}

test "Parser time validation enabled" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Create expired token
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    const now = std.time.timestamp();
    _ = try builder.setIssuedAt(now - 3600); // 1 hour ago
    _ = try builder.setExpiration(now - 1800); // 30 minutes ago (expired)
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    // Parse with time validation enabled (default)
    var parser = v4.Parser.init(allocator);
    
    try testing.expectError(errors.Error.TokenExpired,
        parser.parseLocal(token, &key, null, null));
}

test "Parser time validation with not before" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Create token valid in the future
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    const now = std.time.timestamp();
    _ = try builder.setNotBefore(now + 3600); // Valid 1 hour from now
    _ = try builder.setExpiration(now + 7200); // Expires 2 hours from now
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    
    try testing.expectError(errors.Error.TokenNotYetValid,
        parser.parseLocal(token, &key, null, null));
}

test "Parser time validation with clock skew" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Create token that just expired
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    const now = std.time.timestamp();
    _ = try builder.setIssuedAt(now - 3600);
    _ = try builder.setExpiration(now - 30); // Expired 30 seconds ago
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    // Should fail with default clock skew (60 seconds)
    var parser1 = v4.Parser.init(allocator);
    try testing.expectError(errors.Error.TokenExpired,
        parser1.parseLocal(token, &key, null, null));
    
    // Should pass with larger clock skew
    var parser2 = v4.Parser.init(allocator);
    _ = parser2.setClockSkew(120); // 2 minutes
    
    var claims = try parser2.parseLocal(token, &key, null, null);
    defer claims.deinit(allocator);
    
    try testing.expect(claims.expiration.? == now - 30);
}

test "Parser with required issuer validation" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Create token with specific issuer
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    _ = try builder.setIssuer("trusted-issuer");
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    // Parse with required issuer - should pass
    var parser1 = v4.Parser.init(allocator);
    parser1.setValidateTime(false);
    _ = parser1.setRequiredIssuer("trusted-issuer");
    
    var claims1 = try parser1.parseLocal(token, &key, null, null);
    defer claims1.deinit(allocator);
    
    try testing.expectEqualStrings("trusted-issuer", claims1.issuer.?);
    
    // Parse with wrong required issuer - should fail
    var parser2 = v4.Parser.init(allocator);
    parser2.setValidateTime(false);
    _ = parser2.setRequiredIssuer("different-issuer");
    
    try testing.expectError(errors.Error.InvalidIssuer,
        parser2.parseLocal(token, &key, null, null));
}

test "Parser with required audience validation" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Create token with specific audience
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    _ = try builder.setAudience("api-server");
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    // Parse with required audience - should pass
    var parser1 = v4.Parser.init(allocator);
    parser1.setValidateTime(false);
    _ = parser1.setRequiredAudience("api-server");
    
    var claims1 = try parser1.parseLocal(token, &key, null, null);
    defer claims1.deinit(allocator);
    
    try testing.expectEqualStrings("api-server", claims1.audience.?);
    
    // Parse with wrong required audience - should fail
    var parser2 = v4.Parser.init(allocator);
    parser2.setValidateTime(false);
    _ = parser2.setRequiredAudience("web-client");
    
    try testing.expectError(errors.Error.InvalidAudience,
        parser2.parseLocal(token, &key, null, null));
}

test "Parser with required subject validation" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    // Create token with specific subject
    var builder = v4.PublicBuilder.init(allocator);
    defer builder.deinit();
    
    _ = try builder.setSubject("user-123");
    
    const token = try builder.build(&keypair.secret);
    defer allocator.free(token);
    
    // Parse with required subject - should pass
    var parser1 = v4.Parser.init(allocator);
    parser1.setValidateTime(false);
    _ = parser1.setRequiredSubject("user-123");
    
    var claims1 = try parser1.parsePublic(token, &keypair.public, null, null);
    defer claims1.deinit(allocator);
    
    try testing.expectEqualStrings("user-123", claims1.subject.?);
    
    // Parse with wrong required subject - should fail
    var parser2 = v4.Parser.init(allocator);
    parser2.setValidateTime(false);
    _ = parser2.setRequiredSubject("user-456");
    
    try testing.expectError(errors.Error.InvalidSubject,
        parser2.parsePublic(token, &keypair.public, null, null));
}

test "Parser JWT ID validation" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Create token with JWT ID
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    _ = try builder.setJwtId("unique-id-123");
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parseLocal(token, &key, null, null);
    defer claims.deinit(allocator);
    
    try testing.expectEqualStrings("unique-id-123", claims.jwt_id.?);
}

test "Parser footer validation" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Create token with footer
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    _ = try builder.setFooter("expected-footer");
    _ = try builder.setClaimString("test", "value");
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    // Parse with matching footer - should pass
    var parser1 = v4.Parser.init(allocator);
    parser1.setValidateTime(false);
    
    var claims1 = try parser1.parseLocal(token, &key, "expected-footer", null);
    defer claims1.deinit(allocator);
    
    try testing.expectEqualStrings("value", claims1.custom.get("test").?.string);
    
    // Parse with wrong footer - should fail
    try testing.expectError(errors.Error.InvalidFooter,
        parser1.parseLocal(token, &key, "wrong-footer", null));
    
    // Parse expecting no footer - should fail
    try testing.expectError(errors.Error.InvalidFooter,
        parser1.parseLocal(token, &key, null, null));
}

test "Parser implicit assertion validation" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Create token with implicit assertion
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    _ = try builder.setClaimString("test", "value");
    
    const token = try builder.buildWithImplicit(&key, "secret-context");
    defer allocator.free(token);
    
    // Parse with matching implicit - should pass
    var parser1 = v4.Parser.init(allocator);
    parser1.setValidateTime(false);
    
    var claims1 = try parser1.parseLocal(token, &key, null, "secret-context");
    defer claims1.deinit(allocator);
    
    try testing.expectEqualStrings("value", claims1.custom.get("test").?.string);
    
    // Parse with wrong implicit - should fail
    try testing.expectError(errors.Error.InvalidSignature,
        parser1.parseLocal(token, &key, null, "wrong-context"));
    
    // Parse expecting no implicit - should fail
    try testing.expectError(errors.Error.InvalidSignature,
        parser1.parseLocal(token, &key, null, null));
}

test "Parser invalid token format detection" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    // Wrong version
    try testing.expectError(errors.Error.InvalidHeader,
        parser.parseLocal("v3.local.dGVzdA", &key, null, null));
    
    // Wrong purpose
    try testing.expectError(errors.Error.InvalidHeader,
        parser.parseLocal("v4.public.dGVzdA", &key, null, null));
    
    // Missing parts
    try testing.expectError(errors.Error.InvalidHeader,
        parser.parseLocal("v4", &key, null, null));
    
    try testing.expectError(errors.Error.InvalidHeader,
        parser.parseLocal("v4.local", &key, null, null));
    
    // Invalid base64url
    try testing.expectError(error.InvalidCharacter,
        parser.parseLocal("v4.local.invalid+base64", &key, null, null));
    
    // Empty payload
    try testing.expectError(error.InvalidCharacter,
        parser.parseLocal("v4.local.", &key, null, null));
}

test "Parser malformed JSON payload" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Create a token with manually crafted malformed JSON
    const malformed_json = "{\"test\": \"value\", invalid}";
    const token = try v4.encryptLocal(allocator, malformed_json, &key, null, null);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    try testing.expectError(json.ParseError.InvalidLiteral,
        parser.parseLocal(token, &key, null, null));
}

test "Parser with custom claim validation" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Create token with custom claims
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    _ = try builder.setClaimString("role", "admin");
    _ = try builder.setClaimNumber("permission_level", 9);
    _ = try builder.setClaimBool("verified", true);
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parseLocal(token, &key, null, null);
    defer claims.deinit(allocator);
    
    // Validate custom claims
    const role = claims.custom.get("role").?;
    const permission = claims.custom.get("permission_level").?;
    const verified = claims.custom.get("verified").?;
    
    try testing.expectEqualStrings("admin", role.string);
    try testing.expectEqual(@as(f64, 9), permission.float);
    try testing.expectEqual(true, verified.bool);
}

test "Parser large token handling" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Create token with large payload
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    const large_data = "X" ** 10000;
    _ = try builder.setClaimString("large_data", large_data);
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parseLocal(token, &key, null, null);
    defer claims.deinit(allocator);
    
    const retrieved_data = claims.custom.get("large_data").?;
    try testing.expectEqualStrings(large_data, retrieved_data.string);
}

test "Parser binary data in claims" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Create token with binary data encoded as base64
    const binary_data = [_]u8{ 0x00, 0xFF, 0xAA, 0x55, 0xDE, 0xAD, 0xBE, 0xEF };
    const base64_data = try std.base64.standard.Encoder.encode(allocator, &binary_data);
    defer allocator.free(base64_data);
    
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    _ = try builder.setClaimString("binary", base64_data);
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parseLocal(token, &key, null, null);
    defer claims.deinit(allocator);
    
    const retrieved_b64 = claims.custom.get("binary").?;
    try testing.expectEqualStrings(base64_data, retrieved_b64.string);
}

test "Parser concurrent parsing safety" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Create a token
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    _ = try builder.setClaimString("test", "concurrent");
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    // Parse with multiple parser instances (simulating concurrent use)
    var parser1 = v4.Parser.init(allocator);
    var parser2 = v4.Parser.init(allocator);
    
    parser1.setValidateTime(false);
    parser2.setValidateTime(false);
    
    var claims1 = try parser1.parseLocal(token, &key, null, null);
    defer claims1.deinit(allocator);
    
    var claims2 = try parser2.parseLocal(token, &key, null, null);
    defer claims2.deinit(allocator);
    
    // Both should succeed and return same data
    try testing.expectEqualStrings("concurrent", claims1.custom.get("test").?.string);
    try testing.expectEqualStrings("concurrent", claims2.custom.get("test").?.string);
}

test "Parser configuration persistence" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Create tokens with different requirements
    var builder1 = v4.LocalBuilder.init(allocator);
    defer builder1.deinit();
    _ = try builder1.setIssuer("issuer1");
    const token1 = try builder1.build(&key);
    defer allocator.free(token1);
    
    var builder2 = v4.LocalBuilder.init(allocator);
    defer builder2.deinit();
    _ = try builder2.setIssuer("issuer2");
    const token2 = try builder2.build(&key);
    defer allocator.free(token2);
    
    // Configure parser
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    _ = parser.setRequiredIssuer("issuer1");
    
    // First token should pass
    var claims1 = try parser.parseLocal(token1, &key, null, null);
    defer claims1.deinit(allocator);
    
    // Second token should fail (config should persist)
    try testing.expectError(errors.Error.InvalidIssuer,
        parser.parseLocal(token2, &key, null, null));
}

test "Parser edge case timestamps" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Test edge case timestamps
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    _ = try builder.setIssuedAt(0); // Unix epoch
    _ = try builder.setNotBefore(2147483647); // Max 32-bit timestamp
    _ = try builder.setExpiration(9223372036854775807); // Max 64-bit timestamp
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parseLocal(token, &key, null, null);
    defer claims.deinit(allocator);
    
    try testing.expectEqual(@as(i64, 0), claims.issued_at.?);
    try testing.expectEqual(@as(i64, 2147483647), claims.not_before.?);
    try testing.expectEqual(@as(i64, 9223372036854775807), claims.expiration.?);
}