const std = @import("std");
const testing = std.testing;
const mem = std.mem;

const v4 = @import("../src/v4/mod.zig");
const paserk = @import("../src/paserk/mod.zig");
const errors = @import("../src/errors.zig");
const utils = @import("../src/utils.zig");

test "error types comprehensive coverage" {
    // Verify all error types are accessible
    _ = errors.Error.InvalidKeyLength;
    _ = errors.Error.InvalidHeader;
    _ = errors.Error.InvalidToken;
    _ = errors.Error.InvalidFooter;
    _ = errors.Error.InvalidSignature;
    _ = errors.Error.TokenExpired;
    _ = errors.Error.TokenNotYetValid;
    _ = errors.Error.InvalidIssuer;
    _ = errors.Error.InvalidAudience;
    _ = errors.Error.InvalidSubject;
    _ = errors.Error.InvalidTimeFormat;
    _ = errors.Error.InvalidPaserkType;
    _ = errors.Error.CryptoError;
    _ = errors.Error.OutOfMemory;
}

test "key length validation errors" {
    // LocalKey invalid lengths
    try testing.expectError(errors.Error.InvalidKeyLength, v4.LocalKey.fromBytes(&[_]u8{}));
    try testing.expectError(errors.Error.InvalidKeyLength, v4.LocalKey.fromBytes(&([_]u8{0} ** 16)));
    try testing.expectError(errors.Error.InvalidKeyLength, v4.LocalKey.fromBytes(&([_]u8{0} ** 64)));
    
    // SecretKey invalid lengths
    try testing.expectError(errors.Error.InvalidKeyLength, v4.SecretKey.fromSeed(&[_]u8{}));
    try testing.expectError(errors.Error.InvalidKeyLength, v4.SecretKey.fromSeed(&([_]u8{0} ** 16)));
    try testing.expectError(errors.Error.InvalidKeyLength, v4.SecretKey.fromSeed(&([_]u8{0} ** 64)));
    try testing.expectError(errors.Error.InvalidKeyLength, v4.SecretKey.fromBytes(&([_]u8{0} ** 32)));
    
    // PublicKey invalid lengths
    try testing.expectError(errors.Error.InvalidKeyLength, v4.PublicKey.fromBytes(&[_]u8{}));
    try testing.expectError(errors.Error.InvalidKeyLength, v4.PublicKey.fromBytes(&([_]u8{0} ** 16)));
    try testing.expectError(errors.Error.InvalidKeyLength, v4.PublicKey.fromBytes(&([_]u8{0} ** 64)));
    
    // KeyPair invalid seed length
    try testing.expectError(errors.Error.InvalidKeyLength, v4.KeyPair.fromSeed(&([_]u8{0} ** 16)));
}

test "token header validation errors" {
    const allocator = testing.allocator;
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    // Invalid version
    try testing.expectError(errors.Error.InvalidHeader,
        parser.parseLocal("v3.local.dGVzdA", &key, null, null));
    
    try testing.expectError(errors.Error.InvalidHeader,
        parser.parseLocal("v5.local.dGVzdA", &key, null, null));
    
    // Invalid purpose
    try testing.expectError(errors.Error.InvalidHeader,
        parser.parseLocal("v4.public.dGVzdA", &key, null, null));
    
    try testing.expectError(errors.Error.InvalidHeader,
        parser.parseLocal("v4.invalid.dGVzdA", &key, null, null));
    
    // Malformed headers
    try testing.expectError(errors.Error.InvalidHeader,
        parser.parseLocal("v4", &key, null, null));
    
    try testing.expectError(errors.Error.InvalidHeader,
        parser.parseLocal("v4.local", &key, null, null));
    
    try testing.expectError(errors.Error.InvalidHeader,
        parser.parseLocal("invalid.format.here", &key, null, null));
    
    try testing.expectError(errors.Error.InvalidHeader,
        parser.parseLocal("", &key, null, null));
}

test "token format validation errors" {
    const allocator = testing.allocator;
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    // Empty payload
    try testing.expectError(error.InvalidCharacter,
        parser.parseLocal("v4.local.", &key, null, null));
    
    // Invalid base64url characters
    try testing.expectError(error.InvalidCharacter,
        parser.parseLocal("v4.local.invalid+base64/padding=", &key, null, null));
    
    // Too short token data
    try testing.expectError(errors.Error.InvalidToken,
        parser.parseLocal("v4.local.dGVz", &key, null, null));
}

test "cryptographic validation errors" {
    const allocator = testing.allocator;
    
    var key1 = v4.LocalKey.generate();
    defer key1.deinit();
    
    var key2 = v4.LocalKey.generate();
    defer key2.deinit();
    
    // Create valid token with key1
    const token = try v4.encryptLocal(allocator, "test", &key1, null, null);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    // Try to decrypt with wrong key - should fail with InvalidSignature
    try testing.expectError(errors.Error.InvalidSignature,
        parser.parseLocal(token, &key2, null, null));
}

test "footer validation errors" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Create token with footer
    const token = try v4.encryptLocal(allocator, "test", &key, "expected-footer", null);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    // Wrong footer
    try testing.expectError(errors.Error.InvalidFooter,
        parser.parseLocal(token, &key, "wrong-footer", null));
    
    // Missing footer when expected
    try testing.expectError(errors.Error.InvalidFooter,
        parser.parseLocal(token, &key, null, null));
    
    // Create token without footer
    const token_no_footer = try v4.encryptLocal(allocator, "test", &key, null, null);
    defer allocator.free(token_no_footer);
    
    // Providing footer when none expected
    try testing.expectError(errors.Error.InvalidFooter,
        parser.parseLocal(token_no_footer, &key, "unexpected", null));
}

test "time validation errors" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    const now = std.time.timestamp();
    
    // Create expired token
    var builder1 = v4.LocalBuilder.init(allocator);
    defer builder1.deinit();
    
    _ = try builder1.setExpiration(now - 3600); // Expired 1 hour ago
    
    const expired_token = try builder1.build(&key);
    defer allocator.free(expired_token);
    
    var parser1 = v4.Parser.init(allocator);
    // Time validation enabled by default
    
    try testing.expectError(errors.Error.TokenExpired,
        parser1.parseLocal(expired_token, &key, null, null));
    
    // Create token valid in future
    var builder2 = v4.LocalBuilder.init(allocator);
    defer builder2.deinit();
    
    _ = try builder2.setNotBefore(now + 3600); // Valid 1 hour from now
    
    const future_token = try builder2.build(&key);
    defer allocator.free(future_token);
    
    var parser2 = v4.Parser.init(allocator);
    
    try testing.expectError(errors.Error.TokenNotYetValid,
        parser2.parseLocal(future_token, &key, null, null));
}

test "issuer validation errors" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Create token with specific issuer
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    _ = try builder.setIssuer("actual-issuer");
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    _ = parser.setRequiredIssuer("expected-issuer");
    
    try testing.expectError(errors.Error.InvalidIssuer,
        parser.parseLocal(token, &key, null, null));
}

test "audience validation errors" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    _ = try builder.setAudience("actual-audience");
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    _ = parser.setRequiredAudience("expected-audience");
    
    try testing.expectError(errors.Error.InvalidAudience,
        parser.parseLocal(token, &key, null, null));
}

test "subject validation errors" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    var builder = v4.PublicBuilder.init(allocator);
    defer builder.deinit();
    
    _ = try builder.setSubject("actual-subject");
    
    const token = try builder.build(&keypair.secret);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    _ = parser.setRequiredSubject("expected-subject");
    
    try testing.expectError(errors.Error.InvalidSubject,
        parser.parsePublic(token, &keypair.public, null, null));
}

test "PASERK type validation errors" {
    // Invalid PASERK type strings
    try testing.expectError(errors.Error.InvalidPaserkType, paserk.typeFromString("k3.local."));
    try testing.expectError(errors.Error.InvalidPaserkType, paserk.typeFromString("k4.invalid."));
    try testing.expectError(errors.Error.InvalidPaserkType, paserk.typeFromString("invalid"));
    try testing.expectError(errors.Error.InvalidPaserkType, paserk.typeFromString(""));
    try testing.expectError(errors.Error.InvalidPaserkType, paserk.typeFromString("k4"));
    try testing.expectError(errors.Error.InvalidPaserkType, paserk.typeFromString("v4.local."));
    
    // Invalid deserialization
    try testing.expectError(errors.Error.InvalidPaserkType,
        paserk.deserializeLocalKey("k4.public.dGVzdA"));
    
    try testing.expectError(errors.Error.InvalidPaserkType,
        paserk.deserializePublicKey("k4.secret.dGVzdA"));
    
    try testing.expectError(errors.Error.InvalidPaserkType,
        paserk.deserializeSecretKey("k4.local.dGVzdA"));
}

test "PASERK key length validation errors" {
    // Too short key data in PASERK
    try testing.expectError(errors.Error.InvalidKeyLength,
        paserk.deserializeLocalKey("k4.local.dGVzdA")); // "test" is only 4 bytes
    
    try testing.expectError(errors.Error.InvalidKeyLength,
        paserk.deserializePublicKey("k4.public.dGVzdA"));
    
    try testing.expectError(errors.Error.InvalidKeyLength,
        paserk.deserializeSecretKey("k4.secret.dGVzdA"));
    
    // ID with wrong length
    try testing.expectError(errors.Error.InvalidKeyLength,
        paserk.LocalKeyId.deserialize("k4.lid.dGVzdA"));
}

test "base64url decoding errors" {
    const allocator = testing.allocator;
    
    // Invalid base64url characters
    try testing.expectError(error.InvalidCharacter,
        utils.base64urlDecode(allocator, "invalid+base64/"));
    
    try testing.expectError(error.InvalidCharacter,
        utils.base64urlDecode(allocator, "padding="));
    
    try testing.expectError(error.InvalidCharacter,
        utils.base64urlDecode(allocator, "new\nline"));
    
    try testing.expectError(error.InvalidCharacter,
        utils.base64urlDecode(allocator, "space "));
}

test "timestamp format validation errors" {
    // Invalid RFC3339 formats
    try testing.expectError(utils.errors.Error.InvalidTimeFormat,
        utils.rfc3339ToTimestamp(""));
    
    try testing.expectError(utils.errors.Error.InvalidTimeFormat,
        utils.rfc3339ToTimestamp("2024-01-01"));
    
    try testing.expectError(utils.errors.Error.InvalidTimeFormat,
        utils.rfc3339ToTimestamp("2024/01/01T01:02:03Z"));
    
    try testing.expectError(utils.errors.Error.InvalidTimeFormat,
        utils.rfc3339ToTimestamp("2024-01-01 01:02:03Z"));
    
    try testing.expectError(utils.errors.Error.InvalidTimeFormat,
        utils.rfc3339ToTimestamp("2024-01-01T25:02:03Z")); // Invalid hour
    
    try testing.expectError(utils.errors.Error.InvalidTimeFormat,
        utils.rfc3339ToTimestamp("2024-01-01T01:60:03Z")); // Invalid minute
    
    try testing.expectError(utils.errors.Error.InvalidTimeFormat,
        utils.rfc3339ToTimestamp("2024-01-01T01:02:60Z")); // Invalid second
}

test "implicit assertion validation errors" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Create token with implicit assertion
    const token = try v4.encryptLocal(allocator, "test", &key, null, "secret-context");
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    // Wrong implicit assertion
    try testing.expectError(errors.Error.InvalidSignature,
        parser.parseLocal(token, &key, null, "wrong-context"));
    
    // Missing implicit assertion
    try testing.expectError(errors.Error.InvalidSignature,
        parser.parseLocal(token, &key, null, null));
}

test "public key signature validation errors" {
    const allocator = testing.allocator;
    
    var keypair1 = v4.KeyPair.generate();
    defer keypair1.deinit();
    
    var keypair2 = v4.KeyPair.generate();
    defer keypair2.deinit();
    
    // Sign with keypair1
    const token = try v4.signPublic(allocator, "test", &keypair1.secret, null, null);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    // Try to verify with wrong public key
    try testing.expectError(errors.Error.InvalidSignature,
        parser.parsePublic(token, &keypair2.public, null, null));
}

test "wrapped key decryption errors" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    var wrapping_key1 = v4.LocalKey.generate();
    defer wrapping_key1.deinit();
    
    var wrapping_key2 = v4.LocalKey.generate();
    defer wrapping_key2.deinit();
    
    // Wrap with key1
    const wrapped = try paserk.wrapLocalKeyWithLocalKey(allocator, &local_key, &wrapping_key1);
    defer allocator.free(wrapped);
    
    // Try to unwrap with key2
    try testing.expectError(errors.Error.InvalidSignature,
        paserk.unwrapLocalKeyWithLocalKey(allocator, wrapped, &wrapping_key2));
}

test "password-based key decryption errors" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    const correct_password = "correct";
    const wrong_password = "wrong";
    const options = paserk.PasswordOptions{ .iterations = 1000 };
    
    const wrapped = try paserk.password.wrapLocalKeyWithPassword(
        allocator, 
        &local_key, 
        correct_password, 
        options
    );
    defer allocator.free(wrapped);
    
    // Wrong password
    try testing.expectError(errors.Error.InvalidSignature,
        paserk.password.unwrapLocalKeyWithPassword(allocator, wrapped, wrong_password));
}

test "malformed JSON payload errors" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Create token with malformed JSON
    const malformed_json = "{invalid json}";
    const token = try v4.encryptLocal(allocator, malformed_json, &key, null, null);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    // Should fail to parse JSON
    const result = parser.parseLocal(token, &key, null, null);
    try testing.expect(std.meta.isError(result));
}

test "error message consistency" {
    const allocator = testing.allocator;
    
    // Test that similar operations produce consistent error types
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    // All wrong header formats should produce InvalidHeader
    const bad_headers = [_][]const u8{
        "v3.local.dGVzdA",
        "v5.local.dGVzdA", 
        "v4.public.dGVzdA",
        "v4.invalid.dGVzdA",
    };
    
    for (bad_headers) |header| {
        try testing.expectError(errors.Error.InvalidHeader,
            parser.parseLocal(header, &key, null, null));
    }
}

test "error propagation through call stack" {
    const allocator = testing.allocator;
    
    // Test that errors propagate correctly through the call stack
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    var builder = v4.PublicBuilder.init(allocator);
    defer builder.deinit();
    
    _ = try builder.setIssuer("test-issuer");
    
    const token = try builder.build(&keypair.secret);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    _ = parser.setRequiredIssuer("different-issuer");
    
    // Error should propagate from deep validation logic
    const result = parser.parsePublic(token, &keypair.public, null, null);
    try testing.expectError(errors.Error.InvalidIssuer, result);
}

test "resource cleanup on errors" {
    const allocator = testing.allocator;
    
    // Verify that resources are properly cleaned up even when errors occur
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    // This should fail but not leak memory
    const result = parser.parseLocal("v4.local.invalid", &key, null, null);
    try testing.expect(std.meta.isError(result));
    
    // Parser should still be usable after error
    const valid_token = try v4.encryptLocal(allocator, "test", &key, null, null);
    defer allocator.free(valid_token);
    
    var claims = try parser.parseLocal(valid_token, &key, null, null);
    defer claims.deinit(allocator);
    
    // Should succeed
    try testing.expect(claims.custom.count() == 0);
}