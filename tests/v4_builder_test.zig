const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const json = std.json;

const v4 = @import("../src/v4/mod.zig");
const errors = @import("../src/errors.zig");

test "LocalBuilder basic creation" {
    const allocator = testing.allocator;
    
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    _ = try builder.setClaimString("test", "value");
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    try testing.expect(mem.startsWith(u8, token, "v4.local."));
}

test "LocalBuilder with all standard claims for validation" {
    const allocator = testing.allocator;
    
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    _ = try builder.setIssuer("test-issuer");
    _ = try builder.setSubject("test-subject");
    _ = try builder.setAudience("test-audience");
    _ = try builder.setJwtId("unique-jwt-id");
    _ = try builder.withDefaults();
    
    var key = LocalKey.generate();
    defer key.deinit();
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    try testing.expect(mem.startsWith(u8, token, "v4.local."));
    
    // Verify token can be parsed and contains expected claims
    var parser = v4.PasetoParser.init(allocator);
    _ = parser.setValidateTime(false);
    
    var claims = try parser.parseLocal(token, &key, null, null);
    defer claims.deinit(allocator);
    
    try testing.expectEqualStrings("test-issuer", claims.issuer.?);
    try testing.expectEqualStrings("test-subject", claims.subject.?);
    try testing.expectEqualStrings("test-audience", claims.audience.?);
    try testing.expectEqualStrings("unique-jwt-id", claims.jwt_id.?);
    try testing.expect(claims.expiration != null);
    try testing.expect(claims.issued_at != null);
}

test "LocalBuilder with defaults" {
    const allocator = testing.allocator;
    
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    _ = try builder.withDefaults();
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    // Parse back to verify defaults are set
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false); // Skip time validation for test
    
    var claims = try parser.parseLocal(token, &key, null, null);
    defer claims.deinit(allocator);
    
    // Should have issued_at and expiration set
    try testing.expect(claims.issued_at != null);
    try testing.expect(claims.expiration != null);
}

test "LocalBuilder standard claims" {
    const allocator = testing.allocator;
    
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    _ = try builder.setIssuer("test-issuer");
    _ = try builder.setSubject("test-subject");
    _ = try builder.setAudience("test-audience");
    _ = try builder.setJwtId("test-jti");
    _ = try builder.setNotBefore(1000);
    _ = try builder.setIssuedAt(2000);
    _ = try builder.setExpiration(3000);
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parseLocal(token, &key, null, null);
    defer claims.deinit(allocator);
    
    try testing.expectEqualStrings("test-issuer", claims.issuer.?);
    try testing.expectEqualStrings("test-subject", claims.subject.?);
    try testing.expectEqualStrings("test-audience", claims.audience.?);
    try testing.expectEqualStrings("test-jti", claims.jwt_id.?);
    try testing.expectEqual(@as(i64, 1000), claims.not_before.?);
    try testing.expectEqual(@as(i64, 2000), claims.issued_at.?);
    try testing.expectEqual(@as(i64, 3000), claims.expiration.?);
}

test "LocalBuilder custom claims" {
    const allocator = testing.allocator;
    
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    _ = try builder.setClaimString("string_claim", "test_value");
    _ = try builder.setClaimNumber("number_claim", 42.5);
    _ = try builder.setClaimBool("bool_claim", true);
    _ = try builder.setClaimArray("array_claim", &[_]json.Value{
        json.Value{ .string = "item1" },
        json.Value{ .integer = 123 },
    });
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parseLocal(token, &key, null, null);
    defer claims.deinit(allocator);
    
    const string_val = claims.custom.get("string_claim").?;
    const number_val = claims.custom.get("number_claim").?;
    const bool_val = claims.custom.get("bool_claim").?;
    const array_val = claims.custom.get("array_claim").?;
    
    try testing.expectEqualStrings("test_value", string_val.string);
    try testing.expectEqual(@as(f64, 42.5), number_val.float);
    try testing.expectEqual(true, bool_val.bool);
    try testing.expectEqual(@as(usize, 2), array_val.array.items.len);
}

test "LocalBuilder with footer" {
    const allocator = testing.allocator;
    
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    _ = try builder.setFooter("test-footer");
    _ = try builder.setClaimString("test", "value");
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    try testing.expect(mem.endsWith(u8, token, "test-footer"));
    
    // Verify parsing with footer
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parseLocal(token, &key, "test-footer", null);
    defer claims.deinit(allocator);
    
    const test_val = claims.custom.get("test").?;
    try testing.expectEqualStrings("value", test_val.string);
}

test "LocalBuilder with implicit assertion" {
    const allocator = testing.allocator;
    
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    _ = try builder.setClaimString("test", "value");
    
    const token = try builder.buildWithImplicit(&key, "implicit-data");
    defer allocator.free(token);
    
    // Should decrypt with correct implicit
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parseLocal(token, &key, null, "implicit-data");
    defer claims.deinit(allocator);
    
    const test_val = claims.custom.get("test").?;
    try testing.expectEqualStrings("value", test_val.string);
    
    // Should fail with wrong implicit
    try testing.expectError(errors.Error.InvalidSignature,
        parser.parseLocal(token, &key, null, "wrong-implicit"));
}

test "LocalBuilder claim overwriting" {
    const allocator = testing.allocator;
    
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Set initial value
    _ = try builder.setClaimString("test", "initial");
    
    // Overwrite with new value
    _ = try builder.setClaimString("test", "updated");
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parseLocal(token, &key, null, null);
    defer claims.deinit(allocator);
    
    const test_val = claims.custom.get("test").?;
    try testing.expectEqualStrings("updated", test_val.string);
}

test "LocalBuilder empty claims" {
    const allocator = testing.allocator;
    
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Build without any claims
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parseLocal(token, &key, null, null);
    defer claims.deinit(allocator);
    
    // Should have no standard claims
    try testing.expect(claims.issuer == null);
    try testing.expect(claims.subject == null);
    try testing.expect(claims.audience == null);
    try testing.expect(claims.custom.count() == 0);
}

test "PublicBuilder basic creation" {
    const allocator = testing.allocator;
    
    var builder = v4.PublicBuilder.init(allocator);
    defer builder.deinit();
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    _ = try builder.setClaimString("test", "value");
    
    const token = try builder.build(&keypair.secret);
    defer allocator.free(token);
    
    try testing.expect(mem.startsWith(u8, token, "v4.public."));
}

test "PublicBuilder with defaults" {
    const allocator = testing.allocator;
    
    var builder = v4.PublicBuilder.init(allocator);
    defer builder.deinit();
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    _ = try builder.withDefaults();
    
    const token = try builder.build(&keypair.secret);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parsePublic(token, &keypair.public, null, null);
    defer claims.deinit(allocator);
    
    try testing.expect(claims.issued_at != null);
    try testing.expect(claims.expiration != null);
}

test "PublicBuilder standard claims" {
    const allocator = testing.allocator;
    
    var builder = v4.PublicBuilder.init(allocator);
    defer builder.deinit();
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    _ = try builder.setIssuer("public-issuer");
    _ = try builder.setSubject("public-subject");
    _ = try builder.setAudience("public-audience");
    
    const token = try builder.build(&keypair.secret);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parsePublic(token, &keypair.public, null, null);
    defer claims.deinit(allocator);
    
    try testing.expectEqualStrings("public-issuer", claims.issuer.?);
    try testing.expectEqualStrings("public-subject", claims.subject.?);
    try testing.expectEqualStrings("public-audience", claims.audience.?);
}

test "PublicBuilder with footer" {
    const allocator = testing.allocator;
    
    var builder = v4.PublicBuilder.init(allocator);
    defer builder.deinit();
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    _ = try builder.setFooter("public-footer");
    _ = try builder.setClaimString("test", "public_value");
    
    const token = try builder.build(&keypair.secret);
    defer allocator.free(token);
    
    try testing.expect(mem.endsWith(u8, token, "public-footer"));
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parsePublic(token, &keypair.public, "public-footer", null);
    defer claims.deinit(allocator);
    
    const test_val = claims.custom.get("test").?;
    try testing.expectEqualStrings("public_value", test_val.string);
}

test "PublicBuilder with implicit assertion" {
    const allocator = testing.allocator;
    
    var builder = v4.PublicBuilder.init(allocator);
    defer builder.deinit();
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    _ = try builder.setClaimString("test", "value");
    
    const token = try builder.buildWithImplicit(&keypair.secret, "public-implicit");
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parsePublic(token, &keypair.public, null, "public-implicit");
    defer claims.deinit(allocator);
    
    const test_val = claims.custom.get("test").?;
    try testing.expectEqualStrings("value", test_val.string);
    
    // Should fail with wrong implicit
    try testing.expectError(errors.Error.InvalidSignature,
        parser.parsePublic(token, &keypair.public, null, "wrong-implicit"));
}

test "builder claim type validation" {
    const allocator = testing.allocator;
    
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    // Test various claim types
    _ = try builder.setClaimString("str", "text");
    _ = try builder.setClaimNumber("int", 42);
    _ = try builder.setClaimNumber("float", 3.14159);
    _ = try builder.setClaimBool("true_val", true);
    _ = try builder.setClaimBool("false_val", false);
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parseLocal(token, &key, null, null);
    defer claims.deinit(allocator);
    
    try testing.expectEqualStrings("text", claims.custom.get("str").?.string);
    try testing.expectEqual(@as(f64, 42), claims.custom.get("int").?.float);
    try testing.expectEqual(@as(f64, 3.14159), claims.custom.get("float").?.float);
    try testing.expectEqual(true, claims.custom.get("true_val").?.bool);
    try testing.expectEqual(false, claims.custom.get("false_val").?.bool);
}

test "builder large payload" {
    const allocator = testing.allocator;
    
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    // Create large string claim
    const large_value = "A" ** 5000;
    _ = try builder.setClaimString("large", large_value);
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parseLocal(token, &key, null, null);
    defer claims.deinit(allocator);
    
    const large_val = claims.custom.get("large").?;
    try testing.expectEqualStrings(large_value, large_val.string);
}

test "builder nested JSON structure" {
    const allocator = testing.allocator;
    
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    // Create nested object
    var nested_obj = std.HashMap([]const u8, json.Value).init(allocator);
    defer nested_obj.deinit();
    
    try nested_obj.put("inner_string", json.Value{ .string = "nested_value" });
    try nested_obj.put("inner_number", json.Value{ .integer = 999 });
    
    _ = try builder.setClaimObject("nested", nested_obj);
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parseLocal(token, &key, null, null);
    defer claims.deinit(allocator);
    
    const nested_val = claims.custom.get("nested").?;
    try testing.expect(nested_val == .object);
    
    const inner_string = nested_val.object.get("inner_string").?;
    const inner_number = nested_val.object.get("inner_number").?;
    
    try testing.expectEqualStrings("nested_value", inner_string.string);
    try testing.expectEqual(@as(i64, 999), inner_number.integer);
}

test "builder Unicode and special characters" {
    const allocator = testing.allocator;
    
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    _ = try builder.setClaimString("unicode", "Hello 🌍 世界 مرحبا");
    _ = try builder.setClaimString("special", "Line1\nLine2\tTabbed\"Quoted'");
    _ = try builder.setClaimString("json_like", "{\"key\": \"value\", \"array\": [1,2,3]}");
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    const token = try builder.build(&key);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parseLocal(token, &key, null, null);
    defer claims.deinit(allocator);
    
    try testing.expectEqualStrings("Hello 🌍 世界 مرحبا", claims.custom.get("unicode").?.string);
    try testing.expectEqualStrings("Line1\nLine2\tTabbed\"Quoted'", claims.custom.get("special").?.string);
    try testing.expectEqualStrings("{\"key\": \"value\", \"array\": [1,2,3]}", claims.custom.get("json_like").?.string);
}

test "builder method chaining" {
    const allocator = testing.allocator;
    
    var builder = v4.LocalBuilder.init(allocator);
    defer builder.deinit();
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Test method chaining
    const token = try builder
        .setIssuer("chain-issuer") catch unreachable
        .setSubject("chain-subject") catch unreachable
        .setClaimString("chain", "test") catch unreachable
        .setFooter("chain-footer") catch unreachable
        .build(&key);
    defer allocator.free(token);
    
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parseLocal(token, &key, "chain-footer", null);
    defer claims.deinit(allocator);
    
    try testing.expectEqualStrings("chain-issuer", claims.issuer.?);
    try testing.expectEqualStrings("chain-subject", claims.subject.?);
    try testing.expectEqualStrings("test", claims.custom.get("chain").?.string);
}