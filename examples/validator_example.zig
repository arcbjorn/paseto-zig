const std = @import("std");
const paseto = @import("../src/paseto.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.debug.print("PASETO Validator Example\n");
    std.debug.print("========================\n\n");
    
    // Generate keys
    var key = paseto.LocalKey.generate();
    defer key.deinit();
    
    // Create a token with specific claims
    var builder = paseto.createLocalBuilder(allocator);
    defer builder.deinit();
    
    _ = try builder.withDefaults();
    _ = try builder.setIssuer("api-server");
    _ = try builder.setSubject("user-123");
    _ = try builder.setAudience("mobile-app");
    _ = try builder.setJwtId("token-abc123");
    
    const token = try builder.buildLocal(&key);
    defer allocator.free(token);
    
    std.debug.print("Created token: {s}\n\n", .{token});
    
    // Example 1: Parse with automatic validation
    std.debug.print("Example 1: Automatic validation during parsing\n");
    std.debug.print("----------------------------------------------\n");
    
    var parser = paseto.createParser(allocator);
    _ = parser.setExpectedIssuer("api-server");
    _ = parser.setExpectedAudience("mobile-app");
    _ = parser.setExpectedSubject("user-123");
    _ = parser.setValidateTime(true);
    
    const claims = try parser.parseLocal(token, &key, null, null);
    defer claims.deinit(allocator);
    
    std.debug.print("✓ Token validation passed!\n");
    std.debug.print("  Issuer: {s}\n", .{claims.issuer.?});
    std.debug.print("  Subject: {s}\n", .{claims.subject.?});
    std.debug.print("  Audience: {s}\n", .{claims.audience.?});
    std.debug.print("  JWT ID: {s}\n", .{claims.jwt_id.?});
    
    // Example 2: Manual validation using Validator functions
    std.debug.print("\nExample 2: Manual validation using Validator functions\n");
    std.debug.print("-----------------------------------------------------\n");
    
    // Parse without automatic validation
    var manual_parser = paseto.createParser(allocator);
    _ = manual_parser.setValidateTime(false);  // Disable automatic validation
    
    const manual_claims = try manual_parser.parseLocal(token, &key, null, null);
    defer manual_claims.deinit(allocator);
    
    // Manually validate specific claims
    try paseto.Validator.issuedBy(&manual_claims, "api-server");
    try paseto.Validator.forAudience(&manual_claims, "mobile-app");
    try paseto.Validator.subject(&manual_claims, "user-123");
    try paseto.Validator.identifiedBy(&manual_claims, "token-abc123");
    try paseto.Validator.validAt(&manual_claims, 60); // 60 second leeway
    
    std.debug.print("✓ Manual validation passed!\n");
    
    // Example 3: Validation failures
    std.debug.print("\nExample 3: Validation failure examples\n");
    std.debug.print("--------------------------------------\n");
    
    // Try to validate with wrong expected values
    const wrong_audience_result = paseto.Validator.forAudience(&manual_claims, "wrong-audience");
    if (wrong_audience_result) {
        std.debug.print("Unexpected success!\n");
    } else |err| {
        std.debug.print("✓ Expected failure for wrong audience: {}\n", .{err});
    }
    
    const wrong_issuer_result = paseto.Validator.issuedBy(&manual_claims, "wrong-issuer");
    if (wrong_issuer_result) {
        std.debug.print("Unexpected success!\n");
    } else |err| {
        std.debug.print("✓ Expected failure for wrong issuer: {}\n", .{err});
    }
    
    std.debug.print("\nAll validator examples completed successfully!\n");
}