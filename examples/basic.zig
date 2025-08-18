const std = @import("std");
const print = std.debug.print;
const paseto = @import("paseto");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    print("PASETO Zig Library Demo\n", .{});
    print("=======================\n\n", .{});
    
    // Demo 1: Local tokens (symmetric encryption)
    try demoLocalTokens(allocator);
    
    print("\n", .{});
    
    // Demo 2: Public tokens (digital signatures)
    try demoPublicTokens(allocator);
    
    print("\n", .{});
    
    // Demo 3: PASERK key management
    try demoPaserkKeys(allocator);
}

fn demoLocalTokens(allocator: std.mem.Allocator) !void {
    print("1. Local Tokens (v4.local)\n", .{});
    print("---------------------------\n", .{});
    
    // Generate a local key
    var key = paseto.LocalKey.generate();
    defer key.deinit();
    
    print("Generated local key: ", .{});
    printHex(key.bytes());
    print("\n", .{});
    
    // Create a token
    var builder = paseto.createLocalBuilder(allocator);
    defer builder.deinit();
    
    _ = try builder.withDefaults();
    _ = try builder.setIssuer("demo-app");
    _ = try builder.setSubject("user-123");
    _ = try builder.setAudience("api-server");
    _ = try builder.setClaimNumber("user_id", 12345);
    _ = try builder.setClaimBool("premium", true);
    _ = try builder.setFooter("public-metadata");
    
    const token = try builder.buildLocal(&key);
    defer allocator.free(token);
    
    print("Created token: {s}\n", .{token});
    
    // Parse and verify the token
    var parser = paseto.createParser(allocator);
    _ = parser.setValidateTime(false); // Skip time validation for demo
    
    var claims = try parser.parseLocal(token, &key, "public-metadata", null);
    defer claims.deinit(allocator);
    
    print("Verified claims:\n", .{});
    print("  Issuer: {s}\n", .{claims.issuer.?});
    print("  Subject: {s}\n", .{claims.subject.?});
    print("  Audience: {s}\n", .{claims.audience.?});
    
    const user_id = claims.custom.get("user_id").?;
    const premium = claims.custom.get("premium").?;
    print("  User ID: {d}\n", .{@as(i64, @intFromFloat(user_id.float))});
    print("  Premium: {}\n", .{premium.bool});
}

fn demoPublicTokens(allocator: std.mem.Allocator) !void {
    print("2. Public Tokens (v4.public)\n", .{});
    print("-----------------------------\n", .{});
    
    // Generate a key pair
    var key_pair = paseto.KeyPair.generate();
    defer key_pair.deinit();
    
    print("Generated key pair:\n", .{});
    print("  Public key: ", .{});
    printHex(key_pair.public.bytes());
    print("\n", .{});
    print("  Secret key seed: ", .{});
    printHex(key_pair.secret.seed());
    print("\n", .{});
    
    // Create a signed token
    var builder = paseto.createPublicBuilder(allocator);
    defer builder.deinit();
    
    _ = try builder.setIssuer("auth-service");
    _ = try builder.setSubject("service-account");
    _ = try builder.setClaimNumber("permissions", 755);
    _ = try builder.setClaimBool("service", true);
    
    const token = try builder.buildPublic(&key_pair.secret);
    defer allocator.free(token);
    
    print("Created signed token: {s}\n", .{token});
    
    // Verify the token
    var parser = paseto.createParser(allocator);
    _ = parser.setValidateTime(false);
    
    var claims = try parser.parsePublic(token, &key_pair.public, null, null);
    defer claims.deinit(allocator);
    
    print("Verified claims:\n", .{});
    print("  Issuer: {s}\n", .{claims.issuer.?});
    print("  Subject: {s}\n", .{claims.subject.?});
    
    const permissions = claims.custom.get("permissions").?;
    const service = claims.custom.get("service").?;
    print("  Permissions: {d}\n", .{@as(i64, @intFromFloat(permissions.float))});
    print("  Service: {}\n", .{service.bool});
}

fn demoPaserkKeys(allocator: std.mem.Allocator) !void {
    print("3. PASERK Key Management\n", .{});
    print("------------------------\n", .{});
    
    // Generate keys
    var local_key = paseto.LocalKey.generate();
    defer local_key.deinit();
    
    var key_pair = paseto.KeyPair.generate();
    defer key_pair.deinit();
    
    // Serialize keys to PASERK format
    const local_paserk = try paseto.paserk.serializeLocalKey(allocator, &local_key);
    defer allocator.free(local_paserk);
    
    const public_paserk = try paseto.paserk.serializePublicKey(allocator, &key_pair.public);
    defer allocator.free(public_paserk);
    
    const secret_paserk = try paseto.paserk.serializeSecretKey(allocator, &key_pair.secret);
    defer allocator.free(secret_paserk);
    
    print("PASERK serialized keys:\n", .{});
    print("  Local key: {s}\n", .{local_paserk});
    print("  Public key: {s}\n", .{public_paserk});
    print("  Secret key: {s}\n", .{secret_paserk});
    
    // Generate key identifiers
    const lid = paseto.LocalKeyId.fromLocalKey(local_key.bytes());
    const sid = paseto.SecretKeyId.fromSecretKey(key_pair.secret.bytes());
    
    const lid_paserk = try lid.serialize(allocator);
    defer allocator.free(lid_paserk);
    
    const sid_paserk = try sid.serialize(allocator);
    defer allocator.free(sid_paserk);
    
    print("Key identifiers:\n", .{});
    print("  Local key ID: {s}\n", .{lid_paserk});
    print("  Secret key ID: {s}\n", .{sid_paserk});
    
    // Demonstrate key wrapping with password
    const password = "super-secret-password";
    const wrapped_local = try paseto.paserk.password.wrapLocalKeyWithPassword(
        allocator,
        &local_key,
        password,
        .{ .iterations = 10000 }, // Reduced for demo speed
    );
    defer allocator.free(wrapped_local);
    
    print("Password-wrapped local key: {s}\n", .{wrapped_local});
    
    // Unwrap and verify
    const unwrapped_local = try paseto.paserk.password.unwrapLocalKeyWithPassword(
        allocator,
        wrapped_local,
        password,
    );
    
    print("Successfully unwrapped key: ", .{});
    if (std.mem.eql(u8, local_key.bytes(), unwrapped_local.bytes())) {
        print("✓ Keys match!\n", .{});
    } else {
        print("✗ Keys don't match!\n", .{});
    }
}

fn printHex(bytes: []const u8) void {
    for (bytes[0..@min(bytes.len, 16)]) |byte| { // Print first 16 bytes
        print("{x:0>2}", .{byte});
    }
    if (bytes.len > 16) {
        print("...", .{});
    }
}