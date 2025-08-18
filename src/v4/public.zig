const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const Allocator = std.mem.Allocator;
const testing = std.testing;

const errors = @import("../errors.zig");
const utils = @import("../utils.zig");
const keys = @import("keys.zig");

const SecretKey = keys.SecretKey;
const PublicKey = keys.PublicKey;

const HEADER_V4_PUBLIC = "v4.public.";
const SIGNATURE_SIZE = 64; // Ed25519 signature size

/// Sign a payload using v4.public (Ed25519)
pub fn sign(
    allocator: Allocator,
    payload: []const u8,
    secret_key: *const SecretKey,
    footer: ?[]const u8,
    implicit: ?[]const u8,
) ![]u8 {
    // Build pre-authentication data using PAE
    var pae_parts = std.ArrayList([]const u8).init(allocator);
    defer pae_parts.deinit();
    
    try pae_parts.append(HEADER_V4_PUBLIC);
    try pae_parts.append(payload);
    if (footer) |f| try pae_parts.append(f);
    if (implicit) |i| try pae_parts.append(i);
    
    const pae_data = try utils.pae(allocator, pae_parts.items);
    defer allocator.free(pae_data);
    
    // Sign the PAE data with Ed25519
    const sk = crypto.sign.Ed25519.SecretKey.fromBytes(secret_key.key[0..32].*);
    const signature = sk.sign(pae_data, null);
    
    // Build token data: payload + signature
    const token_data = try allocator.alloc(u8, payload.len + SIGNATURE_SIZE);
    defer allocator.free(token_data);
    
    @memcpy(token_data[0..payload.len], payload);
    @memcpy(token_data[payload.len..], &signature);
    
    // Encode as base64url
    const encoded_data = try utils.base64urlEncode(allocator, token_data);
    defer allocator.free(encoded_data);
    
    // Construct final token
    const footer_len = if (footer) |f| f.len else 0;
    const token_len = HEADER_V4_PUBLIC.len + encoded_data.len + 
        (if (footer_len > 0) footer_len + 1 else 0); // +1 for '.'
    
    var token = try allocator.alloc(u8, token_len);
    var pos: usize = 0;
    
    @memcpy(token[pos..pos + HEADER_V4_PUBLIC.len], HEADER_V4_PUBLIC);
    pos += HEADER_V4_PUBLIC.len;
    
    @memcpy(token[pos..pos + encoded_data.len], encoded_data);
    pos += encoded_data.len;
    
    if (footer) |f| {
        token[pos] = '.';
        pos += 1;
        @memcpy(token[pos..pos + f.len], f);
    }
    
    return token;
}

/// Verify a v4.public token
pub fn verify(
    allocator: Allocator,
    token: []const u8,
    public_key: *const PublicKey,
    footer: ?[]const u8,
    implicit: ?[]const u8,
) ![]u8 {
    // Check header
    if (token.len < HEADER_V4_PUBLIC.len or 
        !mem.eql(u8, token[0..HEADER_V4_PUBLIC.len], HEADER_V4_PUBLIC)) {
        return errors.Error.InvalidHeader;
    }
    
    // Find the footer separator
    var token_body = token[HEADER_V4_PUBLIC.len..];
    var found_footer: ?[]const u8 = null;
    
    if (mem.lastIndexOf(u8, token_body, ".")) |dot_pos| {
        found_footer = token_body[dot_pos + 1..];
        token_body = token_body[0..dot_pos];
    }
    
    // Verify footer matches
    if (footer) |expected_footer| {
        if (found_footer == null or !mem.eql(u8, found_footer.?, expected_footer)) {
            return errors.Error.InvalidFooter;
        }
    } else if (found_footer != null) {
        return errors.Error.InvalidFooter;
    }
    
    // Decode the token body
    const decoded = try utils.base64urlDecode(allocator, token_body);
    defer allocator.free(decoded);
    
    if (decoded.len < SIGNATURE_SIZE) {
        return errors.Error.InvalidToken;
    }
    
    const payload_len = decoded.len - SIGNATURE_SIZE;
    const payload = decoded[0..payload_len];
    const signature = decoded[payload_len..];
    
    // Build PAE for verification
    var pae_parts = std.ArrayList([]const u8).init(allocator);
    defer pae_parts.deinit();
    
    try pae_parts.append(HEADER_V4_PUBLIC);
    try pae_parts.append(payload);
    if (found_footer) |f| try pae_parts.append(f);
    if (implicit) |i| try pae_parts.append(i);
    
    const pae_data = try utils.pae(allocator, pae_parts.items);
    defer allocator.free(pae_data);
    
    // Verify signature
    const sig_array: [64]u8 = signature[0..64].*;
    const pk = crypto.sign.Ed25519.PublicKey{ .bytes = public_key.key };
    const sig = crypto.sign.Ed25519.Signature{ .bytes = sig_array };
    sig.verify(pae_data, pk) catch {
        return errors.Error.InvalidSignature;
    };
    
    // Return verified payload
    const result = try allocator.alloc(u8, payload.len);
    @memcpy(result, payload);
    return result;
}

test "v4.public sign/verify without footer" {
    const allocator = testing.allocator;
    
    var key_pair = keys.KeyPair.generate();
    defer key_pair.deinit();
    
    const payload = "hello world";
    
    const token = try sign(allocator, payload, &key_pair.secret, null, null);
    defer allocator.free(token);
    
    try testing.expect(mem.startsWith(u8, token, HEADER_V4_PUBLIC));
    
    const verified_payload = try verify(allocator, token, &key_pair.public, null, null);
    defer allocator.free(verified_payload);
    
    try testing.expectEqualStrings(payload, verified_payload);
}

test "v4.public sign/verify with footer" {
    const allocator = testing.allocator;
    
    var key_pair = keys.KeyPair.generate();
    defer key_pair.deinit();
    
    const payload = "hello world";
    const footer = "test-footer";
    
    const token = try sign(allocator, payload, &key_pair.secret, footer, null);
    defer allocator.free(token);
    
    try testing.expect(mem.startsWith(u8, token, HEADER_V4_PUBLIC));
    try testing.expect(mem.endsWith(u8, token, footer));
    
    const verified_payload = try verify(allocator, token, &key_pair.public, footer, null);
    defer allocator.free(verified_payload);
    
    try testing.expectEqualStrings(payload, verified_payload);
}

test "v4.public sign/verify with implicit assertion" {
    const allocator = testing.allocator;
    
    var key_pair = keys.KeyPair.generate();
    defer key_pair.deinit();
    
    const payload = "hello world";
    const implicit = "implicit-data";
    
    const token = try sign(allocator, payload, &key_pair.secret, null, implicit);
    defer allocator.free(token);
    
    const verified_payload = try verify(allocator, token, &key_pair.public, null, implicit);
    defer allocator.free(verified_payload);
    
    try testing.expectEqualStrings(payload, verified_payload);
    
    // Should fail with wrong implicit
    try testing.expectError(errors.Error.InvalidSignature, 
        verify(allocator, token, &key_pair.public, null, "wrong-implicit"));
}

test "v4.public verify with wrong key should fail" {
    const allocator = testing.allocator;
    
    var key_pair1 = keys.KeyPair.generate();
    defer key_pair1.deinit();
    
    var key_pair2 = keys.KeyPair.generate();
    defer key_pair2.deinit();
    
    const payload = "hello world";
    
    const token = try sign(allocator, payload, &key_pair1.secret, null, null);
    defer allocator.free(token);
    
    try testing.expectError(errors.Error.InvalidSignature, 
        verify(allocator, token, &key_pair2.public, null, null));
}

test "v4.public verify tampered token should fail" {
    const allocator = testing.allocator;
    
    var key_pair = keys.KeyPair.generate();
    defer key_pair.deinit();
    
    const payload = "hello world";
    
    var token = try sign(allocator, payload, &key_pair.secret, null, null);
    defer allocator.free(token);
    
    // Tamper with the token (change last character)
    token[token.len - 1] = if (token[token.len - 1] == 'A') 'B' else 'A';
    
    try testing.expectError(errors.Error.InvalidSignature, 
        verify(allocator, token, &key_pair.public, null, null));
}