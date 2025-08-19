const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const Allocator = std.mem.Allocator;
const testing = std.testing;

const errors = @import("../errors.zig");
const utils = @import("../utils.zig");
const keys = @import("keys.zig");

const LocalKey = keys.LocalKey;
const Version = keys.Version;
const Purpose = keys.Purpose;

const HEADER_V4_LOCAL = "v4.local.";
const NONCE_SIZE = 32; // Random nonce size
const TAG_SIZE = 32;   // BLAKE2b MAC size

/// Encrypt a payload using v4.local (XChaCha20-BLAKE2b)
pub fn encrypt(
    allocator: Allocator,
    payload: []const u8,
    key: *const LocalKey,
    footer: ?[]const u8,
    implicit: ?[]const u8,
) ![]u8 {
    // Generate random nonce
    var nonce: [NONCE_SIZE]u8 = undefined;
    crypto.random.bytes(&nonce);
    
    return encryptWithNonce(allocator, payload, key, &nonce, footer, implicit);
}

/// Encrypt with a specific nonce (used for testing)
pub fn encryptWithNonce(
    allocator: Allocator,
    payload: []const u8,
    key: *const LocalKey,
    nonce: *const [NONCE_SIZE]u8,
    footer: ?[]const u8,
    implicit: ?[]const u8,
) ![]u8 {
    // Algorithm Lucidity: Validate key is appropriate for v4.local
    if (!key.isKeyValidFor(.v4, .local)) {
        return errors.Error.KeyTypeMismatch;
    }
    
    // Validate footer if provided
    if (footer) |f| {
        try utils.validateFooter(f);
    }
    
    // Calculate sizes (removed unused footer_len)
    
    // Build pre-authentication data using PAE
    var pae_parts = std.ArrayList([]const u8).init(allocator);
    defer pae_parts.deinit();
    
    try pae_parts.append(HEADER_V4_LOCAL);
    try pae_parts.append(nonce);
    try pae_parts.append(""); // ciphertext placeholder, will be updated
    if (footer) |f| try pae_parts.append(f);
    if (implicit) |i| try pae_parts.append(i);
    
    // Derive encryption and authentication keys using BLAKE2b
    const ek_result = try deriveEncryptionKey(allocator, key.bytes(), nonce);
    defer allocator.free(ek_result.key);
    defer allocator.free(ek_result.n2);
    
    const ak = try deriveAuthKey(allocator, key.bytes(), nonce);
    defer allocator.free(ak);
    
    // Encrypt with XChaCha20 using HChaCha20 + ChaCha20IETF construction
    const ciphertext = try allocator.alloc(u8, payload.len);
    defer allocator.free(ciphertext);
    
    // Implement XChaCha20 using HChaCha20 key derivation + ChaCha20IETF
    try xchachaEncrypt(ciphertext, payload, ek_result.key[0..32].*, ek_result.n2[0..24].*);
    
    // Update PAE with actual ciphertext
    pae_parts.items[2] = ciphertext;
    const pae_data = try utils.pae(allocator, pae_parts.items);
    defer allocator.free(pae_data);
    
    // Generate BLAKE2b MAC (32 bytes)
    var hasher = crypto.hash.blake2.Blake2b256.init(.{ .key = ak[0..32] });
    hasher.update(pae_data);
    var tag: [32]u8 = undefined;
    hasher.final(&tag);
    
    // Build final token: header + base64url(nonce + ciphertext + tag) + footer
    const token_data = try allocator.alloc(u8, NONCE_SIZE + ciphertext.len + TAG_SIZE);
    defer allocator.free(token_data);
    
    @memcpy(token_data[0..NONCE_SIZE], nonce);
    @memcpy(token_data[NONCE_SIZE..NONCE_SIZE + ciphertext.len], ciphertext);
    @memcpy(token_data[NONCE_SIZE + ciphertext.len..], &tag);
    
    const encoded_data = try utils.base64urlEncode(allocator, token_data);
    defer allocator.free(encoded_data);
    
    // Construct final token according to specification
    if (footer) |f| {
        // Non-empty: h || base64url(n || c || t) || '.' || base64url(f)
        const encoded_footer = try utils.base64urlEncode(allocator, f);
        defer allocator.free(encoded_footer);
        
        const token_len = HEADER_V4_LOCAL.len + encoded_data.len + 1 + encoded_footer.len;
        var token = try allocator.alloc(u8, token_len);
        var pos: usize = 0;
        
        @memcpy(token[pos..pos + HEADER_V4_LOCAL.len], HEADER_V4_LOCAL);
        pos += HEADER_V4_LOCAL.len;
        
        @memcpy(token[pos..pos + encoded_data.len], encoded_data);
        pos += encoded_data.len;
        
        token[pos] = '.';
        pos += 1;
        
        @memcpy(token[pos..pos + encoded_footer.len], encoded_footer);
        return token;
    } else {
        // Empty: h || base64url(n || c || t)
        const token_len = HEADER_V4_LOCAL.len + encoded_data.len;
        var token = try allocator.alloc(u8, token_len);
        
        @memcpy(token[0..HEADER_V4_LOCAL.len], HEADER_V4_LOCAL);
        @memcpy(token[HEADER_V4_LOCAL.len..], encoded_data);
        return token;
    }
}

/// Decrypt a v4.local token
pub fn decrypt(
    allocator: Allocator,
    token: []const u8,
    key: *const LocalKey,
    footer: ?[]const u8,
    implicit: ?[]const u8,
) ![]u8 {
    // Algorithm Lucidity: Validate key is appropriate for v4.local
    if (!key.isKeyValidFor(.v4, .local)) {
        return errors.Error.KeyTypeMismatch;
    }
    
    // Check header
    if (token.len < HEADER_V4_LOCAL.len or 
        !mem.eql(u8, token[0..HEADER_V4_LOCAL.len], HEADER_V4_LOCAL)) {
        return errors.Error.InvalidHeader;
    }
    
    // Find the footer separator
    var token_body = token[HEADER_V4_LOCAL.len..];
    var found_footer_encoded: ?[]const u8 = null;
    
    if (mem.lastIndexOf(u8, token_body, ".")) |dot_pos| {
        found_footer_encoded = token_body[dot_pos + 1..];
        token_body = token_body[0..dot_pos];
    }
    
    // Decode and validate footer if present
    var found_footer_decoded: ?[]u8 = null;
    defer if (found_footer_decoded) |f| allocator.free(f);
    
    if (found_footer_encoded) |f_enc| {
        found_footer_decoded = try utils.base64urlDecode(allocator, f_enc);
        try utils.validateFooter(found_footer_decoded.?);
    }
    
    // Verify footer matches
    if (footer) |expected_footer| {
        if (found_footer_decoded == null or !mem.eql(u8, found_footer_decoded.?, expected_footer)) {
            return errors.Error.InvalidFooter;
        }
    } else if (found_footer_decoded != null) {
        return errors.Error.InvalidFooter;
    }
    
    // Decode the token body
    const decoded = try utils.base64urlDecode(allocator, token_body);
    defer allocator.free(decoded);
    
    if (decoded.len < NONCE_SIZE + TAG_SIZE) {
        return errors.Error.InvalidToken;
    }
    
    const nonce = decoded[0..NONCE_SIZE];
    const tag = decoded[decoded.len - TAG_SIZE..];
    const ciphertext = decoded[NONCE_SIZE..decoded.len - TAG_SIZE];
    
    // Derive keys
    const ek_result = try deriveEncryptionKey(allocator, key.bytes(), nonce);
    defer allocator.free(ek_result.key);
    defer allocator.free(ek_result.n2);
    
    const ak = try deriveAuthKey(allocator, key.bytes(), nonce);
    defer allocator.free(ak);
    
    // Build PAE for authentication
    var pae_parts = std.ArrayList([]const u8).init(allocator);
    defer pae_parts.deinit();
    
    try pae_parts.append(HEADER_V4_LOCAL);
    try pae_parts.append(nonce);
    try pae_parts.append(ciphertext);
    if (found_footer_decoded) |f| try pae_parts.append(f);
    if (implicit) |i| try pae_parts.append(i);
    
    const pae_data = try utils.pae(allocator, pae_parts.items);
    defer allocator.free(pae_data);
    
    // Verify BLAKE2b MAC
    var hasher = crypto.hash.blake2.Blake2b256.init(.{ .key = ak[0..32] });
    hasher.update(pae_data);
    var expected_tag: [32]u8 = undefined;
    hasher.final(&expected_tag);
    if (!utils.constantTimeEqual(tag, &expected_tag)) {
        return errors.Error.InvalidSignature;
    }
    
    // Decrypt using XChaCha20
    const plaintext = try allocator.alloc(u8, ciphertext.len);
    try xchachaDecrypt(plaintext, ciphertext, ek_result.key[0..32].*, ek_result.n2[0..24].*);
    
    return plaintext;
}

/// Derive encryption key and nonce using BLAKE2b (56 bytes total)
fn deriveEncryptionKey(allocator: Allocator, key: *const [32]u8, nonce: []const u8) !struct { key: []u8, n2: []u8 } {
    // Use BLAKE2b512 and take first 56 bytes to match PASETO specification  
    var hasher = crypto.hash.blake2.Blake2b512.init(.{ .key = &key.* });
    hasher.update("paseto-encryption-key");
    hasher.update(nonce);
    
    var tmp: [64]u8 = undefined;
    hasher.final(&tmp); // BLAKE2b512 produces 64 bytes, we use first 56
    
    // Split: first 32 bytes = encryption key, next 24 bytes = XChaCha20 nonce
    const ek = try allocator.alloc(u8, 32);
    const n2 = try allocator.alloc(u8, 24);
    @memcpy(ek, tmp[0..32]);
    @memcpy(n2, tmp[32..56]);
    
    return .{ .key = ek, .n2 = n2 };
}

/// Derive authentication key using BLAKE2b (32 bytes)
fn deriveAuthKey(allocator: Allocator, key: *const [32]u8, nonce: []const u8) ![]u8 {
    var hasher = crypto.hash.blake2.Blake2b256.init(.{ .key = &key.* });
    hasher.update("paseto-auth-key-for-aead");
    hasher.update(nonce);
    
    var ak = try allocator.alloc(u8, 32);
    hasher.final(ak[0..32]);
    return ak;
}

/// XChaCha20 encryption using HChaCha20 key derivation + ChaCha20IETF
/// This implements XChaCha20 as required by PASETO v4 specification
fn xchachaEncrypt(output: []u8, input: []const u8, key: [32]u8, nonce: [24]u8) !void {
    // Step 1: Derive subkey using HChaCha20
    const subkey = hchacha20(key, nonce[0..16].*);
    
    // Step 2: Use ChaCha20IETF with derived subkey and remaining nonce
    const chacha_nonce = [12]u8{
        nonce[16], nonce[17], nonce[18], nonce[19],
        nonce[20], nonce[21], nonce[22], nonce[23],
        0, 0, 0, 0  // Counter starts at 0
    };
    
    crypto.stream.chacha.ChaCha20IETF.xor(output, input, 0, subkey, chacha_nonce);
}

/// XChaCha20 decryption (same as encryption for stream cipher)
fn xchachaDecrypt(output: []u8, input: []const u8, key: [32]u8, nonce: [24]u8) !void {
    return xchachaEncrypt(output, input, key, nonce);
}

/// HChaCha20 key derivation function
/// Takes a 32-byte key and 16-byte nonce, returns a 32-byte subkey
fn hchacha20(key: [32]u8, nonce: [16]u8) [32]u8 {
    // HChaCha20 constants
    const constants = [4]u32{ 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
    
    // Initialize state
    var state: [16]u32 = undefined;
    
    // Load constants
    state[0] = constants[0];
    state[1] = constants[1];
    state[2] = constants[2];
    state[3] = constants[3];
    
    // Load key (8 words)
    state[4] = mem.readInt(u32, key[0..4], .little);
    state[5] = mem.readInt(u32, key[4..8], .little);
    state[6] = mem.readInt(u32, key[8..12], .little);
    state[7] = mem.readInt(u32, key[12..16], .little);
    state[8] = mem.readInt(u32, key[16..20], .little);
    state[9] = mem.readInt(u32, key[20..24], .little);
    state[10] = mem.readInt(u32, key[24..28], .little);
    state[11] = mem.readInt(u32, key[28..32], .little);
    
    // Load nonce (4 words)
    state[12] = mem.readInt(u32, nonce[0..4], .little);
    state[13] = mem.readInt(u32, nonce[4..8], .little);
    state[14] = mem.readInt(u32, nonce[8..12], .little);
    state[15] = mem.readInt(u32, nonce[12..16], .little);
    
    // Perform 20 rounds (10 double rounds)
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        // Column rounds
        quarterRound(&state[0], &state[4], &state[8], &state[12]);
        quarterRound(&state[1], &state[5], &state[9], &state[13]);
        quarterRound(&state[2], &state[6], &state[10], &state[14]);
        quarterRound(&state[3], &state[7], &state[11], &state[15]);
        
        // Diagonal rounds
        quarterRound(&state[0], &state[5], &state[10], &state[15]);
        quarterRound(&state[1], &state[6], &state[11], &state[12]);
        quarterRound(&state[2], &state[7], &state[8], &state[13]);
        quarterRound(&state[3], &state[4], &state[9], &state[14]);
    }
    
    // Extract result: state[0..3] || state[12..15]
    var result: [32]u8 = undefined;
    mem.writeInt(u32, result[0..4], state[0], .little);
    mem.writeInt(u32, result[4..8], state[1], .little);
    mem.writeInt(u32, result[8..12], state[2], .little);
    mem.writeInt(u32, result[12..16], state[3], .little);
    mem.writeInt(u32, result[16..20], state[12], .little);
    mem.writeInt(u32, result[20..24], state[13], .little);
    mem.writeInt(u32, result[24..28], state[14], .little);
    mem.writeInt(u32, result[28..32], state[15], .little);
    
    return result;
}

/// ChaCha20 quarter round function
fn quarterRound(a: *u32, b: *u32, c: *u32, d: *u32) void {
    a.* = a.* +% b.*;
    d.* ^= a.*;
    d.* = std.math.rotl(u32, d.*, 16);
    
    c.* = c.* +% d.*;
    b.* ^= c.*;
    b.* = std.math.rotl(u32, b.*, 12);
    
    a.* = a.* +% b.*;
    d.* ^= a.*;
    d.* = std.math.rotl(u32, d.*, 8);
    
    c.* = c.* +% d.*;
    b.* ^= c.*;
    b.* = std.math.rotl(u32, b.*, 7);
}

test "v4.local encrypt/decrypt without footer" {
    const allocator = testing.allocator;
    
    var key = LocalKey.generate();
    defer key.deinit();
    
    const payload = "hello world";
    
    const token = try encrypt(allocator, payload, &key, null, null);
    defer allocator.free(token);
    
    try testing.expect(mem.startsWith(u8, token, HEADER_V4_LOCAL));
    
    const decrypted = try decrypt(allocator, token, &key, null, null);
    defer allocator.free(decrypted);
    
    try testing.expectEqualStrings(payload, decrypted);
}

test "v4.local encrypt/decrypt with footer" {
    const allocator = testing.allocator;
    
    var key = LocalKey.generate();
    defer key.deinit();
    
    const payload = "hello world";
    const footer = "test-footer";
    
    const token = try encrypt(allocator, payload, &key, footer, null);
    defer allocator.free(token);
    
    try testing.expect(mem.startsWith(u8, token, HEADER_V4_LOCAL));
    // Footer is now base64url encoded, so check it contains the footer separator
    try testing.expect(mem.indexOf(u8, token, ".") != null);
    
    const decrypted = try decrypt(allocator, token, &key, footer, null);
    defer allocator.free(decrypted);
    
    try testing.expectEqualStrings(payload, decrypted);
}

test "v4.local encrypt/decrypt with implicit assertion" {
    const allocator = testing.allocator;
    
    var key = LocalKey.generate();
    defer key.deinit();
    
    const payload = "hello world";
    const implicit = "implicit-data";
    
    const token = try encrypt(allocator, payload, &key, null, implicit);
    defer allocator.free(token);
    
    const decrypted = try decrypt(allocator, token, &key, null, implicit);
    defer allocator.free(decrypted);
    
    try testing.expectEqualStrings(payload, decrypted);
    
    // Should fail with wrong implicit
    try testing.expectError(errors.Error.InvalidSignature, 
        decrypt(allocator, token, &key, null, "wrong-implicit"));
}

test "v4.local decrypt with wrong key should fail" {
    const allocator = testing.allocator;
    
    var key1 = LocalKey.generate();
    defer key1.deinit();
    
    var key2 = LocalKey.generate();
    defer key2.deinit();
    
    const payload = "hello world";
    
    const token = try encrypt(allocator, payload, &key1, null, null);
    defer allocator.free(token);
    
    try testing.expectError(errors.Error.InvalidSignature, 
        decrypt(allocator, token, &key2, null, null));
}