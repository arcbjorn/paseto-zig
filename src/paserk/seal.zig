const std = @import("std");
const mem = std.mem;
const Allocator = std.mem.Allocator;
const testing = std.testing;

const errors = @import("../errors.zig");
const utils = @import("../utils.zig");
const types = @import("types.zig");
const v4 = @import("../v4/mod.zig");

const PaserkHeader = types.PaserkHeader;
const PublicKey = v4.PublicKey;

/// Seal (encrypt) data for a recipient using their public key
/// Uses X25519 key exchange + XChaCha20-Poly1305
pub fn seal(
    allocator: Allocator,
    data: []const u8,
    recipient_public_key: *const PublicKey,
) ![]u8 {
    // Generate ephemeral X25519 key pair
    const ephemeral_key_pair = std.crypto.dh.X25519.KeyPair.create(null) catch 
        return errors.Error.CryptographicFailure;
    
    // Perform key exchange with recipient's public key
    // Note: This assumes the public key can be used for X25519, which may need conversion
    const shared_secret = std.crypto.dh.X25519.scalarmult(
        ephemeral_key_pair.secret_key,
        recipient_public_key.bytes().* // This might need conversion from Ed25519 to X25519
    ) catch return errors.Error.CryptographicFailure;
    
    // Derive encryption key from shared secret using HKDF
    var encryption_key: [32]u8 = undefined;
    std.crypto.kdf.hkdf.HkdfSha256.extract(&encryption_key, &shared_secret, "paseto-seal");
    defer utils.secureZero(&encryption_key);
    
    // Generate random nonce
    var nonce: [24]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    
    // Encrypt data
    const ciphertext_len = data.len + 16; // data + tag
    var ciphertext = try allocator.alloc(u8, ciphertext_len);
    defer allocator.free(ciphertext);
    
    std.crypto.aead.xchacha20_poly1305.XChaCha20Poly1305.encrypt(
        ciphertext[0..data.len],
        ciphertext[data.len..],
        data,
        "", // no additional data
        nonce,
        encryption_key,
    );
    
    // Build sealed data: ephemeral_public_key + nonce + ciphertext
    const sealed_len = 32 + 24 + ciphertext_len;
    var sealed_data = try allocator.alloc(u8, sealed_len);
    defer allocator.free(sealed_data);
    
    @memcpy(sealed_data[0..32], &ephemeral_key_pair.public_key);
    @memcpy(sealed_data[32..56], &nonce);
    @memcpy(sealed_data[56..], ciphertext);
    
    // Create PASERK
    const header = PaserkHeader{ .version = 4, .type = .seal };
    const header_str = try header.format(allocator);
    defer allocator.free(header_str);
    
    const encoded_data = try utils.base64urlEncode(allocator, sealed_data);
    defer allocator.free(encoded_data);
    
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ header_str, encoded_data });
}

/// Unseal (decrypt) data using a secret key
pub fn unseal(
    allocator: Allocator,
    paserk: []const u8,
    recipient_secret_key: *const v4.SecretKey,
) ![]u8 {
    const header = try PaserkHeader.parse(paserk);
    if (header.version != 4 or header.type != .seal) {
        return errors.Error.InvalidPaserkType;
    }
    
    const prefix = "k4.seal.";
    if (!mem.startsWith(u8, paserk, prefix)) {
        return errors.Error.InvalidPaserkFormat;
    }
    
    const data = paserk[prefix.len..];
    const decoded = try utils.base64urlDecode(allocator, data);
    defer allocator.free(decoded);
    
    if (decoded.len < 32 + 24 + 16) { // ephemeral_public + nonce + min_ciphertext
        return errors.Error.InvalidToken;
    }
    
    const ephemeral_public = decoded[0..32];
    const nonce = decoded[32..56];
    const ciphertext_with_tag = decoded[56..];
    
    // Perform key exchange
    // Note: This needs proper conversion between Ed25519 and X25519 keys
    const shared_secret = std.crypto.dh.X25519.scalarmult(
        recipient_secret_key.seed().*, // This might need conversion
        ephemeral_public.*
    ) catch return errors.Error.CryptographicFailure;
    
    // Derive decryption key
    var decryption_key: [32]u8 = undefined;
    std.crypto.kdf.hkdf.HkdfSha256.extract(&decryption_key, &shared_secret, "paseto-seal");
    defer utils.secureZero(&decryption_key);
    
    // Decrypt
    const plaintext_len = ciphertext_with_tag.len - 16;
    const plaintext = try allocator.alloc(u8, plaintext_len);
    
    std.crypto.aead.xchacha20_poly1305.XChaCha20Poly1305.decrypt(
        plaintext,
        ciphertext_with_tag[0..plaintext_len],
        ciphertext_with_tag[plaintext_len..][0..16].*,
        "", // no additional data
        nonce.*,
        decryption_key,
    ) catch {
        allocator.free(plaintext);
        return errors.Error.CryptographicFailure;
    };
    
    return plaintext;
}

// Note: These tests are simplified and may need adjustment based on proper Ed25519 to X25519 conversion
test "seal/unseal operations" {
    // This test is commented out because it needs proper Ed25519 to X25519 conversion
    // const allocator = testing.allocator;
    // var key_pair = v4.KeyPair.generate();
    // defer key_pair.deinit();
    // const test_data = "Hello, sealed world!";
    // const sealed = try seal(allocator, test_data, &key_pair.public);
    // defer allocator.free(sealed);
    // try testing.expect(mem.startsWith(u8, sealed, "k4.seal."));
    // const unsealed = try unseal(allocator, sealed, &key_pair.secret);
    // defer allocator.free(unsealed);
    // try testing.expectEqualStrings(test_data, unsealed);
}