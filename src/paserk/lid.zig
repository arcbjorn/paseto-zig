const std = @import("std");
const mem = std.mem;
const Allocator = std.mem.Allocator;
const testing = std.testing;

const errors = @import("../errors.zig");
const utils = @import("../utils.zig");
const types = @import("types.zig");
const v4 = @import("../v4/mod.zig");

const PaserkHeader = types.PaserkHeader;
const LocalKey = v4.LocalKey;

/// Serialize a local key to PASERK format (k4.local.base64url(key))
pub fn serializeLocalKey(allocator: Allocator, key: *const LocalKey) ![]u8 {
    const header = PaserkHeader{ .version = 4, .type = .local };
    const header_str = try header.format(allocator);
    defer allocator.free(header_str);
    
    const encoded_key = try utils.base64urlEncode(allocator, key.bytes());
    defer allocator.free(encoded_key);
    
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ header_str, encoded_key });
}

/// Deserialize a local key from PASERK format
pub fn deserializeLocalKey(allocator: Allocator, paserk: []const u8) !LocalKey {
    const header = try PaserkHeader.parse(paserk);
    if (header.version != 4 or header.type != .local) {
        return errors.Error.InvalidPaserkType;
    }
    
    const prefix = "k4.local.";
    if (!mem.startsWith(u8, paserk, prefix)) {
        return errors.Error.InvalidPaserkFormat;
    }
    
    const data = paserk[prefix.len..];
    const decoded = try utils.base64urlDecode(allocator, data);
    defer allocator.free(decoded);
    
    return LocalKey.fromBytes(decoded);
}

test "local key serialization" {
    const allocator = testing.allocator;
    
    var original_key = LocalKey.generate();
    defer original_key.deinit();
    
    // Serialize
    const serialized = try serializeLocalKey(allocator, &original_key);
    defer allocator.free(serialized);
    
    try testing.expect(mem.startsWith(u8, serialized, "k4.local."));
    
    // Deserialize
    const deserialized = try deserializeLocalKey(allocator, serialized);
    
    // Verify round trip
    try testing.expectEqualSlices(u8, original_key.bytes(), deserialized.bytes());
}