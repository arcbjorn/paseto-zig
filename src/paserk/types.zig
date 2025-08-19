const std = @import("std");
const mem = std.mem;
const Allocator = std.mem.Allocator;
const testing = std.testing;

const errors = @import("../errors.zig");
const utils = @import("../utils.zig");

/// PASERK type identifier
pub const PaserkType = enum {
    lid,          // Local key identifier
    sid,          // Secret key identifier  
    local,        // Local key
    public,       // Public key
    secret,       // Secret key
    local_wrap,   // Wrapped local key
    secret_wrap,  // Wrapped secret key
    seal,         // Sealed data
    local_pw,     // Password-wrapped local key
    secret_pw,    // Password-wrapped secret key
    
    const Self = @This();
    
    /// Convert type to string representation
    pub fn toString(self: Self) []const u8 {
        return switch (self) {
            .lid => "lid",
            .sid => "sid",
            .local => "local",
            .public => "public",
            .secret => "secret",
            .local_wrap => "local-wrap",
            .secret_wrap => "secret-wrap",
            .seal => "seal",
            .local_pw => "local-pw",
            .secret_pw => "secret-pw",
        };
    }
    
    /// Parse type from string
    pub fn fromString(s: []const u8) !Self {
        if (mem.eql(u8, s, "lid")) return .lid;
        if (mem.eql(u8, s, "sid")) return .sid;
        if (mem.eql(u8, s, "local")) return .local;
        if (mem.eql(u8, s, "public")) return .public;
        if (mem.eql(u8, s, "secret")) return .secret;
        if (mem.eql(u8, s, "local-wrap")) return .local_wrap;
        if (mem.eql(u8, s, "secret-wrap")) return .secret_wrap;
        if (mem.eql(u8, s, "seal")) return .seal;
        if (mem.eql(u8, s, "local-pw")) return .local_pw;
        if (mem.eql(u8, s, "secret-pw")) return .secret_pw;
        return errors.Error.InvalidPaserkType;
    }
};

/// PASERK header structure
pub const PaserkHeader = struct {
    version: u8,
    type: PaserkType,
    
    const Self = @This();
    
    /// Format: k[version].[type].
    pub fn format(self: Self, allocator: Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "k{d}.{s}.", .{ self.version, self.type.toString() });
    }
    
    /// Parse header from PASERK string
    pub fn parse(paserk: []const u8) !Self {
        if (paserk.len < 4 or paserk[0] != 'k') {
            return errors.Error.InvalidPaserkFormat;
        }
        
        // Find first dot
        const first_dot = mem.indexOf(u8, paserk[1..], ".") orelse 
            return errors.Error.InvalidPaserkFormat;
        
        // Parse version
        const version_str = paserk[1..first_dot + 1];
        const version = std.fmt.parseInt(u8, version_str, 10) catch 
            return errors.Error.InvalidPaserkVersion;
        
        // Find second dot
        const second_dot_start = first_dot + 2;
        const second_dot = mem.indexOf(u8, paserk[second_dot_start..], ".") orelse 
            return errors.Error.InvalidPaserkFormat;
        
        // Parse type
        const type_str = paserk[second_dot_start..second_dot_start + second_dot];
        const paserk_type = try PaserkType.fromString(type_str);
        
        return Self{
            .version = version,
            .type = paserk_type,
        };
    }
};

/// Local key identifier (28 bytes)
pub const LocalKeyId = struct {
    id: [28]u8,
    
    const Self = @This();
    
    /// Generate ID from local key using BLAKE2b
    pub fn fromLocalKey(key: []const u8) Self {
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update("paseto-local-key-id");
        hasher.update(key);
        
        var full_hash: [32]u8 = undefined;
        hasher.final(&full_hash);
        
        var id: [28]u8 = undefined;
        @memcpy(&id, full_hash[0..28]);
        return Self{ .id = id };
    }
    
    /// Get the raw ID bytes
    pub fn bytes(self: *const Self) *const [28]u8 {
        return &self.id;
    }
    
    /// Serialize to PASERK format
    pub fn serialize(self: *const Self, allocator: Allocator) ![]u8 {
        const header = PaserkHeader{ .version = 4, .type = .lid };
        const header_str = try header.format(allocator);
        defer allocator.free(header_str);
        
        const encoded_data = try utils.base64urlEncode(allocator, &self.id);
        defer allocator.free(encoded_data);
        
        return std.fmt.allocPrint(allocator, "{s}{s}", .{ header_str, encoded_data });
    }
    
    /// Deserialize from PASERK format
    pub fn deserialize(allocator: Allocator, paserk: []const u8) !Self {
        const header = try PaserkHeader.parse(paserk);
        if (header.version != 4 or header.type != .lid) {
            return errors.Error.InvalidPaserkType;
        }
        
        // Find data part after "k4.lid."
        const prefix = "k4.lid.";
        if (!mem.startsWith(u8, paserk, prefix)) {
            return errors.Error.InvalidPaserkFormat;
        }
        
        const data = paserk[prefix.len..];
        const decoded = try utils.base64urlDecode(allocator, data);
        defer allocator.free(decoded);
        
        if (decoded.len != 28) {
            return errors.Error.InvalidKeyLength;
        }
        
        var id: [28]u8 = undefined;
        @memcpy(&id, decoded[0..28]);
        return Self{ .id = id };
    }
};

/// Secret key identifier (28 bytes)
pub const SecretKeyId = struct {
    id: [28]u8,
    
    const Self = @This();
    
    /// Generate ID from secret key using BLAKE2b
    pub fn fromSecretKey(key: []const u8) Self {
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update("paseto-secret-key-id");
        hasher.update(key);
        
        var full_hash: [32]u8 = undefined;
        hasher.final(&full_hash);
        
        var id: [28]u8 = undefined;
        @memcpy(&id, full_hash[0..28]);
        return Self{ .id = id };
    }
    
    /// Get the raw ID bytes
    pub fn bytes(self: *const Self) *const [28]u8 {
        return &self.id;
    }
    
    /// Serialize to PASERK format
    pub fn serialize(self: *const Self, allocator: Allocator) ![]u8 {
        const header = PaserkHeader{ .version = 4, .type = .sid };
        const header_str = try header.format(allocator);
        defer allocator.free(header_str);
        
        const encoded_data = try utils.base64urlEncode(allocator, &self.id);
        defer allocator.free(encoded_data);
        
        return std.fmt.allocPrint(allocator, "{s}{s}", .{ header_str, encoded_data });
    }
    
    /// Deserialize from PASERK format
    pub fn deserialize(allocator: Allocator, paserk: []const u8) !Self {
        const header = try PaserkHeader.parse(paserk);
        if (header.version != 4 or header.type != .sid) {
            return errors.Error.InvalidPaserkType;
        }
        
        const prefix = "k4.sid.";
        if (!mem.startsWith(u8, paserk, prefix)) {
            return errors.Error.InvalidPaserkFormat;
        }
        
        const data = paserk[prefix.len..];
        const decoded = try utils.base64urlDecode(allocator, data);
        defer allocator.free(decoded);
        
        if (decoded.len != 28) {
            return errors.Error.InvalidKeyLength;
        }
        
        var id: [28]u8 = undefined;
        @memcpy(&id, decoded[0..28]);
        return Self{ .id = id };
    }
};

test "PaserkType string conversion" {
    try testing.expectEqualStrings("lid", PaserkType.lid.toString());
    try testing.expectEqualStrings("local-wrap", PaserkType.local_wrap.toString());
    
    try testing.expectEqual(PaserkType.lid, try PaserkType.fromString("lid"));
    try testing.expectEqual(PaserkType.local_wrap, try PaserkType.fromString("local-wrap"));
    try testing.expectError(errors.Error.InvalidPaserkType, PaserkType.fromString("invalid"));
}

test "PaserkHeader format and parse" {
    const allocator = testing.allocator;
    
    const header = PaserkHeader{ .version = 4, .type = .lid };
    const formatted = try header.format(allocator);
    defer allocator.free(formatted);
    
    try testing.expectEqualStrings("k4.lid.", formatted);
    
    const parsed = try PaserkHeader.parse("k4.lid.somedata");
    try testing.expectEqual(@as(u8, 4), parsed.version);
    try testing.expectEqual(PaserkType.lid, parsed.type);
}

test "LocalKeyId operations" {
    const allocator = testing.allocator;
    
    const key = "this-is-a-32-byte-test-key-data!";
    const lid = LocalKeyId.fromLocalKey(key);
    
    // Test serialization
    const serialized = try lid.serialize(allocator);
    defer allocator.free(serialized);
    
    try testing.expect(mem.startsWith(u8, serialized, "k4.lid."));
    
    // Test round trip
    const deserialized = try LocalKeyId.deserialize(allocator, serialized);
    try testing.expectEqualSlices(u8, lid.bytes(), deserialized.bytes());
}

test "SecretKeyId operations" {
    const allocator = testing.allocator;
    
    const key = "this-is-a-secret-key-for-testing";
    const sid = SecretKeyId.fromSecretKey(key);
    
    // Test serialization
    const serialized = try sid.serialize(allocator);
    defer allocator.free(serialized);
    
    try testing.expect(mem.startsWith(u8, serialized, "k4.sid."));
    
    // Test round trip
    const deserialized = try SecretKeyId.deserialize(allocator, serialized);
    try testing.expectEqualSlices(u8, sid.bytes(), deserialized.bytes());
}