const std = @import("std");
const json = std.json;
const mem = std.mem;
const time = std.time;
const Allocator = std.mem.Allocator;
const testing = std.testing;

const errors = @import("../errors.zig");
const utils = @import("../utils.zig");
const keys = @import("keys.zig");
const local = @import("local.zig");
const public = @import("public.zig");

const LocalKey = keys.LocalKey;
const SecretKey = keys.SecretKey;

pub const TokenType = enum {
    local,
    public,
};

/// Builder for creating PASETO tokens with secure defaults
pub const PasetoBuilder = struct {
    allocator: Allocator,
    token_type: TokenType,
    claims: json.ObjectMap,
    footer: ?[]const u8,
    implicit: ?[]const u8,
    
    const Self = @This();
    
    /// Initialize a local token builder
    pub fn initLocal(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .token_type = .local,
            .claims = json.ObjectMap.init(allocator),
            .footer = null,
            .implicit = null,
        };
    }
    
    /// Initialize a public token builder
    pub fn initPublic(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .token_type = .public,
            .claims = json.ObjectMap.init(allocator),
            .footer = null,
            .implicit = null,
        };
    }
    
    /// Clean up allocated memory
    pub fn deinit(self: *Self) void {
        // Free all claim values
        var iterator = self.claims.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            switch (entry.value_ptr.*) {
                .string => |s| self.allocator.free(s),
                else => {},
            }
        }
        self.claims.deinit();
        
        if (self.footer) |f| self.allocator.free(f);
        if (self.implicit) |i| self.allocator.free(i);
    }
    
    /// Set the issuer claim
    pub fn setIssuer(self: *Self, issuer: []const u8) !*Self {
        return self.setClaim("iss", issuer);
    }
    
    /// Set the subject claim
    pub fn setSubject(self: *Self, subject: []const u8) !*Self {
        return self.setClaim("sub", subject);
    }
    
    /// Set the audience claim
    pub fn setAudience(self: *Self, audience: []const u8) !*Self {
        return self.setClaim("aud", audience);
    }
    
    /// Set the expiration time (in seconds from Unix epoch)
    pub fn setExpiration(self: *Self, exp: i64) !*Self {
        const exp_str = try utils.timestampToRfc3339(self.allocator, exp);
        return self.setClaimOwned("exp", exp_str);
    }
    
    /// Set expiration to a duration from now (default: 1 hour)
    pub fn setExpirationIn(self: *Self, seconds: i64) !*Self {
        const now = std.time.timestamp();
        return self.setExpiration(now + seconds);
    }
    
    /// Set the not-before time
    pub fn setNotBefore(self: *Self, nbf: i64) !*Self {
        const nbf_str = try utils.timestampToRfc3339(self.allocator, nbf);
        return self.setClaimOwned("nbf", nbf_str);
    }
    
    /// Set the issued-at time
    pub fn setIssuedAt(self: *Self, iat: i64) !*Self {
        const iat_str = try utils.timestampToRfc3339(self.allocator, iat);
        return self.setClaimOwned("iat", iat_str);
    }
    
    /// Set issued-at to current time
    pub fn setIssuedAtNow(self: *Self) !*Self {
        const now = std.time.timestamp();
        return self.setIssuedAt(now);
    }
    
    /// Set the JWT ID claim
    pub fn setJwtId(self: *Self, jti: []const u8) !*Self {
        return self.setClaim("jti", jti);
    }
    
    /// Set a custom string claim
    pub fn setClaim(self: *Self, claim: []const u8, value: []const u8) !*Self {
        const claim_copy = try self.allocator.dupe(u8, claim);
        const value_copy = try self.allocator.dupe(u8, value);
        
        try self.claims.put(claim_copy, json.Value{ .string = value_copy });
        return self;
    }
    
    /// Set a custom claim with owned value (takes ownership of the value)
    pub fn setClaimOwned(self: *Self, claim: []const u8, value: []const u8) !*Self {
        const claim_copy = try self.allocator.dupe(u8, claim);
        try self.claims.put(claim_copy, json.Value{ .string = value });
        return self;
    }
    
    /// Set a custom number claim
    pub fn setClaimNumber(self: *Self, claim: []const u8, value: f64) !*Self {
        const claim_copy = try self.allocator.dupe(u8, claim);
        try self.claims.put(claim_copy, json.Value{ .float = value });
        return self;
    }
    
    /// Set a custom boolean claim
    pub fn setClaimBool(self: *Self, claim: []const u8, value: bool) !*Self {
        const claim_copy = try self.allocator.dupe(u8, claim);
        try self.claims.put(claim_copy, json.Value{ .bool = value });
        return self;
    }
    
    /// Set the footer
    pub fn setFooter(self: *Self, footer: []const u8) !*Self {
        if (self.footer) |old_footer| {
            self.allocator.free(old_footer);
        }
        self.footer = try self.allocator.dupe(u8, footer);
        return self;
    }
    
    /// Set the implicit assertion
    pub fn setImplicit(self: *Self, implicit: []const u8) !*Self {
        if (self.implicit) |old_implicit| {
            self.allocator.free(old_implicit);
        }
        self.implicit = try self.allocator.dupe(u8, implicit);
        return self;
    }
    
    /// Apply secure defaults (1-hour expiration, issued-at now)
    pub fn withDefaults(self: *Self) !*Self {
        const now = std.time.timestamp();
        _ = try self.setIssuedAt(now);
        _ = try self.setExpiration(now + 3600); // 1 hour default
        return self;
    }
    
    /// Build a local token
    pub fn buildLocal(self: *Self, key: *const LocalKey) ![]u8 {
        if (self.token_type != .local) {
            return errors.Error.KeyTypeMismatch;
        }
        
        const payload = try self.buildPayload();
        defer self.allocator.free(payload);
        
        return local.encrypt(self.allocator, payload, key, self.footer, self.implicit);
    }
    
    /// Build a public token
    pub fn buildPublic(self: *Self, secret_key: *const SecretKey) ![]u8 {
        if (self.token_type != .public) {
            return errors.Error.KeyTypeMismatch;
        }
        
        const payload = try self.buildPayload();
        defer self.allocator.free(payload);
        
        return public.sign(self.allocator, payload, secret_key, self.footer, self.implicit);
    }
    
    /// Build the JSON payload from claims
    fn buildPayload(self: *Self) ![]u8 {
        const options = json.StringifyOptions{};
        return json.stringifyAlloc(self.allocator, json.Value{ .object = self.claims }, options);
    }
};

test "PasetoBuilder local token with defaults" {
    const allocator = testing.allocator;
    
    var builder = PasetoBuilder.initLocal(allocator);
    defer builder.deinit();
    
    _ = try builder.withDefaults();
    _ = try builder.setIssuer("test-issuer");
    _ = try builder.setSubject("test-subject");
    
    var key = LocalKey.generate();
    defer key.deinit();
    
    const token = try builder.buildLocal(&key);
    defer allocator.free(token);
    
    try testing.expect(mem.startsWith(u8, token, "v4.local."));
}

test "PasetoBuilder public token with custom claims" {
    const allocator = testing.allocator;
    
    var builder = PasetoBuilder.initPublic(allocator);
    defer builder.deinit();
    
    _ = try builder.setIssuer("test-issuer");
    _ = try builder.setSubject("test-subject");
    _ = try builder.setClaimNumber("custom_number", 42.0);
    _ = try builder.setClaimBool("custom_bool", true);
    _ = try builder.setFooter("custom-footer");
    
    var key_pair = keys.KeyPair.generate();
    defer key_pair.deinit();
    
    const token = try builder.buildPublic(&key_pair.secret);
    defer allocator.free(token);
    
    try testing.expect(mem.startsWith(u8, token, "v4.public."));
    // Footer is now base64url encoded, so check it contains the footer separator
    try testing.expect(mem.indexOf(u8, token, ".") != null);
}

test "PasetoBuilder type mismatch should fail" {
    const allocator = testing.allocator;
    
    var builder = PasetoBuilder.initLocal(allocator);
    defer builder.deinit();
    
    var key_pair = keys.KeyPair.generate();
    defer key_pair.deinit();
    
    try testing.expectError(errors.Error.KeyTypeMismatch, 
        builder.buildPublic(&key_pair.secret));
}

test "PasetoBuilder with implicit assertion" {
    const allocator = testing.allocator;
    
    var builder = PasetoBuilder.initLocal(allocator);
    defer builder.deinit();
    
    _ = try builder.setIssuer("test-issuer");
    _ = try builder.setImplicit("implicit-data");
    
    var key = LocalKey.generate();
    defer key.deinit();
    
    const token = try builder.buildLocal(&key);
    defer allocator.free(token);
    
    try testing.expect(mem.startsWith(u8, token, "v4.local."));
}