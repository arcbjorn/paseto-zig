# PASETO Zig

A secure, type-safe implementation of PASETO (Platform-Agnostic Security Tokens) v4 and PASERK (Platform-Agnostic Serialized Keys) for Zig.

## Features

- **PASETO v4.local**: Symmetric encryption with ChaCha20-Poly1305
- **PASETO v4.public**: Digital signatures with Ed25519
- **PASERK**: Complete key management and serialization
- **Builder Pattern**: Secure token creation with sensible defaults
- **Parser Pattern**: Safe token verification and claims extraction
- **Type Safety**: Prevent key type confusion attacks
- **Memory Safe**: Secure key handling with explicit zeroing

## Quick Start

```zig
const std = @import("std");
const paseto = @import("paseto");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Generate keys
    var local_key = paseto.LocalKey.generate();
    defer local_key.deinit();

    // Create token with secure defaults (1-hour expiration)
    var builder = paseto.createLocalBuilder(allocator);
    defer builder.deinit();

    _ = try builder.withDefaults();
    _ = try builder.setIssuer("myapp");
    _ = try builder.setSubject("user123");

    const token = try builder.buildLocal(&local_key);
    defer allocator.free(token);

    // Verify token
    var parser = paseto.createParser(allocator);
    var claims = try parser.parseLocal(token, &local_key, null, null);
    defer claims.deinit(allocator);

    std.debug.print("Issuer: {s}\n", .{claims.issuer.?});
}
```

## Installation

Add to your `build.zig`:

```zig
const paseto = b.dependency("paseto", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("paseto", paseto.module("paseto"));
```

## Token Types

### Local Tokens (v4.local)
Symmetric encryption for trusted environments:
- **Algorithm**: ChaCha20-Poly1305 AEAD
- **Key Derivation**: BLAKE2b
- **Use Case**: Single application or trusted network

### Public Tokens (v4.public)  
Digital signatures for distributed systems:
- **Algorithm**: Ed25519
- **Use Case**: Multiple services, public verification

## PASERK Support

Complete key management with serialization formats:

```zig
// Serialize keys
const local_paserk = try paseto.paserk.serializeLocalKey(allocator, &key);
const public_paserk = try paseto.paserk.serializePublicKey(allocator, &keypair.public);

// Key identifiers
const lid = paseto.LocalKeyId.fromLocalKey(key.bytes());
const lid_paserk = try lid.serialize(allocator);

// Password-based key wrapping
const wrapped = try paseto.paserk.password.wrapLocalKeyWithPassword(
    allocator, &key, "password", .{}
);
```

## Security Features

- **Constant-time comparisons** prevent timing attacks
- **Secure memory handling** with explicit key zeroing
- **Type-safe APIs** prevent key misuse
- **Secure defaults**: 1-hour expiration, automatic timestamps
- **Footer and implicit assertion** support for additional authenticated data

## API Overview

### Core Functions
- `createLocalBuilder()` / `createPublicBuilder()` - Token creation
- `createParser()` - Token verification
- `LocalKey.generate()` / `KeyPair.generate()` - Key generation

### Builder Methods
- `withDefaults()` - Apply secure defaults
- `setIssuer()`, `setSubject()`, `setAudience()` - Standard claims
- `setExpiration()`, `setIssuedAt()` - Time-based claims
- `setClaim()`, `setClaimNumber()` - Custom claims
- `setFooter()`, `setImplicit()` - Additional authenticated data

### Parser Methods  
- `parseLocal()` / `parsePublic()` - Token verification
- `setValidateTime()` - Enable/disable time validation
- `setLeeway()` - Clock skew tolerance

## Testing

```bash
zig build test    # Run test suite
zig build example # Run example program
```

## Security Considerations

- **Key Management**: Store keys securely, use PASERK for serialization
- **Time Validation**: Enable for production use
- **Transport Security**: Use HTTPS for token transmission
- **Token Lifetime**: Use appropriate expiration times
- **Implicit Assertions**: Include context-specific data when needed

## License

MIT License - see LICENSE file for details.

## Contributing

Issues and pull requests welcome. Please ensure all tests pass and follow existing code style.