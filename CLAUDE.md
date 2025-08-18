# PASETO Zig - Project Documentation

## Project Overview

**PASETO Zig** is a comprehensive, security-focused implementation of PASETO (Platform-Agnostic Security Tokens) v4 and PASERK (Platform-Agnostic Serialized Keys) for the Zig programming language. This library provides a type-safe, memory-safe alternative to JWT tokens with modern cryptographic standards.

### Key Features
- **PASETO v4.local**: Symmetric encryption using ChaCha20-Poly1305 with BLAKE2b key derivation
- **PASETO v4.public**: Digital signatures using Ed25519
- **PASERK**: Complete key management, serialization, and wrapping
- **Builder/Parser Patterns**: Secure-by-default APIs with misuse resistance
- **Type Safety**: Strict separation of key types to prevent confusion attacks
- **Memory Safety**: Secure key handling with explicit zeroing

## Architecture

### Module Structure
```
src/
├── paseto.zig          # Main entry point, re-exports
├── errors.zig          # Comprehensive error types
├── utils.zig           # PAE, base64url, cryptographic utilities
├── v4/                 # PASETO v4 implementation
│   ├── mod.zig         # Module exports
│   ├── keys.zig        # Key types (LocalKey, SecretKey, PublicKey, KeyPair)
│   ├── local.zig       # v4.local token encryption/decryption
│   ├── public.zig      # v4.public token signing/verification
│   ├── builder.zig     # Secure token creation with defaults
│   └── parser.zig      # Token verification and claims extraction
└── paserk/             # PASERK key management
    ├── mod.zig         # Module exports
    ├── types.zig       # Core PASERK types and identifiers
    ├── lid.zig         # Local key serialization
    ├── sid.zig         # Public/secret key serialization
    ├── wrap.zig        # Key wrapping with other keys
    ├── seal.zig        # Public-key encryption (partial implementation)
    └── password.zig    # Password-based key encryption (PBKDF2)
```

### Security Design Principles

1. **Type Safety**: Separate types for `LocalKey`, `SecretKey`, and `PublicKey` prevent misuse
2. **Secure Defaults**: 1-hour expiration, automatic issued-at timestamps
3. **Memory Safety**: Explicit zeroing of sensitive data using `utils.secureZero()`
4. **Constant-Time Operations**: Cryptographic comparisons use `constantTimeEqual()`
5. **Pre-Authentication Encoding (PAE)**: Ensures integrity of all token components

## Implementation Details

### Cryptographic Algorithms

#### PASETO v4.local
- **Encryption**: ChaCha20-Poly1305 AEAD (simplified from XChaCha20 for Zig compatibility)
- **Key Derivation**: BLAKE2b with domain separation
- **Authentication**: Poly1305 MAC over PAE-encoded data
- **Nonce**: 32-byte random nonce (24 bytes used for ChaCha20)

#### PASETO v4.public
- **Signatures**: Ed25519
- **Key Format**: 32-byte seed + 32-byte public key (64 bytes total)
- **Authentication**: Ed25519 signature over PAE-encoded data

#### PASERK
- **Key Identifiers**: BLAKE2b-224 hash of key + domain string
- **Key Wrapping**: ChaCha20-Poly1305 with random nonces
- **Password-Based**: PBKDF2-HMAC-SHA256 with configurable iterations
- **Serialization**: Base64url encoding with versioned headers

### API Design

#### Builder Pattern
```zig
var builder = paseto.createLocalBuilder(allocator);
defer builder.deinit();

_ = try builder.withDefaults();              // 1-hour expiration, issued-at now
_ = try builder.setIssuer("api-server");     // Standard JWT claims
_ = try builder.setSubject("user-123");
_ = try builder.setAudience("client-app");
_ = try builder.setClaimNumber("user_id", 12345);  // Custom claims
_ = try builder.setFooter("public-metadata");      // Additional authenticated data
_ = try builder.setImplicit("secret-context");     // Implicit assertions

const token = try builder.buildLocal(&key);
```

#### Parser Pattern
```zig
var parser = paseto.createParser(allocator);
_ = parser.setValidateTime(true);    // Enable time validation
_ = parser.setLeeway(60);            // 60-second clock skew tolerance

var claims = try parser.parseLocal(token, &key, footer, implicit);
defer claims.deinit(allocator);

// Access standard claims
const issuer = claims.issuer;        // ?[]const u8
const expiration = claims.expiration; // ?i64

// Access custom claims
const user_id = claims.custom.get("user_id");  // ?json.Value
```

## Build Configuration

### Zig Build System
The project uses Zig's native build system with:
- **Static Library**: `libpaseto.a` for linking
- **Module Export**: For use as dependency
- **Test Suite**: Comprehensive unit and integration tests
- **Example Program**: Demonstrates all major features

### Build Targets
```bash
zig build           # Build library and example
zig build test      # Run test suite
zig build example   # Run demonstration program
```

## Testing Strategy

### Test Coverage
- **Unit Tests**: Each module has dedicated test functions
- **Integration Tests**: End-to-end token creation and verification
- **Security Tests**: Key confusion prevention, timing attacks
- **PASERK Tests**: Key serialization and round-trip verification

### Test Vectors
The implementation includes tests based on official PASETO test vectors where applicable, ensuring compatibility with other PASETO implementations.

## Performance Considerations

### Memory Management
- **Explicit Allocation**: All operations require allocator parameter
- **RAII Pattern**: Defer statements ensure proper cleanup
- **Secure Deletion**: Sensitive data explicitly zeroed
- **Minimal Copying**: Direct buffer operations where possible

### Cryptographic Performance
- **Native Algorithms**: Uses Zig standard library crypto implementations
- **Efficient Encoding**: PAE minimizes serialization overhead
- **Streaming Operations**: Large payloads handled efficiently

## Security Considerations

### Threat Model
- **Key Confusion**: Type system prevents wrong key usage
- **Timing Attacks**: Constant-time comparisons for authentication
- **Memory Disclosure**: Explicit zeroing of sensitive data
- **Token Tampering**: PAE ensures integrity of all components

### Best Practices
1. **Key Storage**: Use PASERK for secure key serialization
2. **Time Validation**: Enable for production deployments
3. **Transport Security**: Always use TLS for token transmission
4. **Token Lifetime**: Use short expiration times (≤1 hour)
5. **Implicit Assertions**: Include context-specific data when needed

## Known Limitations

### Current Implementation Status
1. **Crypto API Compatibility**: Some adjustments needed for specific Zig version
2. **XChaCha20**: Simplified to ChaCha20 due to standard library limitations
3. **PASERK Seal**: Partial implementation (X25519 key exchange needs refinement)
4. **Time Handling**: Simplified timestamp functions for demonstration

### Future Improvements
- Full XChaCha20-Poly1305 implementation
- Complete PASERK seal operations
- Proper RFC3339 timestamp handling
- Performance optimizations
- Additional test vectors

## Development Guidelines

### Code Style
- **Memory Safety**: Always use defer for cleanup
- **Error Handling**: Comprehensive error types with context
- **Type Safety**: Leverage Zig's type system for security
- **Testing**: Every public function should have tests

### Security Review Process
1. **Cryptographic Correctness**: Verify against specifications
2. **Memory Safety**: Check for leaks and use-after-free
3. **Timing Safety**: Ensure constant-time operations
4. **API Misuse**: Test for prevention of common mistakes

---

### Git Commit Guidelines

**Rules**:
- NEVER add co-authors, "Generated with" tags, or metadata
- Focus on what changed and why, not how or who
- Use present tense ("add feature" not "added feature")
- Use lowercase for description
- No period at the end of description
- Keep commit message under 50 characters
- Keep description line under 72 characters

Follow [Conventional Commits v1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):

**Format**: `type(scope): description`

**Required components**:
- `type`: feat, fix, docs, style, refactor, test, chore
- `scope`: component/area affected (paseto, paserk, v4, crypto, etc.)
- `description`: concise description of changes

**Examples**:
- `feat(v4): add local token encryption with chacha20`
- `fix(paserk): resolve key serialization padding issue`
- `docs(readme): update installation instructions`
- `refactor(crypto): extract common key derivation`

### Always Use Standard CLI Tools for Initialization
- **Zig**: `zig init`
- **ALWAYS use official scaffolding tools**
- **Never manually create build.zig files**

# Using Gemini CLI for Large Codebase Analysis

When analyzing large codebases or multiple files that might exceed context limits, use the Gemini CLI with its massive context window. Use `gemini -p` to leverage Google Gemini's large context capacity.

## File and Directory Inclusion Syntax

Use the `@` syntax to include files and directories in your Gemini prompts:

**Examples**:
```bash
# Single file analysis:
gemini -p "@src/paseto.zig Explain this file's purpose and structure"

# Multiple files:
gemini -p "@src/v4/local.zig @src/v4/public.zig Compare the encryption vs signing implementations"

# Entire directory:
gemini -p "@src/v4/ Analyze the PASETO v4 implementation architecture"

# Security analysis:
gemini -p "@src/ Check for timing attack vulnerabilities in cryptographic operations"

# PASERK implementation verification:
gemini -p "@src/paserk/ Verify PASERK key wrapping follows the specification correctly"
```

When to Use Gemini CLI:
- Analyzing entire PASETO implementation
- Verifying cryptographic correctness across modules
- Security auditing of key handling
- Architecture review of token parsing/building