# Technical Implementation Details

## Supported Algorithms

### ES256 Algorithm (Default)

ES256 is ECDSA (Elliptic Curve Digital Signature Algorithm) using:
- P-256 curve (also known as secp256r1 or prime256v1)
- SHA-256 for hashing
- Signature scheme as defined in FIPS 186-4

ES256 advantages:
1. Smaller key sizes (256-bit keys provide similar security to 3072-bit RSA)
2. Faster signature generation and verification
3. Lower bandwidth requirements for key distribution
4. Modern cryptographic standard recommended by NIST
5. Widely supported in contemporary systems

### PS256 Algorithm

PS256 is RSASSA-PSS (RSA Signature Scheme with Appendix - Probabilistic Signature Scheme) using:
- SHA-256 for hashing
- MGF1 with SHA-256 for mask generation
- Salt length equal to hash length (32 bytes)

This is more secure than traditional PKCS#1 v1.5 signatures (RS256) because:
1. It uses probabilistic padding (different signatures for the same message)
2. It has provable security properties
3. It's resistant to certain attack vectors

## Key Components

### Dependencies

- **p256 (0.13)**: ECDSA P-256 curve implementation for ES256
- **ecdsa (0.16)**: ECDSA signature algorithms
- **elliptic-curve (0.13)**: Elliptic curve cryptography primitives
- **rsa (0.9)**: RSA key generation and PSS signing/verification for PS256
- **sha2 (0.10)**: SHA-256 hashing implementation
- **base64 (0.22)**: URL-safe base64 encoding without padding (RFC 4648)
- **serde/serde_json (1.0)**: JSON serialization for JWT header and payload
- **clap (4.5)**: Command-line interface with derive macros
- **rand (0.8)**: Secure random number generation for signing
- **anyhow (1.0)**: Error handling with context

### JWT Structure

A JWT consists of three base64url-encoded parts separated by dots:

```
<header>.<payload>.<signature>
```

#### Header
```json
{
  "alg": "ES256",
  "typ": "JWT"
}
```

Or for PS256:
```json
{
  "alg": "PS256",
  "typ": "JWT"
}
```

#### Payload
```json
{
  "preferred_username": "username",
  "iat": 1640995200,
  "exp": 1640998800,
  "custom_claim": "custom_value"
}
```

#### Signature
The signature is created by:
1. Creating the signing input: `base64url(header) + "." + base64url(payload)`
2. Signing with ECDSA-P256-SHA256 (ES256) or RSA-PSS-SHA256 (PS256)
3. Base64url encoding the signature bytes

## Code Structure

### Key Generation (`generate_keypair`)

**For ES256 (default):**
1. Generate ECDSA P-256 private key using cryptographically secure RNG
2. Derive public key from private key
3. Encode both keys in PKCS#8 PEM format
4. Write to files

**For PS256:**
1. Generate RSA private key using cryptographically secure RNG (default 2048 bits)
2. Derive public key from private key
3. Encode both keys in PKCS#8 PEM format
4. Write to files

**Security Note**: The private key should be protected with appropriate file permissions (e.g., `chmod 600`).

### Token Creation (`create_token`)

1. Load private key from PEM file
2. Build JWT header with algorithm (ES256 or PS256)
3. Create payload with:
   - `preferred_username`: User identifier
   - `iat`: Issued at timestamp (current Unix time)
   - `exp`: Expiration timestamp (iat + expiry_seconds)
   - Additional custom claims (if provided)
4. Serialize header and payload to JSON
5. Base64url encode both
6. Create signing input by concatenating: `header_b64 + "." + payload_b64`
7. Sign with ECDSA-P256-SHA256 (ES256) or RSA-PSS-SHA256 (PS256)
8. Base64url encode signature
9. Return complete JWT: `header_b64 + "." + payload_b64 + "." + signature_b64`

### Token Verification (`verify_token`)

1. Split token into three parts
2. Decode and parse header, verify algorithm is ES256 or PS256
3. Decode payload and parse claims
4. Decode signature bytes
5. Load public key from PEM file
6. Reconstruct signing input from header and payload
7. Verify signature using ECDSA-P256-SHA256 (ES256) or RSA-PSS-SHA256 (PS256)
8. Check token expiry against current time
9. Display results and claims

## Security Considerations

### Key Storage
- Private keys should be stored securely with restricted file permissions
- Consider using hardware security modules (HSMs) for production
- Never commit private keys to version control

### Token Expiry
- Use reasonable expiry times (hours, not days)
- Always verify expiry time when validating tokens
- Consider implementing token refresh mechanisms

### Algorithm Verification
- Always verify the algorithm in the token header matches expected algorithm
- Prevents algorithm substitution attacks (e.g., switching from ES256/PS256 to none or HS256)

### Key Size

**ES256:**
- Fixed at 256 bits (P-256 curve)
- Provides security equivalent to ~3072-bit RSA
- No configuration needed

**PS256:**
- Minimum 2048 bits recommended (default)
- 4096 bits for higher security requirements
- Larger keys increase computational cost

## Base64url Encoding

Uses URL-safe alphabet and no padding:
- Standard Base64: `+` and `/`
- Base64url: `-` and `_`
- No padding `=` characters

This makes JWTs safe for use in URLs and HTTP headers.

## Error Handling

The program uses `anyhow::Result` for error propagation with context:
- File I/O errors include file paths
- Cryptographic errors include operation details
- JSON parsing errors include what was being parsed

All errors are propagated to the main function for consistent error reporting.

## Comparison with Other Algorithms

| Algorithm | Type | Hash | Security | Key Size |
|-----------|------|------|----------|----------|
| HS256 | HMAC | SHA-256 | Symmetric (shared secret) | Variable |
| RS256 | RSA PKCS#1 v1.5 | SHA-256 | Asymmetric (deterministic) | 2048-4096 bits |
| PS256 | RSA-PSS | SHA-256 | Asymmetric (probabilistic) | 2048-4096 bits |
| ES256 | ECDSA | SHA-256 | Asymmetric (elliptic curve) | 256 bits |

**ES256 Advantages (Default):**
- Smallest key size (256 bits)
- Fastest verification performance
- Modern cryptographic standard
- Recommended by NIST and industry
- Lower bandwidth for key distribution
- Asymmetric (public key verification)

**ES256 Disadvantages:**
- Requires proper PRNG for secure signing
- More sensitive to implementation errors

**PS256 Advantages:**
- More secure than RS256 (provable security)
- Asymmetric (public key verification)
- Well-established standard (RFC 7518)
- Compatible with existing RSA infrastructure

**PS256 Disadvantages:**
- Larger keys than ES256 (2048+ bits)
- Slower than ES256 for most operations
- Higher computational cost

## Standards Compliance

- **RFC 7519**: JSON Web Token (JWT)
- **RFC 7518**: JSON Web Algorithms (JWA) - ES256 and PS256 specifications
- **FIPS 186-4**: Digital Signature Standard (DSS) - ECDSA specification
- **RFC 8017**: PKCS #1 v2.2 - RSA-PSS
- **RFC 5480**: Elliptic Curve Cryptography Subject Public Key Information
- **RFC 4648**: Base64url encoding
