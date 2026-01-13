# Technical Implementation Details

## PS256 Algorithm

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

- **rsa (0.9)**: Provides RSA key generation and PSS signing/verification
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
2. Signing with RSA-PSS-SHA256
3. Base64url encoding the signature bytes

## Code Structure

### Key Generation (`generate_keypair`)

1. Generate RSA private key using cryptographically secure RNG
2. Derive public key from private key
3. Encode both keys in PKCS#8 PEM format
4. Write to files

**Security Note**: The private key should be protected with appropriate file permissions (e.g., `chmod 600`).

### Token Creation (`create_token`)

1. Load private key from PEM file
2. Build JWT header with PS256 algorithm
3. Create payload with:
   - `preferred_username`: User identifier
   - `iat`: Issued at timestamp (current Unix time)
   - `exp`: Expiration timestamp (iat + expiry_seconds)
   - Additional custom claims (if provided)
4. Serialize header and payload to JSON
5. Base64url encode both
6. Create signing input by concatenating: `header_b64 + "." + payload_b64`
7. Sign with RSA-PSS using SHA-256
8. Base64url encode signature
9. Return complete JWT: `header_b64 + "." + payload_b64 + "." + signature_b64`

### Token Verification (`verify_token`)

1. Split token into three parts
2. Decode and parse header, verify algorithm is PS256
3. Decode payload and parse claims
4. Decode signature bytes
5. Load public key from PEM file
6. Reconstruct signing input from header and payload
7. Verify signature using RSA-PSS with SHA-256
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
- Prevents algorithm substitution attacks (e.g., switching from PS256 to none)

### Key Size
- Minimum 2048 bits recommended
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

| Algorithm | Type | Hash | Security |
|-----------|------|------|----------|
| HS256 | HMAC | SHA-256 | Symmetric (shared secret) |
| RS256 | RSA PKCS#1 v1.5 | SHA-256 | Asymmetric (deterministic) |
| PS256 | RSA-PSS | SHA-256 | Asymmetric (probabilistic) |
| ES256 | ECDSA | SHA-256 | Asymmetric (smaller keys) |

**PS256 Advantages:**
- More secure than RS256 (provable security)
- Asymmetric (public key verification)
- Industry standard (RFC 7518)

**PS256 Disadvantages:**
- Slightly slower than RS256
- Larger keys than ECDSA
- More complex implementation

## Standards Compliance

- **RFC 7519**: JSON Web Token (JWT)
- **RFC 7518**: JSON Web Algorithms (JWA) - PS256 specification
- **RFC 8017**: PKCS #1 v2.2 - RSA-PSS
- **RFC 4648**: Base64url encoding
