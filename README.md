# jwtasym - JWT Asymmetric Token Tool (ES256 & PS256)

A command-line tool for creating and verifying JWT tokens using ES256 (ECDSA with P-256 and SHA-256) or PS256 (RSA-PSS with SHA-256) algorithms.

Disclaimer: This complete tool with its documentation was written by Claude Code.

## Features

- Generate ECDSA keypairs for ES256 signing (default) or RSA keypairs for PS256 signing
- Create JWT tokens with custom claims using either algorithm
- Verify JWT token signatures and expiry for both algorithms
- Support for additional custom claims
- Easy algorithm selection via command-line switches

## Building

```bash
cargo build --release
```

## Usage

### 1. Generate a Keypair

Generate a new ECDSA keypair for ES256 (default algorithm):

```bash
cargo run -- keygen
```

Generate an RSA keypair for PS256:

```bash
cargo run -- keygen --algorithm ps256
```

With custom options (ES256, note: bits parameter is ignored for ES256 as it always uses P-256):

```bash
cargo run -- keygen --algorithm es256 --private-key ec_private.pem --public-key ec_public.pem
```

With custom options (PS256):

```bash
cargo run -- keygen --algorithm ps256 --private-key my_private.pem --public-key my_public.pem --bits 4096
```

### 2. Create a JWT Token

Create a token for a user with 1-hour expiry (default ES256):

```bash
cargo run -- create --username alice --expiry 3600
```

Create a token using PS256:

```bash
cargo run -- create --algorithm ps256 --username alice --expiry 3600
```

With additional claims (ES256):

```bash
cargo run -- create --username bob --expiry 7200 --claims '{"role":"admin","email":"bob@example.com"}'
```

With custom private key and PS256:

```bash
cargo run -- create --algorithm ps256 --username charlie --expiry 3600 --private-key my_private.pem
```

### 3. Verify a JWT Token

Verify a token's signature and check expiry (algorithm is auto-detected from token header):

```bash
cargo run -- verify "eyJhbGc..."
```

With custom public key (ES256):

```bash
cargo run -- verify "eyJhbGc..." --public-key ec_public.pem
```

Verify a PS256 token:

```bash
cargo run -- verify "eyJhbGc..." --public-key my_public.pem
```

## Examples

### Complete Workflow (ES256 - Default)

```bash
# Generate ECDSA keypair
cargo run -- keygen

# Create a token
TOKEN=$(cargo run -- create --username alice --expiry 3600 | tail -1)

# Verify the token
cargo run -- verify "$TOKEN"
```

### Complete Workflow (PS256)

```bash
# Generate RSA keypair
cargo run -- keygen --algorithm ps256 --private-key rsa_private.pem --public-key rsa_public.pem

# Create a token
TOKEN=$(cargo run -- create --algorithm ps256 --username alice --expiry 3600 --private-key rsa_private.pem | tail -1)

# Verify the token
cargo run -- verify "$TOKEN" --public-key rsa_public.pem
```

### Token with Custom Claims

```bash
cargo run -- create \
  --username developer \
  --expiry 86400 \
  --claims '{"role":"developer","department":"engineering","level":3}'
```

## Algorithm Details

### ES256 (ECDSA) - Default
- **Algorithm**: ES256 (ECDSA using P-256 curve and SHA-256)
- **Key Format**: PEM-encoded PKCS#8
- **Curve**: P-256 (secp256r1)
- **Encoding**: URL-safe Base64 without padding
- **Advantages**: Smaller keys, faster verification, modern standard

### PS256 (RSA-PSS)
- **Algorithm**: PS256 (RSASSA-PSS using SHA-256 and MGF1 with SHA-256)
- **Key Format**: PEM-encoded PKCS#8
- **Default Key Size**: 2048 bits (configurable)
- **Encoding**: URL-safe Base64 without padding

## Token Structure

The JWT contains:
- `alg`: Either "PS256" or "ES256" depending on the algorithm used
- `typ`: Always "JWT"
- `preferred_username`: The username provided
- `iat`: Issued at timestamp (Unix epoch)
- `exp`: Expiration timestamp (Unix epoch)
- Additional custom claims (if provided)

## Testing

The project includes comprehensive unit tests and end-to-end tests.

### Run All Tests

```bash
cargo test
```

### Run Unit Tests Only

```bash
cargo test --bin jwtasym
```

### Run End-to-End Tests with Verbose Output

```bash
cargo test --test e2e_tests -- --nocapture
```

### Test Coverage

**Unit Tests** (in `src/main.rs`):
- JWT header and payload serialization/deserialization
- Base64 encoding/decoding
- PS256 token creation and verification
- ES256 token creation and verification
- Token verification with additional claims
- Invalid token format rejection
- Invalid signature detection
- Tampered token detection
- Unsupported algorithm handling
- Cross-algorithm verification failure

**End-to-End Tests** (in `tests/e2e_tests.rs`):
- ES256: keypair generation → token creation → correct verification → wrong key rejection
- PS256: keypair generation → token creation → correct verification → wrong key rejection
- Token tampering detection (payload, signature, format)
- Additional claims preservation
- File-based key storage and loading

All tests verify that:
1. Valid tokens are accepted
2. Invalid/tampered tokens are rejected
3. Wrong keys cause verification to fail
4. Both ES256 and PS256 algorithms work correctly

## Dependencies

- `clap`: Command-line argument parsing
- `rsa`: RSA cryptography implementation (for PS256)
- `p256`: ECDSA P-256 curve implementation (for ES256)
- `ecdsa`: ECDSA signature algorithms
- `elliptic-curve`: Elliptic curve cryptography primitives
- `sha2`: SHA-256 hashing
- `base64`: Base64 encoding/decoding
- `serde`/`serde_json`: JSON serialization
- `rand`: Random number generation for signing
- `anyhow`: Error handling
