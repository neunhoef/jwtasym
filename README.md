# JWT Tool (PS256 & ES256)

A command-line tool for creating and verifying JWT tokens using PS256 (RSA-PSS with SHA-256) or ES256 (ECDSA with P-256 and SHA-256) algorithms.

## Features

- Generate RSA keypairs for PS256 signing or ECDSA keypairs for ES256 signing
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

Generate a new RSA keypair for PS256 (default algorithm, default 2048 bits):

```bash
cargo run -- keygen
```

Generate an ECDSA keypair for ES256:

```bash
cargo run -- keygen --algorithm es256
```

With custom options (PS256):

```bash
cargo run -- keygen --algorithm ps256 --private-key my_private.pem --public-key my_public.pem --bits 4096
```

With custom options (ES256, note: bits parameter is ignored for ES256 as it always uses P-256):

```bash
cargo run -- keygen --algorithm es256 --private-key ec_private.pem --public-key ec_public.pem
```

### 2. Create a JWT Token

Create a token for a user with 1-hour expiry (default PS256):

```bash
cargo run -- create --username alice --expiry 3600
```

Create a token using ES256:

```bash
cargo run -- create --algorithm es256 --username alice --expiry 3600 --private-key ec_private.pem
```

With additional claims (PS256):

```bash
cargo run -- create --username bob --expiry 7200 --claims '{"role":"admin","email":"bob@example.com"}'
```

With custom private key and ES256:

```bash
cargo run -- create --algorithm es256 --username charlie --expiry 3600 --private-key ec_private.pem
```

### 3. Verify a JWT Token

Verify a token's signature and check expiry (algorithm is auto-detected from token header):

```bash
cargo run -- verify "eyJhbGc..."
```

With custom public key:

```bash
cargo run -- verify "eyJhbGc..." --public-key my_public.pem
```

Verify an ES256 token:

```bash
cargo run -- verify "eyJhbGc..." --public-key ec_public.pem
```

## Examples

### Complete Workflow (PS256)

```bash
# Generate RSA keypair
cargo run -- keygen

# Create a token
TOKEN=$(cargo run -- create --username alice --expiry 3600 | tail -1)

# Verify the token
cargo run -- verify "$TOKEN"
```

### Complete Workflow (ES256)

```bash
# Generate ECDSA keypair
cargo run -- keygen --algorithm es256 --private-key ec_private.pem --public-key ec_public.pem

# Create a token
TOKEN=$(cargo run -- create --algorithm es256 --username alice --expiry 3600 --private-key ec_private.pem | tail -1)

# Verify the token
cargo run -- verify "$TOKEN" --public-key ec_public.pem
```

### Token with Custom Claims

```bash
cargo run -- create \
  --username developer \
  --expiry 86400 \
  --claims '{"role":"developer","department":"engineering","level":3}'
```

## Algorithm Details

### PS256 (RSA-PSS)
- **Algorithm**: PS256 (RSASSA-PSS using SHA-256 and MGF1 with SHA-256)
- **Key Format**: PEM-encoded PKCS#8
- **Default Key Size**: 2048 bits (configurable)
- **Encoding**: URL-safe Base64 without padding

### ES256 (ECDSA)
- **Algorithm**: ES256 (ECDSA using P-256 curve and SHA-256)
- **Key Format**: PEM-encoded PKCS#8
- **Curve**: P-256 (secp256r1)
- **Encoding**: URL-safe Base64 without padding

## Token Structure

The JWT contains:
- `alg`: Either "PS256" or "ES256" depending on the algorithm used
- `typ`: Always "JWT"
- `preferred_username`: The username provided
- `iat`: Issued at timestamp (Unix epoch)
- `exp`: Expiration timestamp (Unix epoch)
- Additional custom claims (if provided)

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
