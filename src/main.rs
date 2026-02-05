use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{Parser, Subcommand, ValueEnum};
use p256::ecdsa::{
    signature::Signer, Signature as EcdsaSignature, SigningKey as EcdsaSigningKey,
    VerifyingKey as EcdsaVerifyingKey,
};
use p256::pkcs8::{DecodePrivateKey as EcDecodePrivateKey, EncodePrivateKey as EcEncodePrivateKey};
use p256::pkcs8::{DecodePublicKey as EcDecodePublicKey, EncodePublicKey as EcEncodePublicKey};
use rsa::pss::{
    Signature as RsaSignature, SigningKey as RsaSigningKey, VerifyingKey as RsaVerifyingKey,
};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Algorithm {
    /// PS256 - RSA-PSS with SHA-256
    PS256,
    /// ES256 - ECDSA with P-256 and SHA-256
    ES256,
}

impl Algorithm {
    fn as_str(&self) -> &'static str {
        match self {
            Algorithm::PS256 => "PS256",
            Algorithm::ES256 => "ES256",
        }
    }
}

#[derive(Parser)]
#[command(name = "jwtasym")]
#[command(about = "JWT token generator and verifier supporting ES256 and PS256 algorithms", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new keypair for JWT signing
    Keygen {
        /// Algorithm to use (ES256 or PS256)
        #[arg(short, long, value_enum, default_value = "es256")]
        algorithm: Algorithm,

        /// Path to save the private key (PEM format)
        #[arg(short, long, default_value = "private_key.pem")]
        private_key: PathBuf,

        /// Path to save the public key (PEM format)
        #[arg(short = 'u', long, default_value = "public_key.pem")]
        public_key: PathBuf,

        /// Key size in bits (only for PS256, ignored for ES256 which uses P-256)
        #[arg(short, long, default_value = "2048")]
        bits: usize,
    },

    /// Create a JWT token
    Create {
        /// Algorithm to use (ES256 or PS256)
        #[arg(short, long, value_enum, default_value = "es256")]
        algorithm: Algorithm,

        /// Username for the preferred_username claim
        #[arg(short, long, default_value = "")]
        username: String,

        /// Token expiry duration in seconds (0 for no expiry)
        #[arg(short, long, default_value = "3600")]
        expiry: u64,

        /// Path to the private key file
        #[arg(short, long, default_value = "private_key.pem")]
        private_key: PathBuf,

        /// Additional claims as JSON (optional)
        #[arg(short, long)]
        claims: Option<String>,

        /// Issuer claim (iss)
        #[arg(long, default_value = "arangodb")]
        iss: String,

        /// Server ID claim (server_id)
        #[arg(long, default_value = "foo")]
        server_id: String,
    },

    /// Verify a JWT token
    Verify {
        /// The JWT token to verify
        token: String,

        /// Path to the public key file
        #[arg(short, long, default_value = "public_key.pem")]
        public_key: PathBuf,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct JwtPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    preferred_username: Option<String>,
    iss: String,
    server_id: String,
    iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<u64>,
    #[serde(flatten)]
    additional: serde_json::Map<String, serde_json::Value>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen {
            algorithm,
            private_key,
            public_key,
            bits,
        } => generate_keypair(algorithm, private_key, public_key, bits)?,
        Commands::Create {
            algorithm,
            username,
            expiry,
            private_key,
            claims,
            iss,
            server_id,
        } => create_token(
            algorithm,
            username,
            expiry,
            private_key,
            claims,
            iss,
            server_id,
        )?,
        Commands::Verify { token, public_key } => verify_token(token, public_key)?,
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_header_serialization() {
        let header = JwtHeader {
            alg: "PS256".to_string(),
            typ: "JWT".to_string(),
        };

        let json = serde_json::to_string(&header).unwrap();
        assert!(json.contains("\"alg\":\"PS256\""));
        assert!(json.contains("\"typ\":\"JWT\""));

        let deserialized: JwtHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.alg, "PS256");
        assert_eq!(deserialized.typ, "JWT");
    }

    #[test]
    fn test_jwt_payload_serialization() {
        let mut additional = serde_json::Map::new();
        additional.insert(
            "role".to_string(),
            serde_json::Value::String("admin".to_string()),
        );

        let payload = JwtPayload {
            preferred_username: Some("testuser".to_string()),
            iss: "arangodb".to_string(),
            server_id: "foo".to_string(),
            iat: 1000000,
            exp: Some(2000000),
            additional,
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"preferred_username\":\"testuser\""));
        assert!(json.contains("\"iss\":\"arangodb\""));
        assert!(json.contains("\"server_id\":\"foo\""));
        assert!(json.contains("\"iat\":1000000"));
        assert!(json.contains("\"exp\":2000000"));
        assert!(json.contains("\"role\":\"admin\""));

        let deserialized: JwtPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.preferred_username,
            Some("testuser".to_string())
        );
        assert_eq!(deserialized.iss, "arangodb");
        assert_eq!(deserialized.server_id, "foo");
        assert_eq!(deserialized.iat, 1000000);
        assert_eq!(deserialized.exp, Some(2000000));
        assert_eq!(deserialized.additional.get("role").unwrap(), "admin");
    }

    #[test]
    fn test_base64_encoding_decoding() {
        let test_data = b"Hello, World!";
        let encoded = URL_SAFE_NO_PAD.encode(test_data);
        let decoded = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        assert_eq!(test_data, decoded.as_slice());
    }

    #[test]
    fn test_algorithm_as_str() {
        assert_eq!(Algorithm::PS256.as_str(), "PS256");
        assert_eq!(Algorithm::ES256.as_str(), "ES256");
    }

    #[test]
    fn test_ps256_token_creation_and_verification() {
        // Generate a keypair
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let private_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let public_pem = public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();

        // Create a token
        let username = "testuser".to_string();
        let iat = 1000000;
        let exp = 2000000;
        let additional = serde_json::Map::new();

        let token = create_token_from_keys(
            Algorithm::PS256,
            username.clone(),
            iat,
            exp,
            private_pem.as_str(),
            additional,
            "arangodb".to_string(),
            "foo".to_string(),
        )
        .unwrap();

        // Verify the token has 3 parts
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Verify the token
        let payload = verify_token_with_key(&token, &public_pem).unwrap();
        assert_eq!(payload.preferred_username, Some(username));
        assert_eq!(payload.iss, "arangodb");
        assert_eq!(payload.server_id, "foo");
        assert_eq!(payload.iat, iat);
        assert_eq!(payload.exp, Some(exp));
    }

    #[test]
    fn test_es256_token_creation_and_verification() {
        // Generate a keypair
        let mut rng = rand::thread_rng();
        let private_key = EcdsaSigningKey::random(&mut rng);
        let public_key = private_key.verifying_key();

        let private_pem = private_key
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .unwrap();
        let public_pem = public_key
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .unwrap();

        // Create a token
        let username = "testuser".to_string();
        let iat = 1000000;
        let exp = 2000000;
        let additional = serde_json::Map::new();

        let token = create_token_from_keys(
            Algorithm::ES256,
            username.clone(),
            iat,
            exp,
            private_pem.as_str(),
            additional,
            "arangodb".to_string(),
            "foo".to_string(),
        )
        .unwrap();

        // Verify the token has 3 parts
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Verify the token
        let payload = verify_token_with_key(&token, &public_pem).unwrap();
        assert_eq!(payload.preferred_username, Some(username));
        assert_eq!(payload.iss, "arangodb");
        assert_eq!(payload.server_id, "foo");
        assert_eq!(payload.iat, iat);
        assert_eq!(payload.exp, Some(exp));
    }

    #[test]
    fn test_token_with_additional_claims() {
        // Generate a keypair
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let private_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let public_pem = public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();

        // Create a token with additional claims
        let username = "testuser".to_string();
        let iat = 1000000;
        let exp = 2000000;
        let mut additional = serde_json::Map::new();
        additional.insert(
            "role".to_string(),
            serde_json::Value::String("admin".to_string()),
        );
        additional.insert(
            "department".to_string(),
            serde_json::Value::String("engineering".to_string()),
        );

        let token = create_token_from_keys(
            Algorithm::PS256,
            username.clone(),
            iat,
            exp,
            private_pem.as_str(),
            additional.clone(),
            "arangodb".to_string(),
            "foo".to_string(),
        )
        .unwrap();

        // Verify the token
        let payload = verify_token_with_key(&token, &public_pem).unwrap();
        assert_eq!(payload.preferred_username, Some(username));
        assert_eq!(payload.iss, "arangodb");
        assert_eq!(payload.server_id, "foo");
        assert_eq!(payload.iat, iat);
        assert_eq!(payload.exp, Some(exp));
        assert_eq!(payload.additional.get("role").unwrap(), "admin");
        assert_eq!(payload.additional.get("department").unwrap(), "engineering");
    }

    #[test]
    fn test_invalid_token_format() {
        let public_pem = "dummy_key";
        let result = verify_token_with_key("invalid.token", public_pem);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid JWT format"));
    }

    #[test]
    fn test_invalid_signature() {
        // Generate two different keypairs
        let mut rng = rand::thread_rng();
        let private_key1 = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let private_key2 = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key2 = RsaPublicKey::from(&private_key2);

        let private_pem1 = private_key1
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let public_pem2 = public_key2
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();

        // Create a token with private key 1
        let token = create_token_from_keys(
            Algorithm::PS256,
            "testuser".to_string(),
            1000000,
            2000000,
            private_pem1.as_str(),
            serde_json::Map::new(),
            "arangodb".to_string(),
            "foo".to_string(),
        )
        .unwrap();

        // Try to verify with public key 2 (should fail)
        let result = verify_token_with_key(&token, &public_pem2);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("verification failed"));
    }

    #[test]
    fn test_tampered_token() {
        // Generate a keypair
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let private_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let public_pem = public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();

        // Create a token
        let token = create_token_from_keys(
            Algorithm::PS256,
            "testuser".to_string(),
            1000000,
            2000000,
            private_pem.as_str(),
            serde_json::Map::new(),
            "arangodb".to_string(),
            "foo".to_string(),
        )
        .unwrap();

        // Tamper with the token by modifying the payload
        let parts: Vec<&str> = token.split('.').collect();
        let tampered_payload = URL_SAFE_NO_PAD.encode(b"tampered_data");
        let tampered_token = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

        // Verification should fail
        let result = verify_token_with_key(&tampered_token, &public_pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_unsupported_algorithm() {
        // Create a token with an unsupported algorithm
        let header = JwtHeader {
            alg: "HS256".to_string(),
            typ: "JWT".to_string(),
        };
        let payload = JwtPayload {
            preferred_username: Some("testuser".to_string()),
            iss: "arangodb".to_string(),
            server_id: "foo".to_string(),
            iat: 1000000,
            exp: Some(2000000),
            additional: serde_json::Map::new(),
        };

        let header_json = serde_json::to_string(&header).unwrap();
        let payload_json = serde_json::to_string(&payload).unwrap();

        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(b"fake_signature");

        let token = format!("{}.{}.{}", header_b64, payload_b64, signature_b64);

        let result = verify_token_with_key(&token, "dummy_key");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported algorithm"));
    }

    #[test]
    fn test_ps256_es256_cross_verification_fails() {
        // Generate PS256 keypair
        let mut rng = rand::thread_rng();
        let rsa_private = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let rsa_private_pem = rsa_private
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();

        // Generate ES256 keypair
        let ec_private = EcdsaSigningKey::random(&mut rng);
        let ec_public = ec_private.verifying_key();
        let ec_public_pem = ec_public
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .unwrap();

        // Create PS256 token
        let token = create_token_from_keys(
            Algorithm::PS256,
            "testuser".to_string(),
            1000000,
            2000000,
            rsa_private_pem.as_str(),
            serde_json::Map::new(),
            "arangodb".to_string(),
            "foo".to_string(),
        )
        .unwrap();

        // Try to verify PS256 token with ES256 public key (should fail)
        let result = verify_token_with_key(&token, &ec_public_pem);
        assert!(result.is_err());
    }
}

fn generate_keypair(
    algorithm: Algorithm,
    private_path: PathBuf,
    public_path: PathBuf,
    bits: usize,
) -> Result<()> {
    match algorithm {
        Algorithm::PS256 => {
            println!("Generating {}-bit RSA keypair for PS256...", bits);

            let mut rng = rand::thread_rng();
            let private_key =
                RsaPrivateKey::new(&mut rng, bits).context("Failed to generate RSA private key")?;
            let public_key = RsaPublicKey::from(&private_key);

            // Save private key
            let private_pem = private_key
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .context("Failed to encode private key to PEM")?;
            fs::write(&private_path, private_pem.as_bytes())
                .context("Failed to write private key to file")?;

            // Save public key
            let public_pem = public_key
                .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
                .context("Failed to encode public key to PEM")?;
            fs::write(&public_path, public_pem).context("Failed to write public key to file")?;
        }
        Algorithm::ES256 => {
            println!("Generating P-256 ECDSA keypair for ES256...");

            let mut rng = rand::thread_rng();
            let private_key = EcdsaSigningKey::random(&mut rng);
            let public_key = private_key.verifying_key();

            // Save private key
            let private_pem = private_key
                .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
                .context("Failed to encode EC private key to PEM")?;
            fs::write(&private_path, private_pem.as_bytes())
                .context("Failed to write EC private key to file")?;

            // Save public key
            let public_pem = public_key
                .to_public_key_pem(p256::pkcs8::LineEnding::LF)
                .context("Failed to encode EC public key to PEM")?;
            fs::write(&public_path, public_pem).context("Failed to write EC public key to file")?;
        }
    }

    println!("✓ Private key saved to: {}", private_path.display());
    println!("✓ Public key saved to: {}", public_path.display());

    Ok(())
}

fn create_token_from_keys(
    algorithm: Algorithm,
    username: String,
    iat: u64,
    exp: u64,
    private_key_pem: &str,
    additional: serde_json::Map<String, serde_json::Value>,
    iss: String,
    server_id: String,
) -> Result<String> {
    // Create header
    let header = JwtHeader {
        alg: algorithm.as_str().to_string(),
        typ: "JWT".to_string(),
    };

    // Create payload
    let preferred_username = if username.is_empty() {
        None
    } else {
        Some(username)
    };

    let exp_value = if exp == iat { None } else { Some(exp) };

    let payload = JwtPayload {
        preferred_username,
        iss,
        server_id,
        iat,
        exp: exp_value,
        additional,
    };

    // Encode header and payload
    let header_json = serde_json::to_string(&header)?;
    let payload_json = serde_json::to_string(&payload)?;

    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

    // Create signing input
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    // Sign based on algorithm
    let signature_b64 = match algorithm {
        Algorithm::PS256 => {
            // Load RSA private key
            let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
                .context("Failed to parse RSA private key")?;

            // Sign with PS256
            let signing_key = RsaSigningKey::<Sha256>::new(private_key);
            let mut rng = rand::thread_rng();
            let signature = signing_key.sign_with_rng(&mut rng, signing_input.as_bytes());

            // Encode signature
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        }
        Algorithm::ES256 => {
            // Load ECDSA private key
            let private_key = EcdsaSigningKey::from_pkcs8_pem(private_key_pem)
                .context("Failed to parse ECDSA private key")?;

            // Sign with ES256
            let signature: EcdsaSignature = private_key.sign(signing_input.as_bytes());

            // Encode signature
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        }
    };

    // Create final JWT
    let jwt = format!("{}.{}", signing_input, signature_b64);

    Ok(jwt)
}

fn create_token(
    algorithm: Algorithm,
    username: String,
    expiry_seconds: u64,
    private_key_path: PathBuf,
    additional_claims: Option<String>,
    iss: String,
    server_id: String,
) -> Result<()> {
    // Get current timestamp
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System time error")?
        .as_secs();

    // Parse additional claims if provided
    let additional: serde_json::Map<String, serde_json::Value> =
        if let Some(claims_json) = additional_claims {
            serde_json::from_str(&claims_json).context("Failed to parse additional claims JSON")?
        } else {
            serde_json::Map::new()
        };

    // Load private key
    let private_pem =
        fs::read_to_string(&private_key_path).context("Failed to read private key file")?;

    // Create token
    let exp_time = if expiry_seconds == 0 {
        now // Signal no expiry by passing same value as iat
    } else {
        now + expiry_seconds
    };

    let jwt = create_token_from_keys(
        algorithm,
        username,
        now,
        exp_time,
        &private_pem,
        additional,
        iss,
        server_id,
    )?;

    println!("{}", jwt);

    Ok(())
}

fn verify_token_with_key(token: &str, public_key_pem: &str) -> Result<JwtPayload> {
    // Split token into parts
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        anyhow::bail!("Invalid JWT format: expected 3 parts separated by dots");
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    // Decode header
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .context("Failed to decode header")?;
    let header: JwtHeader =
        serde_json::from_slice(&header_bytes).context("Failed to parse header JSON")?;

    // Verify algorithm is supported
    let algorithm = match header.alg.as_str() {
        "PS256" => Algorithm::PS256,
        "ES256" => Algorithm::ES256,
        _ => anyhow::bail!(
            "Unsupported algorithm: {}. Expected PS256 or ES256",
            header.alg
        ),
    };

    // Decode payload
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .context("Failed to decode payload")?;
    let payload: JwtPayload =
        serde_json::from_slice(&payload_bytes).context("Failed to parse payload JSON")?;

    // Decode signature
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .context("Failed to decode signature")?;

    // Verify signature based on algorithm
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let verification_result = match algorithm {
        Algorithm::PS256 => {
            let signature = RsaSignature::try_from(signature_bytes.as_slice())
                .context("Failed to parse RSA signature")?;

            // Load RSA public key
            let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
                .context("Failed to parse RSA public key")?;

            // Verify signature
            let verifying_key = RsaVerifyingKey::<Sha256>::new(public_key);
            verifying_key.verify(signing_input.as_bytes(), &signature)
        }
        Algorithm::ES256 => {
            let signature = EcdsaSignature::try_from(signature_bytes.as_slice())
                .context("Failed to parse ECDSA signature")?;

            // Load ECDSA public key
            let public_key = EcdsaVerifyingKey::from_public_key_pem(public_key_pem)
                .context("Failed to parse ECDSA public key")?;

            // Verify signature
            use rsa::signature::Verifier as RsaVerifierTrait;
            public_key.verify(signing_input.as_bytes(), &signature)
        }
    };

    verification_result.context("Token signature verification failed")?;

    Ok(payload)
}

fn verify_token(token: String, public_key_path: PathBuf) -> Result<()> {
    // Load public key
    let public_pem =
        fs::read_to_string(&public_key_path).context("Failed to read public key file")?;

    // Verify token
    let payload = verify_token_with_key(&token, &public_pem)?;

    println!("✓ Token signature is valid!");

    // Check expiry
    if let Some(exp) = payload.exp {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("System time error")?
            .as_secs();

        if now > exp {
            println!("⚠ Warning: Token has expired!");
            println!("  Expired at: {} (current time: {})", exp, now);
        } else {
            println!("✓ Token is not expired");
            println!("  Expires at: {} (in {} seconds)", exp, exp - now);
        }
    } else {
        println!("✓ Token has no expiry");
    }

    // Display claims
    println!("\nToken claims:");
    if let Some(username) = &payload.preferred_username {
        println!("  preferred_username: {}", username);
    }
    println!("  iss: {}", payload.iss);
    println!("  server_id: {}", payload.server_id);
    println!("  issued_at: {}", payload.iat);
    if let Some(exp) = payload.exp {
        println!("  expires_at: {}", exp);
    }

    if !payload.additional.is_empty() {
        println!("  Additional claims:");
        for (key, value) in payload.additional.iter() {
            println!("    {}: {}", key, value);
        }
    }

    Ok(())
}
