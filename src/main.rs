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
#[command(name = "jwt-tool")]
#[command(about = "JWT token generator and verifier supporting PS256 and ES256 algorithms", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new keypair for JWT signing
    Keygen {
        /// Algorithm to use (PS256 or ES256)
        #[arg(short, long, value_enum, default_value = "ps256")]
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
        /// Algorithm to use (PS256 or ES256)
        #[arg(short, long, value_enum, default_value = "ps256")]
        algorithm: Algorithm,

        /// Username for the preferred_username claim
        #[arg(short, long)]
        username: String,

        /// Token expiry duration in seconds
        #[arg(short, long)]
        expiry: u64,

        /// Path to the private key file
        #[arg(short, long, default_value = "private_key.pem")]
        private_key: PathBuf,

        /// Additional claims as JSON (optional)
        #[arg(short, long)]
        claims: Option<String>,
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
    preferred_username: String,
    iat: u64,
    exp: u64,
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
        } => create_token(algorithm, username, expiry, private_key, claims)?,
        Commands::Verify { token, public_key } => verify_token(token, public_key)?,
    }

    Ok(())
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

fn create_token(
    algorithm: Algorithm,
    username: String,
    expiry_seconds: u64,
    private_key_path: PathBuf,
    additional_claims: Option<String>,
) -> Result<()> {
    // Create header
    let header = JwtHeader {
        alg: algorithm.as_str().to_string(),
        typ: "JWT".to_string(),
    };

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

    // Create payload
    let payload = JwtPayload {
        preferred_username: username,
        iat: now,
        exp: now + expiry_seconds,
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
            let private_pem =
                fs::read_to_string(&private_key_path).context("Failed to read private key file")?;
            let private_key = RsaPrivateKey::from_pkcs8_pem(&private_pem)
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
            let private_pem =
                fs::read_to_string(&private_key_path).context("Failed to read private key file")?;
            let private_key = EcdsaSigningKey::from_pkcs8_pem(&private_pem)
                .context("Failed to parse ECDSA private key")?;

            // Sign with ES256
            let signature: EcdsaSignature = private_key.sign(signing_input.as_bytes());

            // Encode signature
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        }
    };

    // Create final JWT
    let jwt = format!("{}.{}", signing_input, signature_b64);

    println!("✓ JWT token created successfully:");
    println!("{}", jwt);

    Ok(())
}

fn verify_token(token: String, public_key_path: PathBuf) -> Result<()> {
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
            let public_pem =
                fs::read_to_string(&public_key_path).context("Failed to read public key file")?;
            let public_key = RsaPublicKey::from_public_key_pem(&public_pem)
                .context("Failed to parse RSA public key")?;

            // Verify signature
            let verifying_key = RsaVerifyingKey::<Sha256>::new(public_key);
            verifying_key.verify(signing_input.as_bytes(), &signature)
        }
        Algorithm::ES256 => {
            let signature = EcdsaSignature::try_from(signature_bytes.as_slice())
                .context("Failed to parse ECDSA signature")?;

            // Load ECDSA public key
            let public_pem =
                fs::read_to_string(&public_key_path).context("Failed to read public key file")?;
            let public_key = EcdsaVerifyingKey::from_public_key_pem(&public_pem)
                .context("Failed to parse ECDSA public key")?;

            // Verify signature
            use rsa::signature::Verifier as RsaVerifierTrait;
            public_key.verify(signing_input.as_bytes(), &signature)
        }
    };

    match verification_result {
        Ok(_) => {
            println!("✓ Token signature is valid!");

            // Check expiry
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("System time error")?
                .as_secs();

            if now > payload.exp {
                println!("⚠ Warning: Token has expired!");
                println!("  Expired at: {} (current time: {})", payload.exp, now);
            } else {
                println!("✓ Token is not expired");
                println!(
                    "  Expires at: {} (in {} seconds)",
                    payload.exp,
                    payload.exp - now
                );
            }

            // Display claims
            println!("\nToken claims:");
            println!("  preferred_username: {}", payload.preferred_username);
            println!("  issued_at: {}", payload.iat);
            println!("  expires_at: {}", payload.exp);

            if !payload.additional.is_empty() {
                println!("  Additional claims:");
                for (key, value) in payload.additional.iter() {
                    println!("    {}: {}", key, value);
                }
            }
        }
        Err(e) => {
            anyhow::bail!("✗ Token signature verification failed: {}", e);
        }
    }

    Ok(())
}
