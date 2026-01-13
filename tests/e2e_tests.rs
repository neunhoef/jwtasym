use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
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

#[derive(Debug, Clone, Copy)]
enum Algorithm {
    PS256,
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

fn create_token_from_keys(
    algorithm: Algorithm,
    username: String,
    iat: u64,
    exp: u64,
    private_key_pem: &str,
    additional: serde_json::Map<String, serde_json::Value>,
) -> Result<String> {
    let header = JwtHeader {
        alg: algorithm.as_str().to_string(),
        typ: "JWT".to_string(),
    };

    let payload = JwtPayload {
        preferred_username: username,
        iat,
        exp,
        additional,
    };

    let header_json = serde_json::to_string(&header)?;
    let payload_json = serde_json::to_string(&payload)?;

    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let signature_b64 = match algorithm {
        Algorithm::PS256 => {
            let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
                .context("Failed to parse RSA private key")?;

            let signing_key = RsaSigningKey::<Sha256>::new(private_key);
            let mut rng = rand::thread_rng();
            let signature = signing_key.sign_with_rng(&mut rng, signing_input.as_bytes());

            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        }
        Algorithm::ES256 => {
            let private_key = EcdsaSigningKey::from_pkcs8_pem(private_key_pem)
                .context("Failed to parse ECDSA private key")?;

            let signature: EcdsaSignature = private_key.sign(signing_input.as_bytes());

            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        }
    };

    let jwt = format!("{}.{}", signing_input, signature_b64);

    Ok(jwt)
}

fn verify_token_with_key(token: &str, public_key_pem: &str) -> Result<JwtPayload> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        anyhow::bail!("Invalid JWT format: expected 3 parts separated by dots");
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .context("Failed to decode header")?;
    let header: JwtHeader =
        serde_json::from_slice(&header_bytes).context("Failed to parse header JSON")?;

    let algorithm = match header.alg.as_str() {
        "PS256" => Algorithm::PS256,
        "ES256" => Algorithm::ES256,
        _ => anyhow::bail!(
            "Unsupported algorithm: {}. Expected PS256 or ES256",
            header.alg
        ),
    };

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .context("Failed to decode payload")?;
    let payload: JwtPayload =
        serde_json::from_slice(&payload_bytes).context("Failed to parse payload JSON")?;

    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .context("Failed to decode signature")?;

    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let verification_result = match algorithm {
        Algorithm::PS256 => {
            let signature = RsaSignature::try_from(signature_bytes.as_slice())
                .context("Failed to parse RSA signature")?;

            let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
                .context("Failed to parse RSA public key")?;

            let verifying_key = RsaVerifyingKey::<Sha256>::new(public_key);
            verifying_key.verify(signing_input.as_bytes(), &signature)
        }
        Algorithm::ES256 => {
            let signature = EcdsaSignature::try_from(signature_bytes.as_slice())
                .context("Failed to parse ECDSA signature")?;

            let public_key = EcdsaVerifyingKey::from_public_key_pem(public_key_pem)
                .context("Failed to parse ECDSA public key")?;

            use rsa::signature::Verifier as RsaVerifierTrait;
            public_key.verify(signing_input.as_bytes(), &signature)
        }
    };

    verification_result.context("Token signature verification failed")?;

    Ok(payload)
}

#[test]
fn test_ps256_e2e_keypair_create_verify() {
    println!("\n=== PS256 End-to-End Test ===");

    // Step 1: Generate keypair
    println!("1. Generating PS256 keypair...");
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = RsaPublicKey::from(&private_key);

    let private_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();
    let public_pem = public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();

    println!("   ✓ Keypair generated");

    // Step 2: Create token
    println!("2. Creating JWT token...");
    let username = "testuser".to_string();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expiry = now + 3600; // 1 hour

    let token = create_token_from_keys(
        Algorithm::PS256,
        username.clone(),
        now,
        expiry,
        private_pem.as_str(),
        serde_json::Map::new(),
    )
    .unwrap();

    println!("   ✓ Token created: {}", &token[..50]);

    // Step 3: Verify token with correct key
    println!("3. Verifying token with correct public key...");
    let payload = verify_token_with_key(&token, &public_pem).unwrap();
    assert_eq!(payload.preferred_username, username);
    assert_eq!(payload.iat, now);
    assert_eq!(payload.exp, expiry);
    println!("   ✓ Token verified successfully");

    // Step 4: Verify rejection with wrong key
    println!("4. Verifying token rejection with wrong key...");
    let wrong_private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let wrong_public_key = RsaPublicKey::from(&wrong_private_key);
    let wrong_public_pem = wrong_public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();

    let result = verify_token_with_key(&token, &wrong_public_pem);
    assert!(result.is_err(), "Token should be rejected with wrong key");
    println!("   ✓ Token correctly rejected with wrong key");

    println!("\n✓✓✓ PS256 End-to-End Test PASSED ✓✓✓\n");
}

#[test]
fn test_es256_e2e_keypair_create_verify() {
    println!("\n=== ES256 End-to-End Test ===");

    // Step 1: Generate keypair
    println!("1. Generating ES256 keypair...");
    let mut rng = rand::thread_rng();
    let private_key = EcdsaSigningKey::random(&mut rng);
    let public_key = private_key.verifying_key();

    let private_pem = private_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .unwrap();
    let public_pem = public_key
        .to_public_key_pem(p256::pkcs8::LineEnding::LF)
        .unwrap();

    println!("   ✓ Keypair generated");

    // Step 2: Create token
    println!("2. Creating JWT token...");
    let username = "testuser".to_string();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expiry = now + 3600; // 1 hour

    let token = create_token_from_keys(
        Algorithm::ES256,
        username.clone(),
        now,
        expiry,
        private_pem.as_str(),
        serde_json::Map::new(),
    )
    .unwrap();

    println!("   ✓ Token created: {}", &token[..50]);

    // Step 3: Verify token with correct key
    println!("3. Verifying token with correct public key...");
    let payload = verify_token_with_key(&token, &public_pem).unwrap();
    assert_eq!(payload.preferred_username, username);
    assert_eq!(payload.iat, now);
    assert_eq!(payload.exp, expiry);
    println!("   ✓ Token verified successfully");

    // Step 4: Verify rejection with wrong key
    println!("4. Verifying token rejection with wrong key...");
    let wrong_private_key = EcdsaSigningKey::random(&mut rng);
    let wrong_public_key = wrong_private_key.verifying_key();
    let wrong_public_pem = wrong_public_key
        .to_public_key_pem(p256::pkcs8::LineEnding::LF)
        .unwrap();

    let result = verify_token_with_key(&token, &wrong_public_pem);
    assert!(result.is_err(), "Token should be rejected with wrong key");
    println!("   ✓ Token correctly rejected with wrong key");

    println!("\n✓✓✓ ES256 End-to-End Test PASSED ✓✓✓\n");
}

#[test]
fn test_tampered_token_rejection() {
    println!("\n=== Tampered Token Rejection Test ===");

    // Generate keypair and create token
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = RsaPublicKey::from(&private_key);

    let private_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();
    let public_pem = public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let token = create_token_from_keys(
        Algorithm::PS256,
        "testuser".to_string(),
        now,
        now + 3600,
        private_pem.as_str(),
        serde_json::Map::new(),
    )
    .unwrap();

    // Test 1: Tamper with payload
    println!("1. Testing tampered payload...");
    let parts: Vec<&str> = token.split('.').collect();
    let tampered_payload = URL_SAFE_NO_PAD.encode(b"{\"preferred_username\":\"hacker\"}");
    let tampered_token = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

    let result = verify_token_with_key(&tampered_token, &public_pem);
    assert!(result.is_err(), "Tampered token should be rejected");
    println!("   ✓ Tampered payload correctly rejected");

    // Test 2: Tamper with signature
    println!("2. Testing tampered signature...");
    let tampered_signature = URL_SAFE_NO_PAD.encode(b"fake_signature_data");
    let tampered_token = format!("{}.{}.{}", parts[0], parts[1], tampered_signature);

    let result = verify_token_with_key(&tampered_token, &public_pem);
    assert!(
        result.is_err(),
        "Token with tampered signature should be rejected"
    );
    println!("   ✓ Tampered signature correctly rejected");

    // Test 3: Invalid format
    println!("3. Testing invalid token format...");
    let result = verify_token_with_key("invalid.token", &public_pem);
    assert!(result.is_err(), "Invalid format token should be rejected");
    println!("   ✓ Invalid format correctly rejected");

    println!("\n✓✓✓ Tampered Token Rejection Test PASSED ✓✓✓\n");
}

#[test]
fn test_token_with_additional_claims() {
    println!("\n=== Additional Claims Test ===");

    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = RsaPublicKey::from(&private_key);

    let private_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();
    let public_pem = public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Create token with additional claims
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
        "testuser".to_string(),
        now,
        now + 3600,
        private_pem.as_str(),
        additional.clone(),
    )
    .unwrap();

    // Verify token and check additional claims
    let payload = verify_token_with_key(&token, &public_pem).unwrap();
    assert_eq!(payload.preferred_username, "testuser");
    assert_eq!(payload.additional.get("role").unwrap(), "admin");
    assert_eq!(payload.additional.get("department").unwrap(), "engineering");

    println!("✓ Additional claims correctly preserved and verified");
    println!("\n✓✓✓ Additional Claims Test PASSED ✓✓✓\n");
}

#[test]
fn test_file_based_e2e() {
    println!("\n=== File-Based End-to-End Test ===");

    let test_dir = PathBuf::from("/tmp/jwt_test");
    fs::create_dir_all(&test_dir).unwrap();

    // Test PS256
    println!("1. Testing PS256 with file-based keys...");
    let ps256_private = test_dir.join("ps256_private.pem");
    let ps256_public = test_dir.join("ps256_public.pem");

    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = RsaPublicKey::from(&private_key);

    let private_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();
    let public_pem = public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();

    fs::write(&ps256_private, private_pem.as_bytes()).unwrap();
    fs::write(&ps256_public, &public_pem).unwrap();

    let private_pem_loaded = fs::read_to_string(&ps256_private).unwrap();
    let public_pem_loaded = fs::read_to_string(&ps256_public).unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let token = create_token_from_keys(
        Algorithm::PS256,
        "fileuser".to_string(),
        now,
        now + 3600,
        &private_pem_loaded,
        serde_json::Map::new(),
    )
    .unwrap();

    let payload = verify_token_with_key(&token, &public_pem_loaded).unwrap();
    assert_eq!(payload.preferred_username, "fileuser");
    println!("   ✓ PS256 file-based test passed");

    // Test ES256
    println!("2. Testing ES256 with file-based keys...");
    let es256_private = test_dir.join("es256_private.pem");
    let es256_public = test_dir.join("es256_public.pem");

    let private_key = EcdsaSigningKey::random(&mut rng);
    let public_key = private_key.verifying_key();

    let private_pem = private_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .unwrap();
    let public_pem = public_key
        .to_public_key_pem(p256::pkcs8::LineEnding::LF)
        .unwrap();

    fs::write(&es256_private, private_pem.as_bytes()).unwrap();
    fs::write(&es256_public, &public_pem).unwrap();

    let private_pem_loaded = fs::read_to_string(&es256_private).unwrap();
    let public_pem_loaded = fs::read_to_string(&es256_public).unwrap();

    let token = create_token_from_keys(
        Algorithm::ES256,
        "fileuser".to_string(),
        now,
        now + 3600,
        &private_pem_loaded,
        serde_json::Map::new(),
    )
    .unwrap();

    let payload = verify_token_with_key(&token, &public_pem_loaded).unwrap();
    assert_eq!(payload.preferred_username, "fileuser");
    println!("   ✓ ES256 file-based test passed");

    // Cleanup
    fs::remove_dir_all(&test_dir).unwrap();

    println!("\n✓✓✓ File-Based End-to-End Test PASSED ✓✓✓\n");
}
