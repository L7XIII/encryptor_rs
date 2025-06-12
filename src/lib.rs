use ring::aead;
use ring::rand;
use base64::engine::general_purpose;
use base64::Engine as _;

pub fn encrypt_data(plaintext: &str, key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key_bytes = base64url_decode(key)?;
    let algorithm = match key_bytes.len() {
        16 => &aead::AES_128_GCM,
        32 => &aead::AES_256_GCM,
        _ => return Err("Invalid key length".into()),
    };

    let rng = rand::SystemRandom::new();
    let mut nonce = [0u8; 12];
    rand::SecureRandom::fill(&rng, &mut nonce).expect("Error: random");

    let unbound_key = aead::UnboundKey::new(algorithm, &key_bytes).expect("Error: unbound key");
    let sealing_key = aead::LessSafeKey::new(unbound_key);

    let mut in_out = plaintext.as_bytes().to_vec();
    sealing_key
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut in_out,
        )
        .expect("Error: sealing key");

    let mut combined = Vec::with_capacity(nonce.len() + in_out.len());
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&in_out);

    Ok(base64url_encode(&combined))
}

pub fn decrypt_data(ciphertext: &str, key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let combined = base64url_decode(ciphertext)?;
    if combined.len() < 12 {
        return Err("Ciphertext too short".into());
    }

    let (nonce_bytes, encrypted_data) = combined.split_at(12);
    let key_bytes = base64url_decode(key)?;
    let algorithm = match key_bytes.len() {
        16 => &aead::AES_128_GCM,
        32 => &aead::AES_256_GCM,
        _ => return Err("Invalid key length".into()),
    };

    let unbound_key = aead::UnboundKey::new(algorithm, &key_bytes)
        .map_err(|e| format!("Failed to create unbound key: {}", e))?;
    let opening_key = aead::LessSafeKey::new(unbound_key);

    let mut in_out = encrypted_data.to_vec();
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| "Invalid nonce")?;
    
    let decrypted_data = opening_key
        .open_in_place(
            nonce,
            aead::Aad::empty(),
            &mut in_out,
        )
        .map_err(|_| "Decryption failed")?;

    String::from_utf8(decrypted_data.to_vec())
        .map_err(|e| format!("Invalid UTF-8: {}", e).into())
}

fn base64url_encode(data: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64url_decode(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|e| e.into())
}
