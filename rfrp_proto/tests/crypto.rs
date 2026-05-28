use rfrp_proto::crypto::{derive_key, Cipher};

#[test]
fn derive_key_deterministic() {
    let key1 = derive_key("test-token");
    let key2 = derive_key("test-token");
    assert_eq!(key1, key2);
}

#[test]
fn derive_key_different_inputs() {
    let key1 = derive_key("token-a");
    let key2 = derive_key("token-b");
    assert_ne!(key1, key2);
}

#[test]
fn derive_key_length() {
    let key = derive_key("anything");
    assert_eq!(key.len(), 32);
}

#[test]
fn encrypt_decrypt_roundtrip() {
    let key = derive_key("test-token");
    let cipher = Cipher::new(&key);
    let plaintext = b"Hello, World!";
    let ciphertext = cipher.encrypt(plaintext);
    let decrypted = cipher.decrypt(&ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn encrypt_decrypt_empty_plaintext() {
    let key = derive_key("test-token");
    let cipher = Cipher::new(&key);
    let plaintext = b"";
    let ciphertext = cipher.encrypt(plaintext);
    let decrypted = cipher.decrypt(&ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn encrypt_decrypt_large_data() {
    let key = derive_key("test-token");
    let cipher = Cipher::new(&key);
    let plaintext = vec![0xABu8; 65536];
    let ciphertext = cipher.encrypt(&plaintext);
    let decrypted = cipher.decrypt(&ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn encrypt_different_each_time() {
    let key = derive_key("test-token");
    let cipher = Cipher::new(&key);
    let plaintext = b"Hello, World!";
    let ct1 = cipher.encrypt(plaintext);
    let ct2 = cipher.encrypt(plaintext);
    // Nonces are different (atomic counter), so ciphertexts should differ
    assert_ne!(ct1, ct2);
}

#[test]
fn decrypt_tampered_ciphertext_fails() {
    let key = derive_key("test-token");
    let cipher = Cipher::new(&key);
    let plaintext = b"Hello, World!";
    let mut ciphertext = cipher.encrypt(plaintext);
    // Tamper with the last byte
    let len = ciphertext.len();
    ciphertext[len - 1] ^= 0xFF;
    assert!(cipher.decrypt(&ciphertext).is_err());
}

#[test]
fn decrypt_short_ciphertext_fails() {
    let key = derive_key("test-token");
    let cipher = Cipher::new(&key);
    // Less than 12 bytes (nonce size)
    assert!(cipher.decrypt(&[0u8; 5]).is_err());
}

#[test]
fn decrypt_with_wrong_key_fails() {
    let key1 = derive_key("token-a");
    let key2 = derive_key("token-b");
    let cipher1 = Cipher::new(&key1);
    let cipher2 = Cipher::new(&key2);
    let plaintext = b"secret data";
    let ciphertext = cipher1.encrypt(plaintext);
    assert!(cipher2.decrypt(&ciphertext).is_err());
}

#[test]
fn encrypt_in_place_roundtrip() {
    let key = derive_key("test-token");
    let cipher = Cipher::new(&key);
    let original = b"Hello, World!";
    let mut buf = original.to_vec();
    cipher.encrypt_in_place(&mut buf);
    // Encrypted data should be larger (nonce + tag overhead)
    assert!(buf.len() > original.len());
    let decrypted = cipher.decrypt(&buf).unwrap();
    assert_eq!(decrypted, original);
}

#[test]
fn encrypt_output_format() {
    let key = derive_key("test-token");
    let cipher = Cipher::new(&key);
    let plaintext = b"test";
    let ciphertext = cipher.encrypt(plaintext);
    // Expected: 12 (nonce) + 4 (ciphertext) + 16 (tag) = 32
    assert_eq!(ciphertext.len(), 12 + plaintext.len() + 16);
}
