use aes_gcm::{aead::{Aead, generic_array::GenericArray}, Error, Aes256Gcm, KeyInit, Nonce};
use rand::{thread_rng, Rng};
use base64::{prelude::{Engine, BASE64_STANDARD}, DecodeError};
use std::string::FromUtf8Error;

fn main() {
    let test = String::from("test");

    let (encrypted_data, key, nonce) = match encrypt_aes(&test) {
        Ok(data) => data,
        Err(e) => {
            println!("Error point 1: {:?}", e);
            (String::new(), String::new(), String::new())
        }
    };

    let decrypted_data = match decrypt_aes(&encrypted_data, &key, &nonce) {
        Ok(data) => data,
        Err(e) => {
            println!("Error point 1: {:?}", e);
            String::new()
        }
    };

    println!("enc:   {}", encrypted_data);
    println!("key:   {}", key);
    println!("nonce: {}", nonce);
    println!("dec:   {}", decrypted_data);
}

#[derive(Debug)]
enum AESCryptoError {
    EncryptError(Error),
    DecryptError(Error),
    DecodeError(DecodeError),
    ToUtf8Error(FromUtf8Error)
}

fn encrypt_aes(data: &str) -> Result<(String, String, String), AESCryptoError> {
    const AES_256_KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 12;

    let mut rng = thread_rng();

    let data_bytes = data.as_bytes();

    let mut key_bytes = [0u8; AES_256_KEY_LEN];
    rng.fill(&mut key_bytes);
    let key = GenericArray::from_slice(&key_bytes);
    let key_vec = key_bytes.to_vec();

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let nonce_vec = nonce_bytes.to_vec();

    let cipher = Aes256Gcm::new(key);
    let encrypted = cipher.encrypt(nonce, data_bytes).map_err(AESCryptoError::EncryptError)?;

    let encrypted_base64 = BASE64_STANDARD.encode(encrypted);
    let key_base64 = BASE64_STANDARD.encode(key_vec);
    let nonce_base64 = BASE64_STANDARD.encode(nonce_vec);

    Ok((encrypted_base64, key_base64, nonce_base64))
}

fn decrypt_aes(data_base64: &str, key_base64: &str, nonce_base64: &str) -> Result<String, AESCryptoError> {
    let data_vec = BASE64_STANDARD.decode(data_base64).map_err(AESCryptoError::DecodeError)?;
    let data_bytes = data_vec.as_slice();

    let key_vec= BASE64_STANDARD.decode(key_base64).map_err(AESCryptoError::DecodeError)?;
    let key_bytes = key_vec.as_slice();
    let key = GenericArray::from_slice(key_bytes);

    let nonce_vec = BASE64_STANDARD.decode(nonce_base64).map_err(AESCryptoError::DecodeError)?;
    let nonce_bytes = &nonce_vec.as_slice();
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new(key);
    let decrypted = cipher.decrypt(nonce, data_bytes).map_err(AESCryptoError::DecryptError)?;

    let decrypted_data = String::from_utf8(decrypted).map_err(AESCryptoError::ToUtf8Error)?;
    Ok(decrypted_data)
}