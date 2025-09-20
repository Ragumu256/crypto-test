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

/*
fn aes_encrypt(contents: &[u8], key: &[u8], nonce: &[u8]) -> anyhow::Result<Vec<u8>> {
    let key = GenericArray::from_slice(key);
    let nonce = Nonce::from_slice(nonce);

    // encryption
    let cipher = Aes256Gcm::new(key);
    cipher
        .encrypt(nonce, contents.as_ref())
        .map_err(|e| anyhow!(e))
}

fn aes_decrypt(cipher_text: &[u8], key: &[u8], nonce: &[u8]) -> anyhow::Result<Vec<u8>> {
    let key = GenericArray::from_slice(key);
    let nonce = Nonce::from_slice(nonce);

    // decryption
    let cipher = Aes256Gcm::new(key);
    cipher.decrypt(nonce, cipher_text).map_err(|e| anyhow!(e))
}


use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::anyhow;
use data_encoding::HEXLOWER;
use rand::seq::SliceRandom;
use std::str;

#[derive(Debug)]
struct EncryptionKey(String);
#[derive(Debug)]
struct EncryptionNonce(String);

impl From<String> for EncryptionKey {
    fn from(key: String) -> Self {
        Self(key)
    }
}

impl From<String> for EncryptionNonce {
    fn from(nonce: String) -> Self {
        Self(nonce)
    }
}

const RAND_BASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

fn main() -> anyhow::Result<()> {
    let (encryption_key, encryption_nonce) = init()?;
    let key = encryption_key.0.as_bytes();
    let nonce = encryption_nonce.0.as_bytes();

    // contents to be encrypted
    let contents = "plain text".to_string();

    // encryption
    let encrypted_contents =
        aes_encrypt(contents.as_bytes(), key, nonce).map_err(|e| anyhow!(e))?;
    println!("{:?}", encrypted_contents);

    // encode
    let encoded_contents = HEXLOWER.encode(&encrypted_contents);
    println!("{}", encoded_contents);

    // decode
    let decoded_contents = HEXLOWER
        .decode(encoded_contents.as_ref())
        .map_err(|e| anyhow!(e))?;
    println!("{:?}", decoded_contents);

    // decryption
    let plain_text = aes_decrypt(&encrypted_contents, key, nonce).map_err(|e| anyhow!(e))?;
    let decrypted_contents: &str = str::from_utf8(&plain_text)?;
    println!("{}", decrypted_contents);

    assert_eq!(&contents, decrypted_contents);

    Ok(())
}

fn init() -> anyhow::Result<(EncryptionKey, EncryptionNonce)> {
    let key = gen_rand_string(KEY_SIZE)?.into();
    let nonce = gen_rand_string(NONCE_SIZE)?.into();

    println!("{:?}, {:?}", key, nonce);
    Ok((key, nonce))
}

fn gen_rand_string(size: usize) -> anyhow::Result<String> {
    let mut rng = &mut rand::thread_rng();
    String::from_utf8(
        RAND_BASE
            .as_bytes()
            .choose_multiple(&mut rng, size)
            .cloned()
            .collect(),
    )
    .map_err(|e| anyhow!(e))
}
*/