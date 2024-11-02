use super::Encryption;
use crate::{encoding::Encoding, AesKey, NcrError};
use aes::{
    cipher::{AsyncStreamCipher, KeyIvInit},
    Aes128,
};
use cfb8::{Decryptor, Encryptor};
use rand::random;
use std::num::Wrapping;

/// The aes/cfb8 encryption.
#[derive(Clone, Copy, Debug)]
pub struct Cfb8Encryption<E: Encoding>(pub E);

// Aes/Cfb8 encryption:
// This diagram shows the raw bytes used before encoding (and after decoding).
//
// |    8    -     Var      | (bytes)
// |  Nonce  |  Ciphertext  |
// |------------------------|
//
// Where:
//     Nonce is fed into java.util.Random as seed to generate IV, which is used for encryption.
//     Ciphertext is the plaintext after encryption (same length as plaintext).

fn generate_iv(nonce: u64) -> [u8; 16] {
    /// Modulus
    const M: Wrapping<i64> = Wrapping((1 << 48) - 1);
    /// Multiplier
    const A: Wrapping<i64> = Wrapping(0x5DEECE66D);
    /// Increment
    const C: Wrapping<i64> = Wrapping(11);

    let mut iv = [0u8; 16];

    let mut state = Wrapping((nonce as i64) ^ A.0) & M;

    for chunk in iv.chunks_exact_mut(4) {
        state = (state * A + C) & M;

        chunk.copy_from_slice(&(((state.0 as u64) >> 16) as i32).to_le_bytes());
    }

    iv
}

impl<E: Encoding> Encryption for Cfb8Encryption<E> {
    type KeyType = AesKey;

    fn encrypt(self, plaintext: &str, key: &AesKey) -> Result<String, NcrError> {
        let mut ciphertext = Vec::with_capacity(8 + plaintext.len());
        let nonce = random::<[u8; 8]>();

        ciphertext.extend_from_slice(&nonce);
        ciphertext.extend_from_slice(plaintext.as_ref());

        let iv = generate_iv(u64::from_be_bytes(nonce));

        Encryptor::<Aes128>::new(key.as_ref().into(), &iv.into()).encrypt(&mut ciphertext[8..]);

        Ok(self.0.encode(&ciphertext))
    }

    fn decrypt(self, ciphertext: &str, key: &AesKey) -> Result<String, NcrError> {
        let ciphertext = self.0.decode(ciphertext)?;

        if ciphertext.len() < 8 {
            return Err(NcrError::DecryptError);
        }
        let nonce: [u8; 8] = ciphertext[..8].try_into().unwrap();

        let iv = generate_iv(u64::from_be_bytes(nonce));

        let mut output = Vec::from(&ciphertext[8..]);
        Decryptor::<Aes128>::new(key.as_ref().into(), &iv.into()).decrypt(&mut output);

        String::from_utf8(output).map_err(|_| NcrError::DecryptError)
    }
}
