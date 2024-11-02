use aes::{
    cipher::{typenum::U12, KeyInit},
    Aes128,
};
use aes_gcm::{AeadInPlace, AesGcm};
use rand::random;

use super::Encryption;
use crate::{encoding::Encoding, AesKey, NcrError};

/// The aes/gcm encryption.
#[derive(Clone, Copy, Debug)]
pub struct GcmEncryption<E: Encoding>(pub E);

// Aes/Gcm encryption:
// This diagram shows the raw bytes used before encoding (and after decoding).
//
// |  12  -     Var      -  12   | (bytes)
// |  IV  |  Ciphertext  |  Tag  |
// |-----------------------------|
//
// Where:
//     IV (or Nonce) is used for encryption.
//     Ciphertext is the plaintext after encryption (same length as plaintext).
//     Tag is the GCM Authorization Tag (decryption would fail if tag doesn't match).

impl<E: Encoding> Encryption for GcmEncryption<E> {
    type KeyType = AesKey;

    fn encrypt(self, plaintext: &str, key: &AesKey) -> Result<String, NcrError> {
        let mut ciphertext = Vec::with_capacity(plaintext.len() + 24);
        let iv = random::<[u8; 12]>();

        ciphertext.extend_from_slice(&iv);
        ciphertext.extend_from_slice(plaintext.as_ref());

        let cipher = AesGcm::<Aes128, U12, U12>::new(key.as_ref().into());

        let tag = cipher
            .encrypt_in_place_detached(&iv.into(), &[], &mut ciphertext[12..])
            .map_err(|_| NcrError::EncryptError)?;

        ciphertext.extend_from_slice(&tag);

        Ok(self.0.encode(&ciphertext))
    }

    fn decrypt(self, ciphertext: &str, key: &AesKey) -> Result<String, NcrError> {
        let ciphertext = self.0.decode(ciphertext)?;

        if ciphertext.len() < 24 {
            return Err(NcrError::DecryptError);
        }

        let iv: [u8; 12] = ciphertext[..12].try_into().unwrap();
        let tag: [u8; 12] = ciphertext[(ciphertext.len() - 12)..].try_into().unwrap();

        let mut output = Vec::from(&ciphertext[12..(ciphertext.len() - 12)]);

        let cipher = AesGcm::<Aes128, U12, U12>::new(key.as_ref().into());

        cipher
            .decrypt_in_place_detached(&iv.into(), &[], &mut output, &tag.into())
            .map_err(|_| NcrError::DecryptError)?;

        String::from_utf8(output).map_err(|_| NcrError::DecryptError)
    }
}
