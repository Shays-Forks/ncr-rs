use super::Encryption;
use crate::{encoding::Encoding, AesKey, NcrError};
use aes::{
    cipher::{block_padding::Pkcs7, KeyInit},
    Aes128Dec, Aes128Enc,
};
use cipher::{BlockCipherDecrypt, BlockCipherEncrypt};

/// The aes/ecb encryption.
#[derive(Clone, Copy, Debug)]
pub struct EcbEncryption<E: Encoding>(pub E);

// Aes/Ecb encryption:
// This diagram shows the raw bytes used before encoding (and after decoding).
//
// |     Var      | (bytes)
// |  Ciphertext  |
// |--------------|
//
// Where:
//     Ciphertext is the plaintext after encryption (same length as plaintext).

impl<E: Encoding> Encryption for EcbEncryption<E> {
    type KeyType = AesKey;

    fn encrypt(self, plaintext: &str, key: &AesKey) -> Result<String, NcrError> {
        let cipher = Aes128Enc::new(key.as_ref().into());

        // Pkcs5 is a subset of Pkcs7.
        let ciphertext = cipher.encrypt_padded_vec::<Pkcs7>(plaintext.as_ref());

        Ok(self.0.encode(&ciphertext))
    }

    fn decrypt(self, ciphertext: &str, key: &AesKey) -> Result<String, NcrError> {
        let ciphertext = self.0.decode(ciphertext)?;

        let cipher = Aes128Dec::new(key.as_ref().into());

        // Pkcs5 is a subset of Pkcs7.
        let output = cipher
            .decrypt_padded_vec::<Pkcs7>(&ciphertext)
            .map_err(|_| NcrError::DecryptError)?;

        String::from_utf8(output).map_err(|_| NcrError::DecryptError)
    }
}
