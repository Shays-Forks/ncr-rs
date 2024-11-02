//! Some common encryption algorithms.
//!
//! # Examples
//!
//! ## Encrypting
//!
//! ```
//! use ncr::encryption::{CaesarEncryption, Encryption};
//!
//! let decrypted = "#%Hello, world!";
//! let encrypted = CaesarEncryption.encrypt(decrypted, &5).unwrap();
//!
//! assert_eq!(encrypted, "(*Mjqqt1%|twqi&");
//! ```
//!
//! ## Decrypting
//!
//! ```
//! use ncr::encryption::{CaesarEncryption, Encryption};
//!
//! let encrypted = "(*Mjqqt1%|twqi&";
//! let decrypted = CaesarEncryption.decrypt(encrypted, &5).unwrap();
//!
//! assert_eq!(decrypted, "#%Hello, world!");
//! ```
//!

mod caesar;
#[cfg(feature = "cfb8")]
mod cfb8;
#[cfg(feature = "ecb")]
mod ecb;
#[cfg(feature = "gcm")]
mod gcm;

use crate::NcrError;
pub use caesar::CaesarEncryption;
#[cfg(feature = "cfb8")]
pub use cfb8::Cfb8Encryption;
#[cfg(feature = "ecb")]
pub use ecb::EcbEncryption;
#[cfg(feature = "gcm")]
pub use gcm::GcmEncryption;

/// The encryption trait.
pub trait Encryption {
    type KeyType;

    /// Encrypt a given text.
    fn encrypt(self, plaintext: &str, key: &Self::KeyType) -> Result<String, NcrError>;

    /// Decrypt a given text.
    fn decrypt(self, ciphertext: &str, key: &Self::KeyType) -> Result<String, NcrError>;
}
