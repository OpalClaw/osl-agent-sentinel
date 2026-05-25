//! Ed25519 signing primitives.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::errors::EngineError;

/// An Ed25519 keypair with serializable byte representations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    /// Public key bytes (32).
    pub public: [u8; 32],
    /// Private key bytes (32). Treat as sensitive.
    pub private: [u8; 32],
}

impl KeyPair {
    /// Generate a fresh keypair from the OS RNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let signing = SigningKey::generate(&mut rng);
        let verifying = signing.verifying_key();
        Self {
            public: verifying.to_bytes(),
            private: signing.to_bytes(),
        }
    }

    /// Sign `message` with this keypair.
    ///
    /// # Errors
    /// Returns `EngineError::Internal` if the key bytes are invalid.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64], EngineError> {
        let signing = SigningKey::from_bytes(&self.private);
        let sig: Signature = signing.sign(message);
        Ok(sig.to_bytes())
    }
}

/// Verify an Ed25519 signature.
///
/// Returns `Ok(())` if the signature is valid for the given message under
/// the given public key, and `Err(EngineError::InvalidSignature)` otherwise.
///
/// # Errors
/// Returns `EngineError::Internal` if the public key bytes are malformed.
pub fn verify_ed25519(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), EngineError> {
    let vk =
        VerifyingKey::from_bytes(public_key).map_err(|e| EngineError::Internal(e.to_string()))?;
    let sig = Signature::from_bytes(signature);
    vk.verify(message, &sig)
        .map_err(|_| EngineError::InvalidSignature)
}
