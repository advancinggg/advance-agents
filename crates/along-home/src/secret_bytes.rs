//! Consumed plaintext key wrapper. Debug is redacted; Drop zeroizes.

use zeroize::Zeroize;

pub struct SecretBytes(String);

impl SecretBytes {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBytes(REDACTED)")
    }
}
