//! Pack lane P3 — signed manifests.
//!
//! A pack MAY ship a top-level `pack.sig` (a regular file on the `layout.rs`
//! allow-list) carrying an ed25519 signature over the EXACT bytes of
//! `pack.yaml`:
//!
//! ```yaml
//! alg: ed25519
//! public-key: <64 hex chars>      # the signer's ed25519 public key
//! signature: <128 hex chars>      # ed25519 signature over pack.yaml
//! ```
//!
//! The self-reference problem ("pack.yaml cannot checksum itself") is closed
//! by layering: the signature covers `pack.yaml`, and `pack.yaml`'s
//! `checksums.files` covers every other artifact.
//!
//! Semantics at install step ③b (after checksum verification, before the
//! admin prompt), given the operator's trust roots (`pack.trust-roots`, hex
//! public keys):
//!
//! | `pack.sig`                          | outcome                                   |
//! |-------------------------------------|-------------------------------------------|
//! | absent                              | unsigned                                  |
//! | present, verifies, key ∈ roots      | signed — `signed_by = Some(key)`          |
//! | present, verifies, key ∉ roots      | unsigned (an unknown signer proves nothing)|
//! | present, malformed / does not verify| `PackError::SignatureInvalid` (any roots) |
//!
//! `Installer` then downgrades an UNSIGNED pack that claims `trust-level:
//! trusted` to `untrusted` (the claim is only honoured when a trust root
//! vouches for it) and records `signed_by` in `.meta.yaml`.

use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

use crate::error::PackError;

/// Top-level file name of the manifest signature.
pub const PACK_SIG_FILENAME: &str = "pack.sig";

/// Bound on the `pack.sig` read — the document is three short scalars, so
/// 4 KiB leaves room for comments and still refuses a multi-MiB decoy.
const MAX_PACK_SIG_BYTES: u64 = 4096;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackSigFile {
    alg: String,
    #[serde(rename = "public-key")]
    public_key: String,
    signature: String,
}

/// Verify `<pack_dir>/pack.sig` (if present) over `pack_yaml_bytes`.
///
/// Returns `Ok(None)` when the file is absent or the (valid) signer is not one
/// of `trust_roots`; `Ok(Some(hex))` with the lower-case hex public key when a
/// trust root signed the manifest; `Err(SignatureInvalid)` when the file is
/// present but malformed or its signature does not verify. `trust_roots` are
/// compared case-insensitively (hex).
pub fn verify_pack_signature(
    pack_dir: &Path,
    pack_yaml_bytes: &[u8],
    pack_name: &str,
    trust_roots: &[String],
) -> Result<Option<String>, PackError> {
    let path = pack_dir.join(PACK_SIG_FILENAME);
    let invalid = |reason: String| PackError::SignatureInvalid {
        pack: pack_name.to_string(),
        reason,
    };
    // Probe without following: a symlinked pack.sig is refused like every other
    // symlink in a pack (copy_dir_no_symlinks would reject it later anyway).
    let md = match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(PackError::Io { path, source: e }),
        Ok(md) => md,
    };
    if md.file_type().is_symlink() {
        return Err(invalid("pack.sig is a symlink (rejected)".into()));
    }
    if !md.is_file() {
        return Err(invalid("pack.sig is not a regular file".into()));
    }
    if md.len() > MAX_PACK_SIG_BYTES {
        return Err(invalid(format!(
            "pack.sig exceeds max size {MAX_PACK_SIG_BYTES} bytes ({} bytes)",
            md.len()
        )));
    }
    let text = std::fs::read_to_string(&path).map_err(|e| PackError::Io {
        path: path.clone(),
        source: e,
    })?;
    let public_key_hex = parse_and_verify(&text, pack_yaml_bytes).map_err(invalid)?;
    let known = trust_roots
        .iter()
        .any(|root| root.eq_ignore_ascii_case(&public_key_hex));
    Ok(known.then_some(public_key_hex))
}

/// Sign `pack_yaml_bytes` with an ed25519 secret key (entity-data lane E4, `advance pack
/// sign`): returns the `pack.sig` document text (`alg` / `public-key` / `signature`) and the
/// lower-case hex public key the operator publishes as a trust root. The document is what
/// [`verify_pack_signature`] reads back.
pub fn sign_pack_yaml(pack_yaml_bytes: &[u8], secret: &[u8; 32]) -> (String, String) {
    use ed25519_dalek::{Signer, SigningKey};
    let key = SigningKey::from_bytes(secret);
    let public_hex = hex::encode(key.verifying_key().to_bytes());
    let signature = key.sign(pack_yaml_bytes);
    let text = format!(
        "alg: ed25519\npublic-key: {public_hex}\nsignature: {}\n",
        hex::encode(signature.to_bytes())
    );
    (text, public_hex)
}

/// The lower-case hex ed25519 public key of a secret key (what `advance pack keygen` prints
/// and operators put in `pack.trust-roots`).
pub fn public_key_hex(secret: &[u8; 32]) -> String {
    hex::encode(
        ed25519_dalek::SigningKey::from_bytes(secret)
            .verifying_key()
            .to_bytes(),
    )
}

/// Parse the `pack.sig` text and verify it over `message`. Returns the
/// lower-case hex public key on success; the error is the human-readable
/// reason (wrapped into `SignatureInvalid` by the caller).
fn parse_and_verify(text: &str, message: &[u8]) -> Result<String, String> {
    if crate::manifest::yaml_has_alias_refs(text) {
        return Err("pack.sig contains YAML alias references (rejected)".into());
    }
    let sig: PackSigFile = serde_yml::from_str(text).map_err(|e| format!("pack.sig parse: {e}"))?;
    if sig.alg != "ed25519" {
        return Err(format!(
            "unsupported signature algorithm {:?} (only ed25519)",
            sig.alg
        ));
    }
    let pk_bytes: [u8; 32] = decode_hex_exact(&sig.public_key, 32, "public-key")?;
    let sig_bytes: [u8; 64] = decode_hex_exact(&sig.signature, 64, "signature")?;
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| format!("public-key is not a valid ed25519 key: {e}"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    // `verify_strict` additionally rejects small-order / non-canonical points,
    // closing the malleability classes plain `verify` tolerates.
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| "signature does not verify over pack.yaml".to_string())?;
    Ok(hex::encode(pk_bytes))
}

fn decode_hex_exact<const N: usize>(s: &str, len: usize, field: &str) -> Result<[u8; N], String> {
    if s.len() != len * 2 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "{field} must be {} hex chars (got {} chars)",
            len * 2,
            s.len()
        ));
    }
    let bytes = hex::decode(s).map_err(|e| format!("{field} hex decode: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{field} must decode to {len} bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const YAML: &[u8] = b"name: foo\nversion: 1.0.0\n";

    fn signed(seed: u8, message: &[u8]) -> (String, String) {
        let k = SigningKey::from_bytes(&[seed; 32]);
        let pk = hex::encode(k.verifying_key().to_bytes());
        let sig = hex::encode(k.sign(message).to_bytes());
        (pk, sig)
    }

    fn sig_text(pk: &str, sig: &str) -> String {
        format!("alg: ed25519\npublic-key: {pk}\nsignature: {sig}\n")
    }

    #[test]
    fn verifies_and_reports_lowercase_key() {
        let (pk, sig) = signed(1, YAML);
        let upper = sig_text(&pk.to_uppercase(), &sig.to_uppercase());
        assert_eq!(parse_and_verify(&upper, YAML).unwrap(), pk);
    }

    #[test]
    fn rejects_tamper_wrong_alg_bad_hex_and_unknown_fields() {
        let (pk, sig) = signed(1, YAML);
        assert!(parse_and_verify(&sig_text(&pk, &sig), b"name: bar\n")
            .unwrap_err()
            .contains("does not verify"));
        assert!(
            parse_and_verify(&sig_text(&pk, &sig).replace("ed25519", "rsa"), YAML)
                .unwrap_err()
                .contains("algorithm")
        );
        assert!(parse_and_verify(&sig_text(&pk[..62], &sig), YAML)
            .unwrap_err()
            .contains("public-key must be 64 hex"));
        assert!(
            parse_and_verify(&sig_text(&pk, &format!("zz{}", &sig[2..])), YAML)
                .unwrap_err()
                .contains("signature must be 128 hex")
        );
        assert!(
            parse_and_verify(&format!("{}extra: 1\n", sig_text(&pk, &sig)), YAML)
                .unwrap_err()
                .contains("parse")
        );
        assert!(
            parse_and_verify("alg: &a ed25519\npublic-key: *a\nsignature: *a\n", YAML)
                .unwrap_err()
                .contains("alias")
        );
    }

    #[test]
    fn file_level_semantics_absent_unknown_root_and_symlink() {
        let dir = tempfile::TempDir::new().unwrap();
        // Absent → unsigned.
        assert_eq!(
            verify_pack_signature(dir.path(), YAML, "foo", &[]).unwrap(),
            None
        );
        let (pk, sig) = signed(2, YAML);
        std::fs::write(dir.path().join(PACK_SIG_FILENAME), sig_text(&pk, &sig)).unwrap();
        // Valid but no roots / other root → unsigned; matching root → signed.
        assert_eq!(
            verify_pack_signature(dir.path(), YAML, "foo", &[]).unwrap(),
            None
        );
        let (other, _) = signed(3, YAML);
        assert_eq!(
            verify_pack_signature(dir.path(), YAML, "foo", &[other]).unwrap(),
            None
        );
        assert_eq!(
            verify_pack_signature(dir.path(), YAML, "foo", &[pk.to_uppercase()]).unwrap(),
            Some(pk.clone())
        );
        // Tampered manifest → SignatureInvalid even with no roots.
        assert!(matches!(
            verify_pack_signature(dir.path(), b"tampered", "foo", &[]),
            Err(PackError::SignatureInvalid { .. })
        ));
        #[cfg(unix)]
        {
            let link_dir = tempfile::TempDir::new().unwrap();
            std::os::unix::fs::symlink(
                dir.path().join(PACK_SIG_FILENAME),
                link_dir.path().join(PACK_SIG_FILENAME),
            )
            .unwrap();
            assert!(matches!(
                verify_pack_signature(link_dir.path(), YAML, "foo", &[pk]),
                Err(PackError::SignatureInvalid { .. })
            ));
        }
    }
}
