//! keychain-sync S0 spike — MANUAL, dev-machine only (this lane).
//!
//! Run explicitly with:
//!   ADVANCE_LIVE_KEYCHAIN_SYNC=1 cargo test -p cap-secrets --test live_keychain_sync_smoke -- --ignored --nocapture
//!
//! Drives the PRODUCTION `RealSecItemOps` against the real Security.framework: one
//! `SecItemAdd` of a `kSecUseDataProtectionKeychain` + `kSecAttrSynchronizable` generic
//! password (then a ThisDeviceOnly one), a read-back, and a delete. It RECORDS every OSStatus
//! on stdout (`SPIKE_RESULT …`) instead of asserting success: the whole point of the spike is
//! to learn what an unsigned / ad-hoc-signed / Team-signed process gets back
//! (`errSecMissingEntitlement = -34018` is the expected answer for an unentitled process).
//!
//! Hygiene: a unique per-run service name and best-effort deletion in every path, so repeated
//! runs never leak items into the developer's keychain.

#[cfg(target_vendor = "apple")]
mod apple {
    use cap_secrets::{KeychainItem, RealSecItemOps, SecItemErrorKind, SecItemOps};

    fn unique_service(kind: &str) -> String {
        format!("agents.advance.spike-{}-{kind}.secrets", std::process::id())
    }

    fn status_of<T>(r: &Result<T, cap_secrets::SecItemError>) -> String {
        match r {
            Ok(_) => "0 (ok)".to_string(),
            Err(e) => format!("{} ({:?})", e.status, e.kind),
        }
    }

    /// One add / copy / delete cycle; returns (add, copy, delete) statuses.
    fn cycle(ops: &RealSecItemOps, item: &KeychainItem) -> (String, String, String) {
        let add = ops.add(item, b"spike-value");
        let copy = ops.copy(item);
        let copy_status = match &copy {
            Ok(Some(bytes)) if &***bytes == b"spike-value" => "0 (ok, value matches)".to_string(),
            Ok(Some(_)) => "0 (ok, VALUE MISMATCH)".to_string(),
            Ok(None) => "-25300 (NotFound)".to_string(),
            Err(e) => format!("{} ({:?})", e.status, e.kind),
        };
        let delete = ops.delete(item);
        // Best-effort second delete so a partially-successful run leaves nothing behind.
        let _ = ops.delete(item);
        (status_of(&add), copy_status, status_of(&delete))
    }

    pub fn run() {
        let ops = RealSecItemOps;
        for (kind, synchronizable) in [("sync", true), ("local", false)] {
            let item = KeychainItem {
                service: unique_service(kind),
                account: "spike".into(),
                synchronizable,
                access_group: None,
            };
            let (add, copy, delete) = cycle(&ops, &item);
            println!(
                "SPIKE_RESULT kind={kind} synchronizable={synchronizable} data_protection=true add={add} copy={copy} delete={delete}"
            );
            if let Err(e) = ops.add(&item, b"x") {
                if e.kind == SecItemErrorKind::MissingEntitlement {
                    println!(
                        "SPIKE_NOTE kind={kind}: errSecMissingEntitlement — this process lacks the keychain-access-groups / application-identifier entitlement the data-protection keychain requires"
                    );
                }
            }
            let _ = ops.delete(&item);
        }
    }
}

#[test]
#[ignore = "live Security.framework — manual dev-machine spike (plan §3.0); gated by ADVANCE_LIVE_KEYCHAIN_SYNC=1"]
fn s0_spike_data_protection_synchronizable_item() {
    if std::env::var("ADVANCE_LIVE_KEYCHAIN_SYNC").as_deref() != Ok("1") {
        println!("SPIKE_SKIPPED: set ADVANCE_LIVE_KEYCHAIN_SYNC=1 to touch the live keychain");
        return;
    }
    #[cfg(target_vendor = "apple")]
    apple::run();
    #[cfg(not(target_vendor = "apple"))]
    println!("SPIKE_SKIPPED: not an Apple target");
}
