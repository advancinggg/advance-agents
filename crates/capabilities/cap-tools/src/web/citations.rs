use super::stores::EvidenceIdStore;

/// Extract `ev_` tokens (hex suffix) from text.
pub fn evidence_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 3 < bytes.len() {
        if bytes[i] == b'e' && bytes[i + 1] == b'v' && bytes[i + 2] == b'_' {
            let start = i;
            i += 3;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            if i - start > 3 {
                out.push(text[start..i].to_string());
            }
            continue;
        }
        i += 1;
    }
    out
}

pub fn validate_citations(text: &str, issued: &EvidenceIdStore) -> Result<(), Vec<String>> {
    let bad: Vec<String> = evidence_tokens(text)
        .into_iter()
        .filter(|t| !issued.contains(t))
        .collect();
    if bad.is_empty() {
        Ok(())
    } else {
        Err(bad)
    }
}

/// Fail-closed: drop unissued `ev_` tokens from payload bytes (UTF-8 or not).
/// Repeats until stable so a dropped dummy token cannot reconstitute `ev_`.
pub fn strip_unissued_citations(payload: &[u8], issued: &EvidenceIdStore) -> Vec<u8> {
    let mut cur = payload.to_vec();
    let bound = payload.len().saturating_add(2).max(8);
    for _ in 0..bound {
        let next = strip_unissued_citations_once(&cur, issued);
        if next == cur {
            return next;
        }
        cur = next;
    }
    strip_unissued_citations_once(&cur, &EvidenceIdStore::new())
}

fn strip_unissued_citations_once(payload: &[u8], issued: &EvidenceIdStore) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len());
    let mut i = 0;
    while i < payload.len() {
        if payload[i..].starts_with(b"ev_") {
            let start = i;
            i += 3;
            while i < payload.len() && payload[i].is_ascii_hexdigit() {
                i += 1;
            }
            if i > start + 3 {
                if let Ok(tok) = std::str::from_utf8(&payload[start..i]) {
                    if issued.contains(tok) {
                        out.extend_from_slice(&payload[start..i]);
                    }
                    continue;
                }
            }
            continue;
        }
        out.push(payload[i]);
        i += 1;
    }
    out
}
