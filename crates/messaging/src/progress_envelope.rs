//! CONTRACT-215 `ADVPRG\0` v1 decoder and trusted route stamping.
//!
//! The decoder is deliberately the only place that interprets the reserved
//! payload family. Complete magic and the six exact non-empty proper prefixes
//! fail closed; bytes outside that family remain a byte-identical legacy body.

use std::collections::BTreeMap;

use advance_shared_types::mailbox::{DispatchError, Message};
use advance_shared_types::outbound::{OutboundEncoding, OutboundRoute, RoutedOutboundMessage};

pub const PROGRESS_ENVELOPE_MAGIC: &[u8; 7] = b"ADVPRG\0";
pub const PROGRESS_ENVELOPE_VERSION: u8 = 1;
pub const PROGRESS_ENVELOPE_HEADER_BYTES: usize = 16;
pub const MAX_PROGRESS_ENVELOPE_BYTES: usize = 1_048_576;
pub const MAX_PROGRESS_BODY_BYTES: usize = 65_536;
pub const MAX_PROGRESS_METADATA_ENTRIES: usize = 3;
pub const MAX_PROGRESS_METADATA_KEY_BYTES: usize = 64;
pub const MAX_PROGRESS_METADATA_VALUE_BYTES: usize = 4_096;
pub const MAX_PROGRESS_METADATA_AGGREGATE_BYTES: usize = 8_192;

const PROGRESS_PHASE: &str = "progress.phase";
const PROGRESS_VALUE: &str = "progress.value";
const PROGRESS_SUMMARY: &str = "progress.summary";

fn invalid(reason: &'static str) -> DispatchError {
    DispatchError::InvalidPayload(reason.to_string())
}

fn read_u16(input: &[u8], cursor: &mut usize) -> Result<usize, DispatchError> {
    let end = cursor
        .checked_add(2)
        .ok_or_else(|| invalid("progress-envelope-invalid"))?;
    let bytes: [u8; 2] = input
        .get(*cursor..end)
        .ok_or_else(|| invalid("progress-envelope-truncated"))?
        .try_into()
        .map_err(|_| invalid("progress-envelope-truncated"))?;
    *cursor = end;
    Ok(u16::from_be_bytes(bytes) as usize)
}

fn read_u32(input: &[u8], cursor: &mut usize) -> Result<usize, DispatchError> {
    let end = cursor
        .checked_add(4)
        .ok_or_else(|| invalid("progress-envelope-invalid"))?;
    let bytes: [u8; 4] = input
        .get(*cursor..end)
        .ok_or_else(|| invalid("progress-envelope-truncated"))?
        .try_into()
        .map_err(|_| invalid("progress-envelope-truncated"))?;
    *cursor = end;
    usize::try_from(u32::from_be_bytes(bytes)).map_err(|_| invalid("progress-envelope-invalid"))
}

fn valid_metadata_key(key: &[u8]) -> bool {
    if key.is_empty() || key.len() > MAX_PROGRESS_METADATA_KEY_BYTES {
        return false;
    }
    let first = key[0];
    let first_ok = first.is_ascii_lowercase() || first.is_ascii_digit();
    first_ok
        && key.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(*byte, b'_' | b'.' | b'-')
        })
}

fn validate_progress_value(value: &str) -> bool {
    if value.is_empty() || value.trim() != value {
        return false;
    }
    let Ok(parsed) = value.parse::<f64>() else {
        return false;
    };
    parsed.is_finite() && (0.0..=1.0).contains(&parsed)
}

fn decode_progress_payload(
    payload: &[u8],
) -> Result<(Vec<u8>, BTreeMap<String, String>), DispatchError> {
    if payload.len() > MAX_PROGRESS_ENVELOPE_BYTES {
        return Err(invalid("progress-envelope-too-large"));
    }
    if payload.len() < PROGRESS_ENVELOPE_HEADER_BYTES {
        return Err(invalid("progress-envelope-truncated"));
    }
    if payload[7] != PROGRESS_ENVELOPE_VERSION || payload[8] != 0 || payload[9] != 0 {
        return Err(invalid("progress-envelope-header-invalid"));
    }

    let body_len = u32::from_be_bytes(
        payload[10..14]
            .try_into()
            .map_err(|_| invalid("progress-envelope-truncated"))?,
    ) as usize;
    if body_len > MAX_PROGRESS_BODY_BYTES {
        return Err(invalid("progress-body-too-large"));
    }
    let metadata_count = u16::from_be_bytes(
        payload[14..16]
            .try_into()
            .map_err(|_| invalid("progress-envelope-truncated"))?,
    ) as usize;
    if !(1..=MAX_PROGRESS_METADATA_ENTRIES).contains(&metadata_count) {
        return Err(invalid("progress-metadata-count-invalid"));
    }

    let body_end = PROGRESS_ENVELOPE_HEADER_BYTES
        .checked_add(body_len)
        .ok_or_else(|| invalid("progress-envelope-invalid"))?;
    let body = payload
        .get(PROGRESS_ENVELOPE_HEADER_BYTES..body_end)
        .ok_or_else(|| invalid("progress-envelope-truncated"))?
        .to_vec();

    let mut cursor = body_end;
    let mut aggregate = 0usize;
    let mut metadata = BTreeMap::new();
    for _ in 0..metadata_count {
        let key_len = read_u16(payload, &mut cursor)?;
        let value_len = read_u32(payload, &mut cursor)?;
        if key_len == 0
            || key_len > MAX_PROGRESS_METADATA_KEY_BYTES
            || value_len > MAX_PROGRESS_METADATA_VALUE_BYTES
        {
            return Err(invalid("progress-metadata-bounds-invalid"));
        }
        aggregate = aggregate
            .checked_add(key_len)
            .and_then(|value| value.checked_add(value_len))
            .ok_or_else(|| invalid("progress-metadata-bounds-invalid"))?;
        if aggregate > MAX_PROGRESS_METADATA_AGGREGATE_BYTES {
            return Err(invalid("progress-metadata-too-large"));
        }

        let key_end = cursor
            .checked_add(key_len)
            .ok_or_else(|| invalid("progress-envelope-invalid"))?;
        let key_bytes = payload
            .get(cursor..key_end)
            .ok_or_else(|| invalid("progress-envelope-truncated"))?;
        cursor = key_end;
        if !valid_metadata_key(key_bytes) {
            return Err(invalid("progress-metadata-key-invalid"));
        }
        let key = std::str::from_utf8(key_bytes)
            .map_err(|_| invalid("progress-metadata-key-invalid"))?
            .to_string();
        if !matches!(
            key.as_str(),
            PROGRESS_PHASE | PROGRESS_VALUE | PROGRESS_SUMMARY
        ) {
            return Err(invalid("progress-metadata-key-unknown"));
        }

        let value_end = cursor
            .checked_add(value_len)
            .ok_or_else(|| invalid("progress-envelope-invalid"))?;
        let value = std::str::from_utf8(
            payload
                .get(cursor..value_end)
                .ok_or_else(|| invalid("progress-envelope-truncated"))?,
        )
        .map_err(|_| invalid("progress-metadata-value-invalid"))?
        .to_string();
        cursor = value_end;
        if metadata.insert(key, value).is_some() {
            return Err(invalid("progress-metadata-duplicate"));
        }
    }
    if cursor != payload.len() {
        return Err(invalid("progress-envelope-trailing-bytes"));
    }

    let phase = metadata
        .get(PROGRESS_PHASE)
        .ok_or_else(|| invalid("progress-phase-missing"))?;
    if !matches!(phase.as_str(), "ack" | "progress" | "result" | "error") {
        return Err(invalid("progress-phase-invalid"));
    }
    if metadata
        .get(PROGRESS_VALUE)
        .is_some_and(|value| !validate_progress_value(value))
    {
        return Err(invalid("progress-value-invalid"));
    }
    Ok((body, metadata))
}

fn trusted_route(source: &Message, require_complete: bool) -> Result<OutboundRoute, DispatchError> {
    let Some(origin) = &source.origin else {
        return Ok(OutboundRoute::DirectReply);
    };
    let meta = &origin.channel_metadata;
    let subscription_id = meta
        .get("channel.subscription_id")
        .cloned()
        .unwrap_or_default();
    let conversation_id = meta
        .get("channel.conversation_id")
        .cloned()
        .unwrap_or_default();
    if require_complete
        && (origin.adapter_id.is_empty()
            || subscription_id.is_empty()
            || conversation_id.is_empty())
    {
        return Err(invalid("progress-route-invalid"));
    }
    let reply_address = meta
        .iter()
        .filter_map(|(key, value)| {
            key.strip_prefix("channel.reply_address.")
                .map(|suffix| (suffix.to_string(), value.clone()))
        })
        .collect::<BTreeMap<_, _>>()
        .into_iter()
        .collect();
    Ok(OutboundRoute::Channel {
        adapter_id: origin.adapter_id.clone(),
        subscription_id,
        conversation_id,
        reply_address,
    })
}

/// Decode one validated action payload and stamp correlation from `source`.
///
/// This function performs no sink or transport call. Every malformed reserved
/// payload returns [`DispatchError::InvalidPayload`] before downstream code can
/// observe it.
pub fn decode_routed_outbound(
    source: &Message,
    payload: &[u8],
) -> Result<RoutedOutboundMessage, DispatchError> {
    let is_complete_magic = payload.starts_with(PROGRESS_ENVELOPE_MAGIC);
    let is_exact_proper_prefix =
        (1..PROGRESS_ENVELOPE_MAGIC.len()).any(|len| payload == &PROGRESS_ENVELOPE_MAGIC[..len]);

    if is_exact_proper_prefix {
        return Err(invalid("progress-envelope-reserved-prefix"));
    }
    if !is_complete_magic {
        return Ok(RoutedOutboundMessage {
            encoding: OutboundEncoding::LegacyRaw,
            body: payload.to_vec(),
            metadata: BTreeMap::new(),
            source_message_id: source.id.clone(),
            route: trusted_route(source, false)?,
        });
    }

    let (body, metadata) = decode_progress_payload(payload)?;
    Ok(RoutedOutboundMessage {
        encoding: OutboundEncoding::ProgressV1,
        body,
        metadata,
        source_message_id: source.id.clone(),
        route: trusted_route(source, true)?,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::SystemTime;

    use advance_shared_types::chrono::Utc;
    use advance_shared_types::mailbox::{MessageKind, MessageOrigin};

    use super::*;

    fn source() -> Message {
        let mut channel_metadata = HashMap::new();
        channel_metadata.insert("channel.subscription_id".into(), "sub-1".into());
        channel_metadata.insert("channel.conversation_id".into(), "chat-42".into());
        channel_metadata.insert("channel.reply_address.z".into(), "last".into());
        channel_metadata.insert("channel.reply_address.a".into(), "first".into());
        Message {
            id: "msg-99".into(),
            kind: MessageKind::User,
            from: "user:alice".into(),
            to: "agent:default".into(),
            payload: vec![],
            context: None,
            timestamp: SystemTime::now(),
            origin: Some(MessageOrigin {
                message_id: "untrusted-origin-id".into(),
                original_channel: "telegram".into(),
                original_sender: "telegram:1".into(),
                adapter_id: "telegram".into(),
                channel_metadata,
                received_at: Utc::now(),
                context: None,
            }),
        }
    }

    fn envelope(body: &[u8], entries: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(PROGRESS_ENVELOPE_MAGIC);
        out.extend_from_slice(&[1, 0, 0]);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        for (key, value) in entries {
            out.extend_from_slice(&(key.len() as u16).to_be_bytes());
            out.extend_from_slice(&(value.len() as u32).to_be_bytes());
            out.extend_from_slice(key.as_bytes());
            out.extend_from_slice(value.as_bytes());
        }
        out
    }

    #[test]
    fn valid_v1_decodes_and_host_stamps_source_and_route() {
        let payload = envelope(
            b"working",
            &[("progress.phase", "progress"), ("progress.value", "0.7")],
        );
        let decoded = decode_routed_outbound(&source(), &payload).unwrap();
        assert_eq!(decoded.encoding, OutboundEncoding::ProgressV1);
        assert_eq!(decoded.body, b"working");
        assert_eq!(decoded.source_message_id, "msg-99");
        assert_eq!(decoded.metadata[PROGRESS_PHASE], "progress");
        assert_eq!(
            decoded.route,
            OutboundRoute::Channel {
                adapter_id: "telegram".into(),
                subscription_id: "sub-1".into(),
                conversation_id: "chat-42".into(),
                reply_address: vec![("a".into(), "first".into()), ("z".into(), "last".into())],
            }
        );
    }

    #[test]
    fn all_exact_nonempty_proper_prefixes_are_reserved() {
        for len in 1..PROGRESS_ENVELOPE_MAGIC.len() {
            assert!(matches!(
                decode_routed_outbound(&source(), &PROGRESS_ENVELOPE_MAGIC[..len]),
                Err(DispatchError::InvalidPayload(_))
            ));
        }
    }

    #[test]
    fn payload_outside_reserved_family_is_byte_identical_legacy_raw() {
        for payload in [b"".as_slice(), b"ADVPx", b"ordinary\0binary"] {
            let decoded = decode_routed_outbound(&source(), payload).unwrap();
            assert_eq!(decoded.encoding, OutboundEncoding::LegacyRaw);
            assert_eq!(decoded.body, payload);
            assert!(decoded.metadata.is_empty());
        }
    }

    #[test]
    fn malformed_reserved_envelopes_fail_closed() {
        let cases = [
            PROGRESS_ENVELOPE_MAGIC.to_vec(),
            envelope(b"x", &[]),
            envelope(b"x", &[("progress.phase", "unknown")]),
            envelope(b"x", &[("progress.unknown", "x")]),
            envelope(b"x", &[("progress.value", "0.5")]),
            envelope(
                b"x",
                &[("progress.phase", "progress"), ("progress.value", "NaN")],
            ),
            envelope(
                b"x",
                &[("progress.phase", "progress"), ("progress.phase", "ack")],
            ),
        ];
        for case in cases {
            assert!(
                matches!(
                    decode_routed_outbound(&source(), &case),
                    Err(DispatchError::InvalidPayload(_))
                ),
                "case unexpectedly accepted: {case:?}"
            );
        }
    }

    #[test]
    fn exact_boundary_body_is_accepted_and_over_boundary_rejected() {
        let at = envelope(
            &vec![b'x'; MAX_PROGRESS_BODY_BYTES],
            &[("progress.phase", "ack")],
        );
        assert!(decode_routed_outbound(&source(), &at).is_ok());
        let over = envelope(
            &vec![b'x'; MAX_PROGRESS_BODY_BYTES + 1],
            &[("progress.phase", "ack")],
        );
        assert!(matches!(
            decode_routed_outbound(&source(), &over),
            Err(DispatchError::InvalidPayload(_))
        ));
    }

    #[test]
    fn trailing_bytes_and_invalid_utf8_metadata_reject() {
        let mut trailing = envelope(b"x", &[("progress.phase", "ack")]);
        trailing.push(0);
        assert!(decode_routed_outbound(&source(), &trailing).is_err());

        let mut invalid_utf8 = envelope(b"x", &[("progress.phase", "ack")]);
        *invalid_utf8.last_mut().unwrap() = 0xff;
        assert!(decode_routed_outbound(&source(), &invalid_utf8).is_err());
    }
}
