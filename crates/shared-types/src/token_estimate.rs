//! Shared ceil token estimate used across the workspace.
//!
//! Forward rule (integer ceil of `bytes / 4`):
//!
//! ```text
//! tokens = (bytes saturating+ 3) / 4
//! ```
//!
//! The inverse is offset-aware and exact on the non-saturating domain
//! (`bytes <= usize::MAX - 3`):
//!
//! ```text
//! offset = (bytes saturating+ 3) % 4          # 0..=3
//! bytes  = 4 * tokens + offset - 3            # checked; None if unrepresentable
//! ```
//!
//! On `bytes ∈ {usize::MAX-2, usize::MAX-1, usize::MAX}` the forward
//! estimator saturates (`saturating_add(3)` clamps to `usize::MAX`), so
//! the inverse recovers `usize::MAX - 3`, not the original length. That
//! matches existing `chars_to_tokens` saturating-add behavior.
//!
//! **REJECT:** grok's floor / loose inverse (would silently widen
//! documented caps by 3–7 bytes). Truncation budgets at call sites
//! (`4T-3`, `4T-7`, `T*4` clip) stay local and are not retuned here.

/// Ceil estimate: `(bytes saturating+ 3) / 4`.
pub fn tokens_from_bytes(bytes: usize) -> usize {
    bytes.saturating_add(3) / 4
}

/// Residue of the ceil formula: `(bytes saturating+ 3) % 4`, in `0..=3`.
pub fn offset_from_bytes(bytes: usize) -> u8 {
    (bytes.saturating_add(3) % 4) as u8
}

/// [`tokens_from_bytes`] saturating at `u32::MAX`.
///
/// Byte-identical to `advance_context_engine::assembler::chars_to_tokens`
/// (`.min(u32::MAX as usize) as u32`, not a wrapping `as u32`).
pub fn tokens_from_bytes_u32(bytes: usize) -> u32 {
    tokens_from_bytes(bytes).min(u32::MAX as usize) as u32
}

/// Exact inverse of [`tokens_from_bytes`] + [`offset_from_bytes`].
///
/// Returns `None` when `offset > 3`, when `(tokens, offset) = (0, off ≠ 3)`
/// (would be a negative length), or when `4 * tokens + offset - 3` is not
/// representable as `usize`.
pub fn bytes_from_tokens_offset(tokens: usize, offset: u8) -> Option<usize> {
    if offset > 3 {
        return None;
    }
    if tokens == 0 {
        return if offset == 3 { Some(0) } else { None };
    }
    tokens
        .checked_mul(4)?
        .checked_add(usize::from(offset))?
        .checked_sub(3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero_and_inverts() {
        assert_eq!(tokens_from_bytes(0), 0);
        assert_eq!(offset_from_bytes(0), 3);
        assert_eq!(bytes_from_tokens_offset(0, 3), Some(0));
    }

    #[test]
    fn non_aligned_lengths_match_ceil_div4() {
        for n in 1usize..=8 {
            assert_eq!(tokens_from_bytes(n), (n + 3) / 4, "n={n}");
        }
        assert_eq!(tokens_from_bytes(1), 1);
        assert_eq!(tokens_from_bytes(4), 1);
        assert_eq!(tokens_from_bytes(5), 2);
    }

    #[test]
    fn every_offset_round_trips_for_small_t() {
        for t in 1usize..=32 {
            for off in 0u8..=3 {
                let b = bytes_from_tokens_offset(t, off).expect("small t fits");
                assert_eq!(tokens_from_bytes(b), t);
                assert_eq!(offset_from_bytes(b), off);
            }
        }
    }

    #[test]
    fn identity_over_small_and_last_nonsaturating() {
        for b in 0usize..=32 {
            let recovered =
                bytes_from_tokens_offset(tokens_from_bytes(b), offset_from_bytes(b)).unwrap();
            assert_eq!(recovered, b, "identity at {b}");
        }
        let last = usize::MAX - 3;
        let recovered =
            bytes_from_tokens_offset(tokens_from_bytes(last), offset_from_bytes(last)).unwrap();
        assert_eq!(recovered, last);
    }

    #[test]
    fn saturating_forward_path_is_not_identity() {
        for b in [usize::MAX - 2, usize::MAX - 1, usize::MAX] {
            let recovered =
                bytes_from_tokens_offset(tokens_from_bytes(b), offset_from_bytes(b)).unwrap();
            assert_eq!(recovered, usize::MAX - 3, "saturating path at {b}");
            assert_ne!(recovered, b);
        }
    }

    #[test]
    fn inverse_rejects_invalid_pairs() {
        assert_eq!(bytes_from_tokens_offset(0, 0), None);
        assert_eq!(bytes_from_tokens_offset(0, 1), None);
        assert_eq!(bytes_from_tokens_offset(0, 2), None);
        assert_eq!(bytes_from_tokens_offset(1, 4), None);
        let overflowing_t = usize::MAX / 4 + 1;
        assert_eq!(bytes_from_tokens_offset(overflowing_t, 0), None);
    }

    #[test]
    fn u32_form_matches_cap_skills_pins() {
        assert_eq!(tokens_from_bytes_u32(0), 0);
        assert_eq!(tokens_from_bytes_u32(1), 1);
        assert_eq!(tokens_from_bytes_u32(4), 1);
        assert_eq!(tokens_from_bytes_u32(5), 2);
        assert_eq!(tokens_from_bytes_u32(397), 100);
        assert_eq!(tokens_from_bytes_u32(398), 100);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn u32_form_saturates_not_wraps() {
        let bytes = 4 * (u32::MAX as usize) + 1;
        assert_eq!(tokens_from_bytes(bytes), u32::MAX as usize + 1);
        assert_eq!(tokens_from_bytes_u32(bytes), u32::MAX);
    }
}
