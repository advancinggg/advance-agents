//! Natural order of vault entry names (ADR 2026-10-15 vault files;
//! CONTRACT-246 listing order).
//!
//! Deterministic and locale-free, so the server's sorted listing pages, the Apple client's
//! in-place row patches (`VaultNaturalOrder`) and any other SDK agree on one order:
//!
//! 1. NFC, then the per-scalar full lowercase mapping (no final-sigma context; Swift
//!    `Unicode.Scalar.Properties.lowercaseMapping` is the same mapping);
//! 2. runs of ASCII digits `0-9` compare by numeric value (any length); every other scalar compares
//!    by code point, so a digit run sorts where its first digit would;
//! 3. runs of equal value but different length (`1` / `01`) tie-break shorter first — deferred, so
//!    it only decides when everything else is equal;
//! 4. then the NFC bytes (so `A.md` precedes `a.md`);
//! 5. then the name's bytes as given (the on-disk spelling), so canonically equal names stored
//!    differently still order deterministically.
//!
//! A listing sorted by name ([`compare_entries`] under an [`EntryOrder`]) puts directories first
//! when asked, in **both** directions, and a descending listing reverses this order inside each
//! group, tie-breaks included. Only the `dir` kind groups first: a symlink is never followed, so it
//! sorts among the files, as do the other kinds. [`golden_cases`] is the conformance corpus
//! `gen_client_sdk` publishes as `conformance/files-natural-order.json`.

use std::cmp::Ordering;

use serde::Serialize;

use crate::workspace_path::to_nfc;

/// Compare two names in natural order (module docs). The names may be in any normalization
/// form; pass the on-disk spelling when it is known.
pub fn compare(a: &str, b: &str) -> Ordering {
    NaturalKey::new(a).cmp(&NaturalKey::new(b))
}

/// How a listing sorted by name orders its entries (`order=asc|desc`, `folders_first`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct EntryOrder {
    /// Directories precede every other kind, in both directions.
    pub folders_first: bool,
    /// Reverse [`compare`] inside each group (its tie-breaks included).
    pub descending: bool,
}

/// Compare two listing entries under `order`: directories first when `order.folders_first`
/// (whatever the direction), then [`compare`], reversed when `order.descending`. `a_is_dir` and
/// `b_is_dir` are true only for the `dir` kind; symlinks and other kinds sort with files.
pub fn compare_entries(
    a: &str,
    a_is_dir: bool,
    b: &str,
    b_is_dir: bool,
    order: EntryOrder,
) -> Ordering {
    if order.folders_first && a_is_dir != b_is_dir {
        return if a_is_dir {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    let by_name = compare(a, b);
    if order.descending {
        by_name.reverse()
    } else {
        by_name
    }
}

/// A precomputed sort key whose `Ord` is [`compare`]: the fs core builds one per entry for its
/// cached sorted snapshot instead of normalizing on every comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NaturalKey {
    /// NFC, then per-scalar lowercase: the primary comparison text.
    folded: String,
    /// NFC: the first tie-break.
    nfc: String,
    /// The name exactly as given: the last tie-break.
    given: String,
}

impl NaturalKey {
    /// The key of one name (any normalization form).
    pub fn new(name: &str) -> Self {
        let nfc = to_nfc(name);
        let folded = nfc.chars().flat_map(char::to_lowercase).collect();
        Self {
            folded,
            nfc,
            given: name.to_owned(),
        }
    }
}

impl Ord for NaturalKey {
    fn cmp(&self, other: &Self) -> Ordering {
        let (primary, leading_zeros) =
            compare_folded(self.folded.as_bytes(), other.folded.as_bytes());
        primary
            .then(leading_zeros)
            .then_with(|| self.nfc.as_bytes().cmp(other.nfc.as_bytes()))
            .then_with(|| self.given.as_bytes().cmp(other.given.as_bytes()))
    }
}

impl PartialOrd for NaturalKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The primary order over folded UTF-8 bytes, plus the deferred leading-zero tie-break (the first
/// pair of equal-valued digit runs of different length; shorter first). UTF-8 byte order is code
/// point order and ASCII digits are single bytes, so walking bytes in lockstep stays on scalar
/// boundaries.
fn compare_folded(a: &[u8], b: &[u8]) -> (Ordering, Ordering) {
    let (mut i, mut j) = (0, 0);
    let mut leading_zeros = Ordering::Equal;
    while i < a.len() && j < b.len() {
        if a[i].is_ascii_digit() && b[j].is_ascii_digit() {
            let run_a = digit_run(&a[i..]);
            let run_b = digit_run(&b[j..]);
            let by_value = compare_digit_values(run_a, run_b);
            if by_value != Ordering::Equal {
                return (by_value, leading_zeros);
            }
            if leading_zeros == Ordering::Equal {
                leading_zeros = run_a.len().cmp(&run_b.len());
            }
            i += run_a.len();
            j += run_b.len();
        } else {
            if a[i] != b[j] {
                return (a[i].cmp(&b[j]), leading_zeros);
            }
            i += 1;
            j += 1;
        }
    }
    ((a.len() - i).cmp(&(b.len() - j)), leading_zeros)
}

fn digit_run(bytes: &[u8]) -> &[u8] {
    let len = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
    &bytes[..len]
}

/// Numeric comparison of two ASCII digit runs of any length.
fn compare_digit_values(a: &[u8], b: &[u8]) -> Ordering {
    let a = strip_leading_zeros(a);
    let b = strip_leading_zeros(b);
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn strip_leading_zeros(run: &[u8]) -> &[u8] {
    let zeros = run.iter().take_while(|b| **b == b'0').count();
    &run[zeros..]
}

/// One conformance case: any permutation of `sorted`, ordered with [`compare_entries`] under the
/// case's [`EntryOrder`] (`folders_first`, `descending`), must yield exactly `sorted`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NaturalOrderCase {
    /// Stable case id.
    pub id: &'static str,
    /// What the case pins.
    pub description: &'static str,
    /// Whether directories group first.
    pub folders_first: bool,
    /// Whether the name order is reversed (directories still first when `folders_first`).
    pub descending: bool,
    /// The entries in the expected order.
    pub sorted: Vec<NaturalOrderEntry>,
}

impl NaturalOrderCase {
    /// The listing order the case pins.
    pub fn order(&self) -> EntryOrder {
        EntryOrder {
            folders_first: self.folders_first,
            descending: self.descending,
        }
    }
}

/// One named entry of a [`NaturalOrderCase`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NaturalOrderEntry {
    /// The name, in the spelling under test (NFD where the case says so).
    pub name: String,
    /// `"file"`, `"dir"`, `"symlink"` or `"other"` (the `files` family's entry kinds); only
    /// `"dir"` groups first.
    pub kind: &'static str,
}

/// The natural-order conformance corpus (`conformance/files-natural-order.json`).
pub fn golden_cases() -> Vec<NaturalOrderCase> {
    fn files(names: &[&str]) -> Vec<NaturalOrderEntry> {
        names
            .iter()
            .map(|name| NaturalOrderEntry {
                name: (*name).to_owned(),
                kind: "file",
            })
            .collect()
    }
    fn entries(items: &[(&str, &'static str)]) -> Vec<NaturalOrderEntry> {
        items
            .iter()
            .map(|&(name, kind)| NaturalOrderEntry {
                name: name.to_owned(),
                kind,
            })
            .collect()
    }
    let case = |id, description, folders_first, sorted| NaturalOrderCase {
        id,
        description,
        folders_first,
        descending: false,
        sorted,
    };
    let descending_case = |id, description, folders_first, sorted| NaturalOrderCase {
        id,
        description,
        folders_first,
        descending: true,
        sorted,
    };
    vec![
        case(
            "numeric_runs",
            "ASCII digit runs compare by value, at any length; a separator sorts before a digit",
            false,
            files(&[
                "file.txt",
                "file1.txt",
                "file2.txt",
                "file9.txt",
                "file10.txt",
                "file11.txt",
                "file100.txt",
                "file18446744073709551615.txt",
                "file18446744073709551616.txt",
            ]),
        ),
        case(
            "version_strings",
            "every digit run in a name is numeric",
            false,
            files(&["v1.2.9", "v1.2.10", "v1.10.0", "v2.0"]),
        ),
        case(
            "leading_zeros",
            "equal values tie-break shorter run first, only after the rest of the name",
            false,
            files(&["a1", "a01", "a001", "a01b", "a1c", "a2", "a02", "a10"]),
        ),
        case(
            "case",
            "letters compare case-insensitively; equal names put uppercase (lower NFC bytes) first",
            false,
            files(&["apple", "Banana", "banana", "bananas", "Cherry", "cherry"]),
        ),
        case(
            "cjk",
            "CJK, kana and Hangul compare by code point; digit runs inside CJK names stay numeric",
            false,
            files(&[
                "2024年1月.md",
                "2024年2月.md",
                "2024年10月.md",
                "かな.md",
                "周报.md",
                "笔记.md",
                "计划.md",
                "项目1.md",
                "项目2.md",
                "项目10.md",
                "한글.md",
            ]),
        ),
        case(
            "nfc_ties",
            "accented letters sort by code point after ASCII; canonically equal names tie on NFC \
             bytes and fall back to the bytes as given (NFD before NFC)",
            false,
            files(&[
                "e.md",
                "f.md",
                "z.md",
                "\u{C9}.md",
                "e\u{301}.md",
                "\u{E9}.md",
            ]),
        ),
        case(
            "folders_first",
            "directories group first, each group in natural order",
            true,
            entries(&[
                ("2", "dir"),
                ("10", "dir"),
                ("b", "dir"),
                ("Z", "dir"),
                ("1.txt", "file"),
                ("a", "file"),
                ("c", "file"),
            ]),
        ),
        case(
            "folders_mixed",
            "without folders first, directories and files interleave by name",
            false,
            entries(&[
                ("1.txt", "file"),
                ("2", "dir"),
                ("10", "dir"),
                ("a", "file"),
                ("b", "dir"),
                ("c", "file"),
                ("Z", "dir"),
            ]),
        ),
        case(
            "punctuation_vs_digits",
            "non-digit scalars compare by code point against a digit run's first digit",
            false,
            files(&["a b", "a-b", "a.b", "a0", "a9", "a_b", "ab", "a~b"]),
        ),
        case(
            "prefixes",
            "a prefix of a name sorts first; dotfiles and underscores sort by code point",
            false,
            files(&[
                ".env",
                ".obsidian",
                "_drafts",
                "a",
                "a.md",
                "a1",
                "a1.md",
                "ab",
            ]),
        ),
        case(
            "per_scalar_lowercase",
            "lowercase maps each scalar alone: no final-sigma rule, İ lowers to i + U+0307",
            false,
            files(&[
                "ix",
                "\u{130}x",
                "\u{3C3}\u{3B1}\u{3C2}",
                "\u{3A3}\u{391}\u{3A3}",
            ]),
        ),
        case(
            "ascii_digits_only",
            "only ASCII 0-9 are numeric; fullwidth digits compare as text",
            false,
            files(&["n9", "n10", "n\u{FF11}\u{FF10}", "n\u{FF12}"]),
        ),
        case(
            "emoji",
            "emoji (ZWJ sequences included) compare by code point",
            false,
            files(&[
                "a.md",
                "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}.md",
                "\u{1F600}.md",
            ]),
        ),
        case(
            "kinds_with_folders_first",
            "only directories group first; symlinks (never followed) and other kinds sort among \
             the files",
            true,
            entries(&[
                ("docs", "dir"),
                ("Zeta", "dir"),
                ("a-link", "symlink"),
                ("b.md", "file"),
                ("fifo", "other"),
                ("z.md", "file"),
            ]),
        ),
        descending_case(
            "folders_first_descending",
            "descending reverses the name order inside each group; directories still come first",
            true,
            entries(&[
                ("Z", "dir"),
                ("b", "dir"),
                ("10", "dir"),
                ("2", "dir"),
                ("c", "file"),
                ("a", "file"),
                ("1.txt", "file"),
            ]),
        ),
        descending_case(
            "descending_mixed",
            "descending without folders first reverses the whole interleaved order",
            false,
            entries(&[
                ("Z", "dir"),
                ("c", "file"),
                ("b", "dir"),
                ("a", "file"),
                ("10", "dir"),
                ("2", "dir"),
                ("1.txt", "file"),
            ]),
        ),
        descending_case(
            "descending_ties",
            "descending reverses the tie-breaks too: NFC before NFD, lowercase before uppercase, \
             the longer digit run first",
            false,
            files(&["\u{E9}.md", "e\u{301}.md", "banana", "Banana", "a01", "a1"]),
        ),
        descending_case(
            "kinds_descending",
            "descending with folders first keeps every non-directory kind in the file group",
            true,
            entries(&[
                ("Zeta", "dir"),
                ("docs", "dir"),
                ("z.md", "file"),
                ("fifo", "other"),
                ("b.md", "file"),
                ("a-link", "symlink"),
            ]),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_dir(entry: &NaturalOrderEntry) -> bool {
        entry.kind == "dir"
    }

    fn sort_entries(entries: &mut [NaturalOrderEntry], order: EntryOrder) {
        entries.sort_by(|a, b| compare_entries(&a.name, is_dir(a), &b.name, is_dir(b), order));
    }

    const ASCENDING: EntryOrder = EntryOrder {
        folders_first: false,
        descending: false,
    };
    const FOLDERS_FIRST: EntryOrder = EntryOrder {
        folders_first: true,
        descending: false,
    };
    const DESCENDING: EntryOrder = EntryOrder {
        folders_first: false,
        descending: true,
    };
    const FOLDERS_FIRST_DESCENDING: EntryOrder = EntryOrder {
        folders_first: true,
        descending: true,
    };

    #[test]
    fn numeric_runs_compare_by_value() {
        assert_eq!(compare("file2", "file10"), Ordering::Less);
        assert_eq!(compare("file10", "file9"), Ordering::Greater);
        assert_eq!(
            compare("x99999999999999999999", "x100000000000000000000"),
            Ordering::Less
        );
        assert_eq!(compare("2024-01-02", "2024-1-10"), Ordering::Less);
        assert_eq!(compare("file", "file0"), Ordering::Less);
    }

    #[test]
    fn leading_zeros_are_a_deferred_tie_break() {
        assert_eq!(compare("a1", "a01"), Ordering::Less);
        assert_eq!(compare("a01", "a001"), Ordering::Less);
        assert_eq!(compare("a00", "a0"), Ordering::Greater);
        // The rest of the name decides first.
        assert_eq!(compare("a01b", "a1c"), Ordering::Less);
        assert_eq!(compare("a1b", "a01b"), Ordering::Less);
    }

    #[test]
    fn case_is_secondary_to_letters_then_nfc_bytes() {
        assert_eq!(compare("apple", "Banana"), Ordering::Less);
        assert_eq!(compare("Banana", "banana"), Ordering::Less);
        assert_eq!(compare("banana", "BANANAS"), Ordering::Less);
        assert_eq!(compare("\u{C9}", "\u{E9}"), Ordering::Less);
    }

    #[test]
    fn canonically_equal_names_fall_back_to_disk_bytes() {
        let nfd = "e\u{301}.md";
        let nfc = "\u{E9}.md";
        assert_eq!(compare(nfd, nfc), Ordering::Less);
        assert_eq!(compare(nfc, nfd), Ordering::Greater);
        assert_eq!(compare(nfc, nfc), Ordering::Equal);
        assert_ne!(NaturalKey::new(nfd), NaturalKey::new(nfc));
    }

    #[test]
    fn folders_first_groups_directories() {
        assert_eq!(
            compare_entries("z", true, "a", false, FOLDERS_FIRST),
            Ordering::Less
        );
        assert_eq!(
            compare_entries("a", false, "z", true, FOLDERS_FIRST),
            Ordering::Greater
        );
        assert_eq!(
            compare_entries("z", true, "a", false, ASCENDING),
            Ordering::Greater
        );
        assert_eq!(
            compare_entries("a", true, "b", true, FOLDERS_FIRST),
            Ordering::Less
        );
        assert_eq!(EntryOrder::default(), ASCENDING);
    }

    #[test]
    fn descending_keeps_folders_first() {
        // Directories stay first in a descending listing: only the name order reverses.
        assert_eq!(
            compare_entries("a", true, "z", false, FOLDERS_FIRST_DESCENDING),
            Ordering::Less
        );
        assert_eq!(
            compare_entries("z", false, "a", true, FOLDERS_FIRST_DESCENDING),
            Ordering::Greater
        );
        assert_eq!(
            compare_entries("a", true, "b", true, FOLDERS_FIRST_DESCENDING),
            Ordering::Greater
        );
        assert_eq!(
            compare_entries("file2", false, "file10", false, FOLDERS_FIRST_DESCENDING),
            Ordering::Greater
        );
        // Without folders first, descending is the exact reverse, kinds ignored.
        assert_eq!(
            compare_entries("a", true, "z", false, DESCENDING),
            Ordering::Greater
        );
        // Tie-breaks reverse too, so descending is the mirror image of ascending.
        for (a, b) in [("Banana", "banana"), ("a1", "a01"), ("e\u{301}", "\u{E9}")] {
            assert_eq!(
                compare_entries(a, false, b, false, ASCENDING),
                Ordering::Less
            );
            assert_eq!(
                compare_entries(a, false, b, false, DESCENDING),
                Ordering::Greater
            );
        }
        assert_eq!(
            compare_entries("same", false, "same", false, DESCENDING),
            Ordering::Equal
        );
    }

    #[test]
    fn natural_key_agrees_with_compare() {
        let names: Vec<String> = golden_cases()
            .into_iter()
            .flat_map(|case| case.sorted.into_iter().map(|entry| entry.name))
            .collect();
        for a in &names {
            for b in &names {
                assert_eq!(
                    NaturalKey::new(a).cmp(&NaturalKey::new(b)),
                    compare(a, b),
                    "{a:?} vs {b:?}"
                );
                assert_eq!(
                    NaturalKey::new(a).partial_cmp(&NaturalKey::new(b)),
                    Some(compare(a, b))
                );
            }
        }
    }

    #[test]
    fn golden_cases_sort_back_from_any_permutation() {
        for case in golden_cases() {
            let n = case.sorted.len();
            let mut permutations: Vec<Vec<NaturalOrderEntry>> = (0..n)
                .map(|shift| {
                    let mut rotated = case.sorted.clone();
                    rotated.rotate_left(shift);
                    rotated
                })
                .collect();
            let mut reversed = case.sorted.clone();
            reversed.reverse();
            permutations.push(reversed);
            for mut permutation in permutations {
                sort_entries(&mut permutation, case.order());
                assert_eq!(permutation, case.sorted, "case {}", case.id);
            }
            for pair in case.sorted.windows(2) {
                assert_eq!(
                    compare_entries(
                        &pair[0].name,
                        is_dir(&pair[0]),
                        &pair[1].name,
                        is_dir(&pair[1]),
                        case.order()
                    ),
                    Ordering::Less,
                    "case {}: {:?} must precede {:?}",
                    case.id,
                    pair[0].name,
                    pair[1].name
                );
            }
        }
    }

    #[test]
    fn golden_cases_cover_required_topics() {
        let cases = golden_cases();
        let mut ids: Vec<&str> = cases.iter().map(|case| case.id).collect();
        for required in [
            "numeric_runs",
            "leading_zeros",
            "case",
            "cjk",
            "nfc_ties",
            "folders_first",
            "folders_mixed",
            "punctuation_vs_digits",
            "per_scalar_lowercase",
            "ascii_digits_only",
            "kinds_with_folders_first",
            "folders_first_descending",
            "descending_mixed",
            "descending_ties",
            "kinds_descending",
        ] {
            assert!(ids.contains(&required), "missing case {required}");
        }
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), cases.len(), "case ids are unique");
        let mixed = |case: &NaturalOrderCase| {
            case.sorted.iter().any(is_dir) && case.sorted.iter().any(|entry| !is_dir(entry))
        };
        // Every combination of the two flags is pinned on a case holding directories and files.
        for order in [
            ASCENDING,
            FOLDERS_FIRST,
            DESCENDING,
            FOLDERS_FIRST_DESCENDING,
        ] {
            assert!(
                cases
                    .iter()
                    .any(|case| case.order() == order && mixed(case)),
                "no mixed case for {order:?}"
            );
        }
        // Symlinks and other kinds are pinned to the file group in both directions.
        for order in [FOLDERS_FIRST, FOLDERS_FIRST_DESCENDING] {
            assert!(
                cases.iter().any(|case| case.order() == order
                    && case.sorted.iter().any(|entry| entry.kind == "symlink")
                    && case.sorted.iter().any(|entry| entry.kind == "other")),
                "no symlink and other kinds under {order:?}"
            );
        }
        for case in &cases {
            assert!(case.sorted.len() >= 2, "case {}", case.id);
            for entry in &case.sorted {
                assert!(
                    matches!(entry.kind, "file" | "dir" | "symlink" | "other"),
                    "case {}",
                    case.id
                );
            }
        }
        // The NFC-tie case really carries an NFD spelling.
        let nfc_ties = cases
            .iter()
            .find(|case| case.id == "nfc_ties")
            .expect("nfc_ties");
        assert!(nfc_ties
            .sorted
            .iter()
            .any(|entry| !unicode_normalization::is_nfc(&entry.name)));
        let json = serde_json::to_value(&cases).expect("cases serialize");
        assert_eq!(json[0]["sorted"][0]["kind"], "file");
        assert_eq!(json[0]["descending"], false);
    }

    #[test]
    fn order_is_total_over_golden_names() {
        let mut names: Vec<String> = golden_cases()
            .into_iter()
            .flat_map(|case| case.sorted.into_iter().map(|entry| entry.name))
            .collect();
        names.sort();
        names.dedup();
        // `natural_key_agrees_with_compare` ties the keys to `compare`.
        let keys: Vec<NaturalKey> = names.iter().map(|name| NaturalKey::new(name)).collect();
        for (a, key_a) in names.iter().zip(&keys) {
            assert_eq!(key_a.cmp(key_a), Ordering::Equal);
            for (b, key_b) in names.iter().zip(&keys) {
                let ab = key_a.cmp(key_b);
                assert_eq!(ab, key_b.cmp(key_a).reverse(), "{a:?} vs {b:?}");
                if a != b {
                    assert_ne!(ab, Ordering::Equal, "{a:?} vs {b:?}");
                }
                if ab != Ordering::Less {
                    continue;
                }
                for (c, key_c) in names.iter().zip(&keys) {
                    if key_b.cmp(key_c) == Ordering::Less {
                        assert_eq!(key_a.cmp(key_c), Ordering::Less, "{a:?} < {b:?} < {c:?}");
                    }
                }
            }
        }
    }
}
