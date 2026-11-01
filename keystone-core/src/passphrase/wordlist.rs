//! The embedded EFF large wordlist (FR-03 AC1, SEC-05). Sensitive code (GOVERNANCE.md section 3).
//!
//! Source: <https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt>, downloaded once,
//! checked as untrusted data and committed. Its SHA-256 is pinned by the test
//! `fr03_ac1_embedded_wordlist_is_the_pinned_eff_large_list`, so any change to the file
//! fails the build's tests.
//!
//! File format: 7,776 lines `<five dice digits 1-6>\t<word>\n`, in dice-code order, so the
//! word at index `i` has the dice code of `i` written in base 6 (digits 1-6). Words are
//! lowercase ASCII letters; four of them contain one inner hyphen (`drop-down`,
//! `felt-tip`, `t-shirt`, `yo-yo`). The words are strictly ascending, so lookups use
//! binary search, and no word is a prefix of another.
//!
//! Matching rule used everywhere (word boxes, autocomplete, re-entering a passphrase):
//! surrounding whitespace and ASCII letter case are ignored. Nothing else is accepted.
#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::sync::OnceLock;

/// The embedded wordlist file, byte for byte as published by the EFF.
pub(crate) const WORDLIST_TEXT: &str = include_str!("eff_large_wordlist.txt");

/// Number of words in the list (FR-03 AC1).
pub const WORDLIST_LEN: usize = 7_776;

/// Longest word in the list, in bytes.
pub const MAX_WORD_LEN: usize = 9;

/// The parsed list, or `None` if the embedded file failed validation (a corrupted binary).
fn parsed() -> Option<&'static [&'static str]> {
    static WORDS: OnceLock<Option<Vec<&'static str>>> = OnceLock::new();
    WORDS.get_or_init(|| parse(WORDLIST_TEXT)).as_deref()
}

/// Every word, in list order, or `None` if the embedded list is corrupt.
pub(crate) fn words() -> Option<&'static [&'static str]> {
    parsed()
}

/// Parses and validates the wordlist text. Returns `None` on any deviation from the format.
fn parse(text: &'static str) -> Option<Vec<&'static str>> {
    let body = text.strip_suffix('\n')?;
    let mut out = Vec::with_capacity(WORDLIST_LEN);
    for (index, line) in body.split('\n').enumerate() {
        let (code, word) = line.split_once('\t')?;
        if code != dice_code(index)? || !valid_word(word) {
            return None;
        }
        if let Some(previous) = out.last()
            && *previous >= word
        {
            return None;
        }
        out.push(word);
    }
    (out.len() == WORDLIST_LEN).then_some(out)
}

/// The five-digit dice code (digits 1-6) of list position `index`.
fn dice_code(index: usize) -> Option<String> {
    if index >= WORDLIST_LEN {
        return None;
    }
    let mut digits = [b'1'; 5];
    let mut rest = index;
    for slot in digits.iter_mut().rev() {
        *slot = b'1' + u8::try_from(rest % 6).ok()?;
        rest /= 6;
    }
    String::from_utf8(digits.to_vec()).ok()
}

/// Lowercase ASCII letters, optionally with inner single hyphens, at most `MAX_WORD_LEN` bytes.
fn valid_word(word: &str) -> bool {
    let bytes = word.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_WORD_LEN
        && bytes.iter().all(|b| b.is_ascii_lowercase() || *b == b'-')
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes.last().is_some_and(u8::is_ascii_lowercase)
        && !word.contains("--")
}

/// Compares typed text with a list word, ignoring ASCII case of the typed text.
fn cmp_typed(word: &str, typed: &str) -> Ordering {
    word.bytes()
        .cmp(typed.bytes().map(|b| b.to_ascii_lowercase()))
}

/// The list index of `text` (surrounding whitespace and ASCII case ignored), if it is a list word.
pub fn index_of(text: &str) -> Option<u16> {
    let typed = text.trim();
    if typed.is_empty() || typed.len() > MAX_WORD_LEN {
        return None;
    }
    let words = words()?;
    let index = words.binary_search_by(|word| cmp_typed(word, typed)).ok()?;
    u16::try_from(index).ok()
}

/// True when `text` is a word of the list (FR-03 AC4: word boxes accept only list words).
pub fn is_word(text: &str) -> bool {
    index_of(text).is_some()
}

/// The list word at `index`, if the index is in range.
pub fn word_at(index: u16) -> Option<&'static str> {
    words()?.get(usize::from(index)).copied()
}

/// Autocomplete for a word box (FR-03 AC4): every list word that starts with `prefix`
/// (leading whitespace and ASCII case ignored), in list order. An empty prefix returns
/// no words, so the GUI never lists the whole wordlist.
pub fn complete(prefix: &str) -> &'static [&'static str] {
    let typed = prefix.trim_start();
    let Some(words) = words() else {
        return &[];
    };
    if typed.is_empty() || typed.len() > MAX_WORD_LEN {
        return &[];
    }
    let starts_with = |word: &str| {
        word.len() >= typed.len() && cmp_typed(&word[..typed.len()], typed) == Ordering::Equal
    };
    let start = words.partition_point(|word| cmp_typed(word, typed) == Ordering::Less);
    let len = words[start..]
        .iter()
        .take_while(|word| starts_with(word))
        .count();
    &words[start..start + len]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::sha256;

    /// SHA-256 of the published EFF large wordlist (eff_large_wordlist.txt, 2016-07-18).
    const PINNED_SHA256: &str = "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e";

    #[test]
    fn fr03_ac1_embedded_wordlist_is_the_pinned_eff_large_list() {
        // Covers: FR-03 AC1, SEC-05
        assert_eq!(sha256(WORDLIST_TEXT.as_bytes()).to_hex(), PINNED_SHA256);
        let words = words().expect("embedded list is valid");
        assert_eq!(words.len(), WORDLIST_LEN);
        assert_eq!(words[0], "abacus");
        assert_eq!(words[WORDLIST_LEN - 1], "zoom");
        let unique: std::collections::BTreeSet<_> = words.iter().collect();
        assert_eq!(unique.len(), WORDLIST_LEN);
    }

    #[test]
    fn fr03_ac1_every_dice_code_is_present_in_order() {
        // Covers: FR-03 AC1
        assert_eq!(dice_code(0).as_deref(), Some("11111"));
        assert_eq!(dice_code(WORDLIST_LEN - 1).as_deref(), Some("66666"));
        assert_eq!(dice_code(WORDLIST_LEN), None);
        for (index, line) in WORDLIST_TEXT.lines().enumerate() {
            let code = line.split('\t').next().expect("code");
            assert_eq!(
                Some(code.to_string()),
                dice_code(index),
                "line {}",
                index + 1
            );
        }
    }

    #[test]
    fn parser_rejects_tampered_lists() {
        let changed_word = WORDLIST_TEXT.replacen("abacus", "zzz", 1).leak();
        assert!(parse(changed_word).is_none(), "word order broken");
        let missing_line = WORDLIST_TEXT.replacen("11111\tabacus\n", "", 1).leak();
        assert!(parse(missing_line).is_none());
        let uppercase = WORDLIST_TEXT.replacen("abacus", "Abacus", 1).leak();
        assert!(parse(uppercase).is_none());
        let no_final_newline = WORDLIST_TEXT.trim_end().to_string().leak();
        assert!(parse(no_final_newline).is_none());
        let bad_code = WORDLIST_TEXT
            .replacen("11111\tabacus", "11110\tabacus", 1)
            .leak();
        assert!(parse(bad_code).is_none());
    }

    #[test]
    fn valid_word_rules() {
        assert!(valid_word("t-shirt"));
        assert!(!valid_word("-shirt"));
        assert!(!valid_word("shirt-"));
        assert!(!valid_word("a--b"));
        assert!(!valid_word("abcdefghij"));
        assert!(!valid_word(""));
    }

    #[test]
    fn fr03_ac4_is_word_accepts_only_list_words() {
        // Covers: FR-03 AC4
        assert!(is_word("abacus"));
        assert!(is_word("  Zoom "));
        assert!(is_word("yo-yo"));
        assert!(!is_word("abacu"));
        assert!(is_word("password"), "a list word, though it looks weak");
        assert!(!is_word("qwerty"));
        assert!(!is_word(""));
        assert!(!is_word("abacus abdomen"));
        assert!(!is_word("ab\u{e9}cus"));
        assert_eq!(index_of("abacus"), Some(0));
        assert_eq!(index_of("ZOOM"), Some(7775));
        assert_eq!(word_at(7775), Some("zoom"));
        assert_eq!(word_at(7776), None);
    }

    #[test]
    fn fr03_ac4_autocomplete_lists_only_matching_list_words() {
        // Covers: FR-03 AC4
        let matches = complete("zoo");
        assert!(!matches.is_empty());
        assert!(matches.iter().all(|word| word.starts_with("zoo")));
        assert!(matches.contains(&"zoom"));
        assert_eq!(complete("ZOOLOGY"), &["zoology"]);
        assert!(complete("").is_empty());
        assert!(complete("qqq").is_empty());
        assert!(complete("abacusabacus").is_empty());
        assert_eq!(complete("t-s"), &["t-shirt"]);
        // Every match for a one-letter prefix, and nothing else.
        let a_words = complete("a");
        let expected = words()
            .expect("valid")
            .iter()
            .filter(|word| word.starts_with('a'))
            .count();
        assert_eq!(a_words.len(), expected);
    }

    #[test]
    fn no_word_is_a_prefix_of_another() {
        let words = words().expect("valid");
        for pair in words.windows(2) {
            assert!(!pair[1].starts_with(pair[0]), "{} / {}", pair[0], pair[1]);
        }
    }
}
