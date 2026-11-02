//! Passphrase generation and confirmation (FR-03, SEC-05, SEC-17). Sensitive code
//! (GOVERNANCE.md section 3: the passphrase generator and the embedded EFF wordlist).
//!
//! # Rules
//! - Words come only from the embedded EFF large wordlist (7,776 words), chosen with
//!   `crypto::rand::uniform_below` (OpenSSL's DRBG, seeded by the OS). About 12.9 bits
//!   per word: 10 words give about 129 bits, 20 words about 258 bits (SEC-05).
//! - There is no constructor that takes operator-chosen text for a *new* passphrase. The
//!   only ways to get a passphrase are [`NewPassphrase::generate_master`],
//!   [`NewPassphrase::generate_sub_intermediate`], and [`EnteredPassphrase::parse`], which
//!   re-enters an existing passphrase to *unlock* a key and accepts only list words.
//! - The secret text is the words joined by single spaces, held in a locked, wiped-on-drop
//!   [`SecretString`]. That exact string is what encrypts the key. No type here implements
//!   `Clone`, `Display`, `Serialize` or `Deserialize`; `Debug` shows only the word count.
//!
//! # Show-once lifecycle (SEC-17, FR-03 AC3)
//! ```text
//! NewPassphrase ──into_confirmation──▶ ConfirmationSession ──finish──▶ ConfirmedPassphrase
//!  (words can be displayed)            (words can be viewed again,     (secret only: no word
//!                                       retyping per group)              can be displayed)
//! ```
//! `finish` consumes the session, so after confirmation nothing can display the words.
//! Callers that encrypt a *new* key should take a [`ConfirmedPassphrase`]; callers that
//! decrypt an existing key take an [`EnteredPassphrase`].
//!
//! # Confirmation for a tired person (FR-03 AC4)
//! [`ConfirmationSession`] is a pure state machine the GUI drives:
//! - words are numbered from 1 and shown in groups of 4 ([`GROUP_SIZE`]);
//! - retyping is enabled only after the operator ticks the box returned by
//!   [`ConfirmationSession::written_down_prompt`];
//! - each word box accepts only list words ([`is_word`], [`complete`]);
//! - each group is checked on its own; a mistake marks only that group for re-entry (its
//!   boxes are cleared) and keeps every group already confirmed;
//! - the operator can view the words again at any time before finishing;
//! - [`ConfirmationSession::finish`] succeeds only when every group matches.
#![forbid(unsafe_code)]

mod wordlist;

use std::fmt;

use crate::crypto::CryptoError;
use crate::crypto::rand::uniform_below;
use crate::crypto::secret::{SecretBytes, SecretString};

pub use wordlist::{MAX_WORD_LEN, WORDLIST_LEN, complete, index_of, is_word, word_at};

/// Fewest words the operator may choose for the master passphrase (FR-03 AC2).
pub const MASTER_MIN_WORDS: usize = 10;
/// Most words the operator may choose for the master passphrase (FR-03 AC2).
pub const MASTER_MAX_WORDS: usize = 20;
/// Words in every sub-intermediate passphrase (FR-03 AC2, SEC-05).
pub const SUB_INTERMEDIATE_WORDS: usize = 10;
/// Words per displayed and checked group (FR-03 AC4).
pub const GROUP_SIZE: usize = 4;
/// Longest text accepted when a passphrase is re-entered (SEC-08 style input limit).
pub const MAX_ENTERED_TEXT_BYTES: usize = 1024;

/// Bytes needed for the longest passphrase: 20 words of up to 9 bytes plus 19 spaces.
const SECRET_CAPACITY: usize = MASTER_MAX_WORDS * (MAX_WORD_LEN + 1);

/// Errors from this module. No variant ever contains passphrase text.
#[derive(Debug, thiserror::Error)]
pub enum PassphraseError {
    /// The secure random source or locked memory failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The embedded wordlist failed validation: the binary is damaged.
    #[error("the embedded wordlist is damaged; reinstall Keystone and check its SHA-256")]
    WordlistCorrupt,
    /// Word count outside the allowed range.
    #[error("a passphrase must have {min} to {max} words, not {found}")]
    WordCount {
        /// Words found or requested.
        found: usize,
        /// Fewest allowed.
        min: usize,
        /// Most allowed.
        max: usize,
    },
    /// A re-entered passphrase contains a word that is not in the list (1-based position).
    #[error("word {position} is not a word from the Keystone wordlist")]
    UnknownWord {
        /// 1-based position of the first unknown word.
        position: usize,
    },
    /// Re-entered text is longer than any valid passphrase.
    #[error("the passphrase text is too long")]
    InputTooLong,
    /// A word box received text that is not a list word (FR-03 AC4).
    #[error("only words from the Keystone wordlist can be entered")]
    NotAListWord,
    /// Retyping before the operator ticked "I have written down all N words".
    #[error("tick \"I have written down all {words} words\" before retyping them")]
    RetypingNotEnabled {
        /// Number of words in the passphrase.
        words: usize,
    },
    /// Word number outside 1..=N.
    #[error("there is no word number {number}")]
    NoSuchWord {
        /// The requested 1-based word number.
        number: usize,
    },
    /// Group number outside 1..=groups.
    #[error("there is no group number {group}")]
    NoSuchGroup {
        /// The requested 1-based group number.
        group: usize,
    },
    /// A group was checked before all of its words were entered.
    #[error("group {group} still has empty word boxes")]
    GroupIncomplete {
        /// The 1-based group number.
        group: usize,
    },
    /// A word in a group that is already confirmed was changed.
    #[error("group {group} is already confirmed")]
    GroupAlreadyConfirmed {
        /// The 1-based group number.
        group: usize,
    },
}

/// What a passphrase protects; fixes its allowed length (FR-03 AC2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseKind {
    /// The master (root) key: 10 to 20 words, chosen by the operator.
    Master,
    /// A sub-intermediate key: always 10 words.
    SubIntermediate,
}

/// Bits of entropy of a generated passphrase with `word_count` words (SEC-05):
/// `word_count × log2(7776)`, about 12.925 bits per word.
pub fn entropy_bits(word_count: usize) -> f64 {
    // Word counts are at most 20, so the conversion is exact.
    let words = u32::try_from(word_count).map_or(f64::INFINITY, f64::from);
    words * (WORDLIST_LEN as f64).log2()
}

/// Number of groups of [`GROUP_SIZE`] needed for `word_count` words.
pub const fn group_count(word_count: usize) -> usize {
    word_count.div_ceil(GROUP_SIZE)
}

/// A freshly generated passphrase that may still be displayed (SEC-17).
///
/// Created only by the generator. Turn it into a [`ConfirmationSession`] to confirm it.
pub struct NewPassphrase {
    /// The words joined by single spaces: the exact text that encrypts the key.
    text: SecretString,
    /// The list index of each word, 2 bytes big-endian per word.
    indices: SecretBytes,
    word_count: usize,
    kind: PassphraseKind,
}

impl NewPassphrase {
    /// Generates a master passphrase of `word_count` words (10 to 20, FR-03 AC2).
    pub fn generate_master(word_count: usize) -> Result<Self, PassphraseError> {
        if !(MASTER_MIN_WORDS..=MASTER_MAX_WORDS).contains(&word_count) {
            return Err(PassphraseError::WordCount {
                found: word_count,
                min: MASTER_MIN_WORDS,
                max: MASTER_MAX_WORDS,
            });
        }
        Self::generate(word_count, PassphraseKind::Master)
    }

    /// Generates a 10-word sub-intermediate passphrase (FR-03 AC2).
    pub fn generate_sub_intermediate() -> Result<Self, PassphraseError> {
        Self::generate(SUB_INTERMEDIATE_WORDS, PassphraseKind::SubIntermediate)
    }

    fn generate(word_count: usize, kind: PassphraseKind) -> Result<Self, PassphraseError> {
        let bound = u32::try_from(WORDLIST_LEN).map_err(|_| PassphraseError::WordlistCorrupt)?;
        let mut text = SecretString::with_capacity(SECRET_CAPACITY)?;
        let mut indices = SecretBytes::with_capacity(2 * MASTER_MAX_WORDS)?;
        for position in 0..word_count {
            let index = u16::try_from(uniform_below(bound)?)
                .map_err(|_| PassphraseError::WordlistCorrupt)?;
            let word = word_at(index).ok_or(PassphraseError::WordlistCorrupt)?;
            if position > 0 {
                text.push(' ')?;
            }
            text.push_str(word)?;
            indices.extend_from_slice(&index.to_be_bytes())?;
        }
        Ok(NewPassphrase {
            text,
            indices,
            word_count,
            kind,
        })
    }

    /// Number of words.
    pub fn word_count(&self) -> usize {
        self.word_count
    }

    /// What this passphrase protects.
    pub fn kind(&self) -> PassphraseKind {
        self.kind
    }

    /// Number of display groups of [`GROUP_SIZE`] words.
    pub fn group_count(&self) -> usize {
        group_count(self.word_count)
    }

    /// Bits of entropy (SEC-05).
    pub fn entropy_bits(&self) -> f64 {
        entropy_bits(self.word_count)
    }

    /// Word number `number` (1-based), for display only.
    pub fn word(&self, number: usize) -> Option<&'static str> {
        let index = self.index(number)?;
        word_at(index)
    }

    /// Display group `group` (1-based): its words with their 1-based numbers (FR-03 AC4).
    pub fn group(&self, group: usize) -> Option<WordGroup<'_>> {
        (1..=self.group_count())
            .contains(&group)
            .then_some(WordGroup {
                passphrase: self,
                group,
            })
    }

    /// Starts confirmation. The words stay viewable through the session until it finishes.
    pub fn into_confirmation(self) -> ConfirmationSession {
        let groups = vec![GroupState::default(); self.group_count()];
        let entries = (0..self.word_count).map(|_| None).collect();
        ConfirmationSession {
            passphrase: self,
            written_down: false,
            entries,
            groups,
        }
    }

    fn index(&self, number: usize) -> Option<u16> {
        if !(1..=self.word_count).contains(&number) {
            return None;
        }
        let bytes = self.indices.expose();
        let at = 2 * (number - 1);
        Some(u16::from_be_bytes([bytes[at], bytes[at + 1]]))
    }
}

impl fmt::Debug for NewPassphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NewPassphrase([REDACTED; {} words])", self.word_count)
    }
}

/// One numbered display group of a passphrase that is still allowed to be shown.
#[derive(Debug, Clone, Copy)]
pub struct WordGroup<'a> {
    passphrase: &'a NewPassphrase,
    group: usize,
}

impl WordGroup<'_> {
    /// The 1-based group number.
    pub fn number(&self) -> usize {
        self.group
    }

    /// The 1-based word numbers in this group.
    pub fn word_numbers(&self) -> std::ops::RangeInclusive<usize> {
        let first = (self.group - 1) * GROUP_SIZE + 1;
        let last = (first + GROUP_SIZE - 1).min(self.passphrase.word_count);
        first..=last
    }

    /// `(word number, word)` pairs for display. Nothing is copied or stored.
    pub fn numbered_words(&self) -> impl Iterator<Item = (usize, &'static str)> + '_ {
        self.word_numbers()
            .filter_map(|number| Some((number, self.passphrase.word(number)?)))
    }
}

/// Per-group confirmation state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct GroupState {
    confirmed: bool,
    needs_reentry: bool,
}

/// What a group shows in the confirmation screen (FR-03 AC4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupStatus {
    /// Some word boxes are still empty.
    Incomplete,
    /// Every box has a list word; the group can be checked.
    ReadyToCheck,
    /// The group matched and is kept; its boxes are locked.
    Confirmed,
}

/// Result of checking one group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupCheck {
    /// Every word in the group matches. The group is kept.
    Correct,
    /// At least one word is wrong. Only this group was cleared for re-entry.
    Mistake,
}

/// The confirmation state machine (FR-03 AC4). Owns the passphrase until it is confirmed.
pub struct ConfirmationSession {
    passphrase: NewPassphrase,
    written_down: bool,
    /// The list index entered in each word box (2 bytes), or `None` when empty.
    entries: Vec<Option<SecretBytes>>,
    groups: Vec<GroupState>,
}

impl ConfirmationSession {
    /// Number of words.
    pub fn word_count(&self) -> usize {
        self.passphrase.word_count
    }

    /// Number of groups.
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Text of the tick box that enables retyping (FR-03 AC4).
    pub fn written_down_prompt(&self) -> String {
        format!("I have written down all {} words", self.word_count())
    }

    /// Ticks or unticks "I have written down all N words".
    pub fn set_written_down(&mut self, ticked: bool) {
        self.written_down = ticked;
    }

    /// True once the tick box is ticked: the word boxes accept input.
    pub fn retyping_enabled(&self) -> bool {
        self.written_down
    }

    /// Go back and view the words again; allowed at any time before [`Self::finish`]
    /// (FR-03 AC4). Entered words and confirmed groups are kept.
    pub fn view_words(&self) -> &NewPassphrase {
        &self.passphrase
    }

    /// Enters text in word box `number` (1-based). Accepts only list words (surrounding
    /// whitespace and letter case ignored); anything else is refused and not stored.
    pub fn enter_word(&mut self, number: usize, text: &str) -> Result<(), PassphraseError> {
        self.ensure_editable(number)?;
        let index = index_of(text).ok_or(PassphraseError::NotAListWord)?;
        self.entries[number - 1] = Some(SecretBytes::from_slice(&index.to_be_bytes())?);
        Ok(())
    }

    /// Empties word box `number` (1-based).
    pub fn clear_word(&mut self, number: usize) -> Result<(), PassphraseError> {
        self.ensure_editable(number)?;
        self.entries[number - 1] = None;
        Ok(())
    }

    /// The list word in box `number`, so the GUI can redraw the box. `None` when empty.
    /// After a mistake the group's boxes are empty again.
    pub fn entered_word(&self, number: usize) -> Option<&'static str> {
        let entry = self.entries.get(number.checked_sub(1)?)?.as_ref()?;
        let bytes = entry.expose();
        word_at(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Status of group `group` (1-based).
    pub fn group_status(&self, group: usize) -> Result<GroupStatus, PassphraseError> {
        let state = self.group_state(group)?;
        if state.confirmed {
            return Ok(GroupStatus::Confirmed);
        }
        let filled = self
            .numbers_in(group)
            .all(|n| self.entries[n - 1].is_some());
        Ok(if filled {
            GroupStatus::ReadyToCheck
        } else {
            GroupStatus::Incomplete
        })
    }

    /// True when the last check of group `group` found a mistake and the group has not
    /// been confirmed since: the GUI marks it for re-entry.
    pub fn needs_reentry(&self, group: usize) -> Result<bool, PassphraseError> {
        Ok(self.group_state(group)?.needs_reentry)
    }

    /// Checks group `group` on its own (FR-03 AC4). On a match the group is confirmed and
    /// kept. On a mistake only this group's boxes are cleared and marked for re-entry.
    pub fn check_group(&mut self, group: usize) -> Result<GroupCheck, PassphraseError> {
        match self.group_status(group)? {
            GroupStatus::Confirmed => return Ok(GroupCheck::Correct),
            GroupStatus::Incomplete => return Err(PassphraseError::GroupIncomplete { group }),
            GroupStatus::ReadyToCheck => {}
        }
        if !self.written_down {
            return Err(self.not_enabled());
        }
        let mut expected = SecretBytes::with_capacity(2 * GROUP_SIZE)?;
        let mut entered = SecretBytes::with_capacity(2 * GROUP_SIZE)?;
        let numbers: Vec<usize> = self.numbers_in(group).collect();
        let all = self.passphrase.indices.expose();
        for &number in &numbers {
            expected.extend_from_slice(&all[2 * (number - 1)..2 * number])?;
            if let Some(entry) = &self.entries[number - 1] {
                entered.extend_from_slice(entry.expose())?;
            }
        }
        let state = &mut self.groups[group - 1];
        if expected.ct_eq(&entered) {
            state.confirmed = true;
            state.needs_reentry = false;
            Ok(GroupCheck::Correct)
        } else {
            state.needs_reentry = true;
            for number in numbers {
                self.entries[number - 1] = None;
            }
            Ok(GroupCheck::Mistake)
        }
    }

    /// True when every group is confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.groups.iter().all(|state| state.confirmed)
    }

    /// Ends confirmation. Succeeds only when every word matched; then the session is
    /// consumed and only the secret remains (SEC-17). Otherwise the session is returned
    /// unchanged so the operator can continue.
    pub fn finish(self) -> Result<ConfirmedPassphrase, ConfirmationSession> {
        if !self.is_confirmed() {
            return Err(self);
        }
        let NewPassphrase {
            text,
            word_count,
            kind,
            ..
        } = self.passphrase;
        Ok(ConfirmedPassphrase {
            text,
            word_count,
            kind,
        })
    }

    fn ensure_editable(&self, number: usize) -> Result<(), PassphraseError> {
        if !(1..=self.word_count()).contains(&number) {
            return Err(PassphraseError::NoSuchWord { number });
        }
        if !self.written_down {
            return Err(self.not_enabled());
        }
        let group = (number - 1) / GROUP_SIZE + 1;
        if self.groups[group - 1].confirmed {
            return Err(PassphraseError::GroupAlreadyConfirmed { group });
        }
        Ok(())
    }

    fn not_enabled(&self) -> PassphraseError {
        PassphraseError::RetypingNotEnabled {
            words: self.word_count(),
        }
    }

    fn group_state(&self, group: usize) -> Result<GroupState, PassphraseError> {
        group
            .checked_sub(1)
            .and_then(|at| self.groups.get(at))
            .copied()
            .ok_or(PassphraseError::NoSuchGroup { group })
    }

    fn numbers_in(&self, group: usize) -> impl Iterator<Item = usize> {
        let first = (group - 1) * GROUP_SIZE + 1;
        let last = (first + GROUP_SIZE - 1).min(self.word_count());
        first..=last
    }
}

impl fmt::Debug for ConfirmationSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfirmationSession")
            .field("word_count", &self.word_count())
            .field("written_down", &self.written_down)
            .field("groups", &self.groups)
            .finish_non_exhaustive()
    }
}

/// A generated passphrase the operator has confirmed. Holds only the secret: no method
/// displays its words (SEC-17). Use it to encrypt a new key.
///
/// ```compile_fail
/// # use keystone_core::passphrase::ConfirmedPassphrase;
/// fn show(confirmed: &ConfirmedPassphrase) -> Option<&'static str> {
///     confirmed.word(1) // there is no way to display a confirmed passphrase
/// }
/// ```
pub struct ConfirmedPassphrase {
    text: SecretString,
    word_count: usize,
    kind: PassphraseKind,
}

impl ConfirmedPassphrase {
    /// The secret: words joined by single spaces. Only the crypto module should read it.
    pub fn secret(&self) -> &SecretString {
        &self.text
    }

    /// Number of words.
    pub fn word_count(&self) -> usize {
        self.word_count
    }

    /// What this passphrase protects.
    pub fn kind(&self) -> PassphraseKind {
        self.kind
    }

    /// Bits of entropy (SEC-05).
    pub fn entropy_bits(&self) -> f64 {
        entropy_bits(self.word_count)
    }
}

impl fmt::Debug for ConfirmedPassphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ConfirmedPassphrase([REDACTED; {} words])",
            self.word_count
        )
    }
}

/// A passphrase re-entered by the operator to unlock an existing key (for example the
/// master key in Flows B, D and E). It is not a way to choose a new passphrase: use it
/// only for decryption.
pub struct EnteredPassphrase {
    text: SecretString,
    word_count: usize,
}

impl EnteredPassphrase {
    /// Parses typed text: 10 to 20 list words separated by any whitespace; letter case and
    /// extra whitespace are ignored. The secret is rebuilt from the list words joined by
    /// single spaces, so it equals the generated text exactly when the words are right.
    pub fn parse(text: &str) -> Result<Self, PassphraseError> {
        if text.len() > MAX_ENTERED_TEXT_BYTES {
            return Err(PassphraseError::InputTooLong);
        }
        let mut secret = SecretString::with_capacity(SECRET_CAPACITY)?;
        let mut word_count = 0usize;
        for (position, typed) in text.split_whitespace().enumerate() {
            if position >= MASTER_MAX_WORDS {
                return Err(PassphraseError::WordCount {
                    found: text.split_whitespace().count(),
                    min: MASTER_MIN_WORDS,
                    max: MASTER_MAX_WORDS,
                });
            }
            let word = index_of(typed)
                .and_then(word_at)
                .ok_or(PassphraseError::UnknownWord {
                    position: position + 1,
                })?;
            if position > 0 {
                secret.push(' ')?;
            }
            secret.push_str(word)?;
            word_count += 1;
        }
        if word_count < MASTER_MIN_WORDS {
            return Err(PassphraseError::WordCount {
                found: word_count,
                min: MASTER_MIN_WORDS,
                max: MASTER_MAX_WORDS,
            });
        }
        Ok(EnteredPassphrase {
            text: secret,
            word_count,
        })
    }

    /// The secret: words joined by single spaces. Only the crypto module should read it.
    pub fn secret(&self) -> &SecretString {
        &self.text
    }

    /// Number of words.
    pub fn word_count(&self) -> usize {
        self.word_count
    }
}

impl fmt::Debug for EnteredPassphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EnteredPassphrase([REDACTED; {} words])",
            self.word_count
        )
    }
}

#[cfg(test)]
mod tests;
