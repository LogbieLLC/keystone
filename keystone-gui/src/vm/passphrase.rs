//! Passphrase show-once and confirmation (FR-03 AC3, AC4, SEC-17).
//!
//! The state machine is core's `passphrase::ConfirmationSession`; the word list,
//! `is_word` and `complete` are core's too. This module phrases group states and word
//! box feedback for a tired person:
//! - every group says in words whether it is incomplete, ready, confirmed or must be
//!   typed again (never colour alone);
//! - a word box autocompletes when the typed letters fit exactly one list word, and
//!   otherwise lists a few matching words;
//! - only list words are accepted.
#![forbid(unsafe_code)]

use keystone_core::passphrase::{
    ConfirmationSession, GROUP_SIZE, GroupStatus, PassphraseError, complete, is_word,
};

use super::{Line, Status};

/// Most suggestions shown under a word box.
pub const MAX_SUGGESTIONS: usize = 5;

/// The 1-based word numbers of group `group` for `word_count` words.
pub fn group_words(group: usize, word_count: usize) -> std::ops::RangeInclusive<usize> {
    let first = (group - 1) * GROUP_SIZE + 1;
    let last = (first + GROUP_SIZE - 1).min(word_count);
    first..=last
}

/// "Group 2: words 5 to 8".
pub fn group_heading(group: usize, word_count: usize) -> String {
    let words = group_words(group, word_count);
    if words.start() == words.end() {
        format!("Group {group}: word {}", words.start())
    } else {
        format!("Group {group}: words {} to {}", words.start(), words.end())
    }
}

/// The status line of one group on the retyping screen.
pub fn group_line(session: &ConfirmationSession, group: usize) -> Result<Line, PassphraseError> {
    let words = group_words(group, session.word_count());
    let count = words.end() - words.start() + 1;
    let status = session.group_status(group)?;
    let reentry = session.needs_reentry(group)?;
    Ok(match status {
        GroupStatus::Confirmed => {
            Line::new(Status::Ok, format!("Group {group} matches and is kept."))
        }
        GroupStatus::ReadyToCheck => Line::new(
            Status::Info,
            format!("Group {group} is ready: press Check group {group}."),
        ),
        GroupStatus::Incomplete if reentry => Line::new(
            Status::Blocked,
            format!(
                "Group {group} does not match. Type these {count} words again; the other groups are kept."
            ),
        ),
        GroupStatus::Incomplete => Line::new(
            Status::Info,
            format!("Group {group}: type all {count} words."),
        ),
    })
}

/// The overall line under the groups.
pub fn summary_line(session: &ConfirmationSession) -> Line {
    if !session.retyping_enabled() {
        return Line::new(
            Status::Blocked,
            format!(
                "Retyping is enabled only after you tick \"I have written down all {} words\" on the words screen.",
                session.word_count()
            ),
        );
    }
    let confirmed = (1..=session.group_count())
        .filter(|g| matches!(session.group_status(*g), Ok(GroupStatus::Confirmed)))
        .count();
    if session.is_confirmed() {
        Line::new(
            Status::Ok,
            "Every word matches. Press Confirm passphrase to continue; the words will not be shown again.",
        )
    } else {
        Line::new(
            Status::Info,
            format!(
                "{confirmed} of {} groups match. Keystone continues only when every word matches.",
                session.group_count()
            ),
        )
    }
}

/// What a word box shows under itself while the operator types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WordFeedback {
    /// Nothing typed.
    Empty,
    /// A word from the list.
    ListWord,
    /// The start of these list words (at most [`MAX_SUGGESTIONS`]) and how many match.
    Prefix {
        /// A few matching words.
        suggestions: Vec<&'static str>,
        /// Number of matching words.
        total: usize,
    },
    /// Not a word from the list and not the start of one.
    NotAWord,
}

/// Feedback for the text in a word box.
pub fn word_feedback(text: &str) -> WordFeedback {
    let typed = text.trim();
    if typed.is_empty() {
        return WordFeedback::Empty;
    }
    if is_word(typed) {
        return WordFeedback::ListWord;
    }
    let matches = complete(typed);
    if matches.is_empty() {
        WordFeedback::NotAWord
    } else {
        WordFeedback::Prefix {
            suggestions: matches.iter().take(MAX_SUGGESTIONS).copied().collect(),
            total: matches.len(),
        }
    }
}

/// The text under a word box (empty when nothing needs saying).
pub fn feedback_text(feedback: &WordFeedback) -> String {
    match feedback {
        WordFeedback::Empty | WordFeedback::ListWord => String::new(),
        WordFeedback::Prefix { suggestions, total } if *total == 1 => {
            format!("Press Enter or Tab to complete: {}", suggestions[0])
        }
        WordFeedback::Prefix { suggestions, total } => format!(
            "{total} words start like this: {}{}",
            suggestions.join(", "),
            if *total > suggestions.len() {
                ", …"
            } else {
                ""
            }
        ),
        WordFeedback::NotAWord => "Not a word from the list. Check the spelling.".to_string(),
    }
}

/// Autocomplete: the one list word the typed text can complete to, if exactly one.
pub fn autocomplete(text: &str) -> Option<&'static str> {
    match complete(text.trim()) {
        [only] => Some(only),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::passphrase::{GroupCheck, NewPassphrase};

    fn session(words: usize) -> (ConfirmationSession, Vec<&'static str>) {
        let session = NewPassphrase::generate_master(words)
            .expect("generate")
            .into_confirmation();
        let list = (1..=words)
            .map(|n| session.view_words().word(n).expect("word"))
            .collect();
        (session, list)
    }

    fn other_word(not: &str) -> &'static str {
        ["abacus", "zoom"]
            .into_iter()
            .find(|w| *w != not)
            .expect("word")
    }

    #[test]
    fn fr03_ac4_groups_of_four_numbered_from_one() {
        // Covers: FR-03 AC4
        assert_eq!(group_words(1, 10), 1..=4);
        assert_eq!(group_words(3, 10), 9..=10);
        assert_eq!(group_heading(2, 10), "Group 2: words 5 to 8");
        assert_eq!(group_heading(4, 13), "Group 4: word 13");
    }

    #[test]
    fn fr03_ac4_retyping_needs_the_tick() {
        // Covers: FR-03 AC4
        let (mut session, _) = session(10);
        let line = summary_line(&session);
        assert_eq!(line.status, Status::Blocked);
        assert!(line.text.contains("I have written down all 10 words"));
        session.set_written_down(true);
        assert_eq!(summary_line(&session).status, Status::Info);
    }

    #[test]
    fn fr03_ac4_a_mistake_marks_only_that_group() {
        // Covers: FR-03 AC4
        let (mut session, words) = session(10);
        session.set_written_down(true);
        for n in 1..=8 {
            let typed = if n == 6 {
                other_word(words[5])
            } else {
                words[n - 1]
            };
            session.enter_word(n, typed).expect("enter");
        }
        assert_eq!(session.check_group(1).expect("check"), GroupCheck::Correct);
        assert_eq!(session.check_group(2).expect("check"), GroupCheck::Mistake);
        let first = group_line(&session, 1).expect("line");
        let second = group_line(&session, 2).expect("line");
        let third = group_line(&session, 3).expect("line");
        assert_eq!(first.status, Status::Ok);
        assert!(first.text.contains("matches and is kept"));
        assert_eq!(second.status, Status::Blocked);
        assert!(second.text.contains("Type these 4 words again"));
        assert_eq!(third.status, Status::Info);
        assert!(third.text.contains("type all 2 words"));
        assert!(summary_line(&session).text.contains("1 of 3 groups match"));
    }

    #[test]
    fn fr03_ac4_word_boxes_accept_only_list_words_and_autocomplete() {
        // Covers: FR-03 AC4
        assert_eq!(word_feedback(""), WordFeedback::Empty);
        assert_eq!(word_feedback("abacus"), WordFeedback::ListWord);
        assert_eq!(word_feedback("ABACUS "), WordFeedback::ListWord);
        assert_eq!(word_feedback("qqq"), WordFeedback::NotAWord);
        assert!(feedback_text(&word_feedback("qqq")).contains("Not a word"));
        let WordFeedback::Prefix { suggestions, total } = word_feedback("ab") else {
            panic!("expected a prefix");
        };
        assert!(total > MAX_SUGGESTIONS);
        assert_eq!(suggestions.len(), MAX_SUGGESTIONS);
        assert!(feedback_text(&word_feedback("ab")).ends_with(", …"));
        assert_eq!(autocomplete("abac"), Some("abacus"));
        assert_eq!(autocomplete("ab"), None);
        assert_eq!(autocomplete(""), None);
        assert!(feedback_text(&word_feedback("abac")).contains("complete: abacus"));
    }

    #[test]
    fn fr03_ac4_all_groups_matching_allows_finishing() {
        // Covers: FR-03 AC4
        let (mut session, words) = session(10);
        session.set_written_down(true);
        for (index, word) in words.iter().enumerate() {
            session.enter_word(index + 1, word).expect("enter");
        }
        for group in 1..=3 {
            assert!(
                group_line(&session, group)
                    .expect("line")
                    .text
                    .contains("ready")
            );
            session.check_group(group).expect("check");
        }
        assert_eq!(summary_line(&session).status, Status::Ok);
        assert!(session.finish().is_ok());
    }
}
