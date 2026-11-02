//! Tests for passphrase generation and confirmation (FR-03, SEC-05, SEC-17).
#![forbid(unsafe_code)]

use super::*;

fn words_of(passphrase: &NewPassphrase) -> Vec<&'static str> {
    (1..=passphrase.word_count())
        .map(|n| passphrase.word(n).expect("word"))
        .collect()
}

/// A list word that differs from `word`.
fn other_word(word: &str) -> &'static str {
    if word == "abacus" { "zoom" } else { "abacus" }
}

fn ready_session(words: usize) -> (ConfirmationSession, Vec<&'static str>) {
    let passphrase = NewPassphrase::generate_master(words).expect("generate");
    let list = words_of(&passphrase);
    let mut session = passphrase.into_confirmation();
    session.set_written_down(true);
    (session, list)
}

#[test]
fn fr03_ac1_generated_words_come_from_the_list_and_form_the_secret() {
    // Covers: FR-03 AC1
    let passphrase = NewPassphrase::generate_master(12).expect("generate");
    let list = words_of(&passphrase);
    assert_eq!(list.len(), 12);
    assert!(list.iter().all(|word| is_word(word)));
    let mut session = passphrase.into_confirmation();
    session.set_written_down(true);
    for (number, word) in list.iter().enumerate() {
        session.enter_word(number + 1, word).expect("enter");
    }
    for group in 1..=session.group_count() {
        assert_eq!(
            session.check_group(group).expect("check"),
            GroupCheck::Correct
        );
    }
    let confirmed = session.finish().expect("confirmed");
    // The secret is exactly the words joined by single spaces.
    assert_eq!(confirmed.secret().expose(), list.join(" "));
}

#[test]
fn fr03_ac1_generation_uses_the_secure_random_source() {
    // Covers: FR-03 AC1, SEC-05
    // 50 passphrases of 10 words: with a working random source no two are equal and many
    // different words appear (a broken or constant source would fail this).
    let mut seen = std::collections::BTreeSet::new();
    let mut distinct_words = std::collections::BTreeSet::new();
    for _ in 0..50 {
        let passphrase = NewPassphrase::generate_sub_intermediate().expect("generate");
        let list = words_of(&passphrase);
        distinct_words.extend(list.iter().copied());
        assert!(seen.insert(list.join(" ")));
    }
    assert!(distinct_words.len() > 400, "{}", distinct_words.len());
}

#[test]
fn fr03_ac2_master_length_is_10_to_20_words() {
    // Covers: FR-03 AC2, SEC-05
    for words in MASTER_MIN_WORDS..=MASTER_MAX_WORDS {
        let passphrase = NewPassphrase::generate_master(words).expect("in range");
        assert_eq!(passphrase.word_count(), words);
        assert_eq!(passphrase.kind(), PassphraseKind::Master);
    }
    for words in [0, 1, 9, 21, 100] {
        assert!(matches!(
            NewPassphrase::generate_master(words),
            Err(PassphraseError::WordCount { found, min: 10, max: 20 }) if found == words
        ));
    }
}

#[test]
fn fr03_ac2_sub_intermediate_has_10_words() {
    // Covers: FR-03 AC2, SEC-05
    let passphrase = NewPassphrase::generate_sub_intermediate().expect("generate");
    assert_eq!(passphrase.word_count(), 10);
    assert_eq!(passphrase.kind(), PassphraseKind::SubIntermediate);
}

#[test]
fn sec05_entropy_is_about_129_to_258_bits() {
    // Covers: SEC-05
    assert!((entropy_bits(1) - 12.925).abs() < 0.001);
    assert!((entropy_bits(10) - 129.25).abs() < 0.01);
    assert!((entropy_bits(20) - 258.5).abs() < 0.01);
    let passphrase = NewPassphrase::generate_master(15).expect("generate");
    assert!((passphrase.entropy_bits() - 193.88).abs() < 0.01);
}

#[test]
fn fr03_ac4_words_are_numbered_in_groups_of_four() {
    // Covers: FR-03 AC4
    let passphrase = NewPassphrase::generate_master(10).expect("generate");
    assert_eq!(passphrase.group_count(), 3);
    let first = passphrase.group(1).expect("group 1");
    assert_eq!(first.word_numbers(), 1..=4);
    let last = passphrase.group(3).expect("group 3");
    assert_eq!(last.word_numbers(), 9..=10);
    let shown: Vec<(usize, &str)> = last.numbered_words().collect();
    assert_eq!(shown.len(), 2);
    assert_eq!(shown[0], (9, passphrase.word(9).expect("w9")));
    assert!(passphrase.group(0).is_none());
    assert!(passphrase.group(4).is_none());
    assert!(passphrase.word(0).is_none());
    assert!(passphrase.word(11).is_none());
    assert_eq!(group_count(20), 5);
    assert_eq!(group_count(13), 4);
}

#[test]
fn fr03_ac4_retyping_is_enabled_only_after_the_tick() {
    // Covers: FR-03 AC4
    let passphrase = NewPassphrase::generate_master(10).expect("generate");
    let first = passphrase.word(1).expect("w1");
    let mut session = passphrase.into_confirmation();
    assert_eq!(
        session.written_down_prompt(),
        "I have written down all 10 words"
    );
    assert!(!session.retyping_enabled());
    assert!(matches!(
        session.enter_word(1, first),
        Err(PassphraseError::RetypingNotEnabled { words: 10 })
    ));
    session.set_written_down(true);
    assert!(session.retyping_enabled());
    session.enter_word(1, first).expect("enabled");
    // Unticking disables retyping again but keeps what was entered.
    session.set_written_down(false);
    assert!(session.clear_word(1).is_err());
    assert_eq!(session.entered_word(1), Some(first));
}

#[test]
fn fr03_ac4_word_boxes_accept_only_list_words() {
    // Covers: FR-03 AC4, FR-03 AC1
    let (mut session, list) = ready_session(10);
    assert!(matches!(
        session.enter_word(1, "notaword"),
        Err(PassphraseError::NotAListWord)
    ));
    assert!(matches!(
        session.enter_word(1, ""),
        Err(PassphraseError::NotAListWord)
    ));
    assert_eq!(session.entered_word(1), None);
    // Case and surrounding whitespace are ignored, as the autocomplete does.
    let shouted = format!("  {}  ", list[0].to_ascii_uppercase());
    session.enter_word(1, &shouted).expect("list word");
    assert_eq!(session.entered_word(1), Some(list[0]));
    assert!(matches!(
        session.enter_word(11, list[0]),
        Err(PassphraseError::NoSuchWord { number: 11 })
    ));
    assert!(matches!(
        session.enter_word(0, list[0]),
        Err(PassphraseError::NoSuchWord { number: 0 })
    ));
}

#[test]
fn fr03_ac4_each_group_is_checked_on_its_own_and_a_mistake_clears_only_that_group() {
    // Covers: FR-03 AC4
    let (mut session, list) = ready_session(12);
    // Group 1 correct.
    for n in 1..=4 {
        session.enter_word(n, list[n - 1]).expect("enter");
    }
    assert_eq!(
        session.group_status(1).expect("g1"),
        GroupStatus::ReadyToCheck
    );
    assert_eq!(session.check_group(1).expect("check"), GroupCheck::Correct);
    assert_eq!(session.group_status(1).expect("g1"), GroupStatus::Confirmed);
    // Group 2 with one wrong word; group 3 filled correctly but not yet checked.
    for n in 5..=8 {
        let word = if n == 7 {
            other_word(list[6])
        } else {
            list[n - 1]
        };
        session.enter_word(n, word).expect("enter");
    }
    for n in 9..=12 {
        session.enter_word(n, list[n - 1]).expect("enter");
    }
    assert_eq!(session.check_group(2).expect("check"), GroupCheck::Mistake);
    // Only group 2 is marked and cleared; groups 1 and 3 keep their words.
    assert!(session.needs_reentry(2).expect("g2"));
    assert!(!session.needs_reentry(1).expect("g1"));
    assert!(!session.needs_reentry(3).expect("g3"));
    for n in 5..=8 {
        assert_eq!(session.entered_word(n), None, "box {n} cleared");
    }
    assert_eq!(session.group_status(1).expect("g1"), GroupStatus::Confirmed);
    assert_eq!(session.entered_word(1), Some(list[0]));
    assert_eq!(session.entered_word(9), Some(list[8]));
    assert_eq!(
        session.group_status(3).expect("g3"),
        GroupStatus::ReadyToCheck
    );
    // A confirmed group cannot be changed.
    assert!(matches!(
        session.enter_word(2, list[1]),
        Err(PassphraseError::GroupAlreadyConfirmed { group: 1 })
    ));
    // An incomplete group cannot be checked.
    assert!(matches!(
        session.check_group(2),
        Err(PassphraseError::GroupIncomplete { group: 2 })
    ));
    // Re-entering group 2 correctly confirms it and clears the mark.
    for n in 5..=8 {
        session.enter_word(n, list[n - 1]).expect("enter");
    }
    assert_eq!(session.check_group(2).expect("check"), GroupCheck::Correct);
    assert!(!session.needs_reentry(2).expect("g2"));
    assert_eq!(session.check_group(3).expect("check"), GroupCheck::Correct);
    assert!(session.is_confirmed());
    assert!(session.finish().is_ok());
}

#[test]
fn fr03_ac4_words_can_be_viewed_again_before_confirming() {
    // Covers: FR-03 AC4
    let (mut session, list) = ready_session(10);
    for n in 1..=4 {
        session.enter_word(n, list[n - 1]).expect("enter");
    }
    session.check_group(1).expect("check");
    // Go back and view the words: the same words, and progress is kept.
    let viewed = session.view_words();
    assert_eq!(words_of(viewed), list);
    assert_eq!(session.group_status(1).expect("g1"), GroupStatus::Confirmed);
}

#[test]
fn fr03_ac4_flow_continues_only_when_every_word_matches() {
    // Covers: FR-03 AC4, FR-03 AC3
    let (mut session, list) = ready_session(10);
    // Nothing entered: finish refuses and gives the session back.
    session = session.finish().expect_err("not confirmed");
    for n in 1..=8 {
        session.enter_word(n, list[n - 1]).expect("enter");
    }
    session.check_group(1).expect("g1");
    session.check_group(2).expect("g2");
    // Last group wrong.
    session.enter_word(9, list[8]).expect("enter");
    session.enter_word(10, other_word(list[9])).expect("enter");
    assert_eq!(session.check_group(3).expect("g3"), GroupCheck::Mistake);
    assert!(!session.is_confirmed());
    session = session.finish().expect_err("one group wrong");
    session.enter_word(9, list[8]).expect("enter");
    session.enter_word(10, list[9]).expect("enter");
    assert_eq!(session.check_group(3).expect("g3"), GroupCheck::Correct);
    let confirmed = session.finish().expect("all match");
    assert_eq!(confirmed.word_count(), 10);
    assert_eq!(confirmed.kind(), PassphraseKind::Master);
}

#[test]
fn sec17_confirmed_passphrase_cannot_be_displayed() {
    // Covers: SEC-17, FR-03 AC3, SEC-07
    // The only access left after confirmation is the secret for encryption. The
    // compile_fail doc test on `ConfirmedPassphrase` proves there is no word accessor;
    // here we check nothing leaks through Debug.
    let (mut session, list) = ready_session(10);
    for (n, word) in list.iter().enumerate() {
        session.enter_word(n + 1, word).expect("enter");
    }
    let debug_session = format!("{session:?}");
    assert!(!list.iter().any(|word| debug_session.contains(word)));
    let debug_new = format!("{:?}", session.view_words());
    assert!(!list.iter().any(|word| debug_new.contains(word)));
    for group in 1..=3 {
        session.check_group(group).expect("check");
    }
    let confirmed = session.finish().expect("confirmed");
    let shown = format!("{confirmed:?}");
    assert!(shown.contains("REDACTED"));
    assert!(!list.iter().any(|word| shown.contains(word)));
    assert!((confirmed.entropy_bits() - 129.25).abs() < 0.01);
}

#[test]
fn fr03_ac1_entered_passphrase_accepts_only_list_words() {
    // Covers: FR-03 AC1
    let passphrase = NewPassphrase::generate_master(10).expect("generate");
    let list = words_of(&passphrase);
    let messy = format!(
        "  {}\n\t{}  ",
        list[..5].join("   "),
        list[5..].join(" ").to_uppercase()
    );
    let entered = EnteredPassphrase::parse(&messy).expect("valid");
    assert_eq!(entered.secret().expose(), list.join(" "));
    assert_eq!(entered.word_count(), 10);
    assert!(!format!("{entered:?}").contains(list[0]));

    let mut wrong = list.clone();
    wrong[3] = "notaword";
    assert!(matches!(
        EnteredPassphrase::parse(&wrong.join(" ")),
        Err(PassphraseError::UnknownWord { position: 4 })
    ));
    assert!(matches!(
        EnteredPassphrase::parse(&list[..9].join(" ")),
        Err(PassphraseError::WordCount { found: 9, .. })
    ));
    let too_many = vec!["abacus"; 21].join(" ");
    assert!(matches!(
        EnteredPassphrase::parse(&too_many),
        Err(PassphraseError::WordCount { found: 21, .. })
    ));
    let huge = "abacus ".repeat(500);
    assert!(matches!(
        EnteredPassphrase::parse(&huge),
        Err(PassphraseError::InputTooLong)
    ));
}

#[test]
fn errors_never_contain_the_passphrase() {
    // Covers: SEC-07, FR-03 AC3
    let (mut session, list) = ready_session(10);
    let error = session.enter_word(1, "notaword").expect_err("refused");
    let text = error.to_string();
    assert!(!text.contains("notaword"));
    assert!(!list.iter().any(|word| text.contains(word)));
}

proptest::proptest! {
    #[test]
    fn entered_passphrase_parser_never_panics(text in ".{0,1100}") {
        // Covers: SEC-08
        let _ = EnteredPassphrase::parse(&text);
        let _ = is_word(&text);
        let _ = complete(&text);
    }
}
