//! Passphrase show-once and confirmation (FR-03 AC3, AC4, SEC-07, SEC-17).
//!
//! - The words are shown on a dedicated screen, numbered, in groups of 4, with a hide
//!   control. Labels are not selectable, so nothing can be copied or dragged.
//! - "I have written down all N words" enables retyping.
//! - One box per word; each box autocompletes from the wordlist (Enter or Tab completes
//!   a unique match) and accepts only list words. Boxes refuse copy, cut, paste and
//!   selection and keep no undo history.
//! - Each group is checked on its own; a mistake clears and marks only that group.
//! - "View the words again" works until the final confirmation.
//! - On confirmation the session is consumed (core `ConfirmationSession::finish`), both
//!   screens are removed from the window and the words are never shown again. They are
//!   never put in an accessible description, the clipboard, a file or a log.
#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::rc::Rc;

use gtk::prelude::*;
use keystone_core::passphrase::{
    ConfirmationSession, ConfirmedPassphrase, GroupCheck, GroupStatus, MAX_WORD_LEN, NewPassphrase,
    is_word,
};

use super::App;
use super::widgets::{self, PageBuilder, StatusLine};
use crate::secrets::harden_entry;
use crate::vm::passphrase::{
    autocomplete, feedback_text, group_heading, group_line, group_words, summary_line,
    word_feedback,
};
use crate::vm::{Line, Status};

/// Page ids.
pub const SHOW_ID: &str = "passphrase-words";
/// Page id of the retyping screen.
pub const CONFIRM_ID: &str = "passphrase-confirm";

type Confirmed = Box<dyn FnOnce(&Rc<App>, ConfirmedPassphrase)>;
type Aborted = Box<dyn FnOnce(&Rc<App>)>;

struct Run {
    app: Rc<App>,
    session: RefCell<Option<ConfirmationSession>>,
    what: String,
    on_confirmed: RefCell<Option<Confirmed>>,
    on_abort: RefCell<Option<Aborted>>,
    /// Widgets of the show screen that hold words (cleared before removal).
    word_labels: RefCell<Vec<gtk::Label>>,
    tick: RefCell<Option<gtk::CheckButton>>,
    confirm: RefCell<Option<Rc<ConfirmScreen>>>,
}

struct ConfirmScreen {
    entries: Vec<gtk::Entry>,
    feedback: Vec<gtk::Label>,
    group_lines: Vec<StatusLine>,
    check_buttons: Vec<gtk::Button>,
    summary: StatusLine,
    confirm_button: gtk::Button,
}

/// Starts show-once and confirmation for a newly generated passphrase. `what` names
/// the key it protects ("master", "sub-intermediate"). Exactly one of the callbacks
/// runs.
pub fn start(
    app: &Rc<App>,
    passphrase: NewPassphrase,
    what: &str,
    on_confirmed: impl FnOnce(&Rc<App>, ConfirmedPassphrase) + 'static,
    on_abort: impl FnOnce(&Rc<App>) + 'static,
) {
    let run = Rc::new(Run {
        app: app.clone(),
        session: RefCell::new(Some(passphrase.into_confirmation())),
        what: what.to_string(),
        on_confirmed: RefCell::new(Some(Box::new(on_confirmed))),
        on_abort: RefCell::new(Some(Box::new(on_abort))),
        word_labels: RefCell::new(Vec::new()),
        tick: RefCell::new(None),
        confirm: RefCell::new(None),
    });
    show_words(&run);
}

/// Removes both screens and forgets every widget that showed a word.
fn tear_down(run: &Rc<Run>) {
    for label in run.word_labels.borrow_mut().drain(..) {
        label.set_text("");
    }
    if let Some(screen) = run.confirm.borrow_mut().take() {
        for entry in &screen.entries {
            entry.set_text("");
        }
        for label in &screen.feedback {
            label.set_text("");
        }
    }
    run.tick.borrow_mut().take();
    run.app.remove(SHOW_ID);
    run.app.remove(CONFIRM_ID);
}

fn abort(run: &Rc<Run>) {
    run.session.borrow_mut().take();
    tear_down(run);
    if let Some(on_abort) = run.on_abort.borrow_mut().take() {
        on_abort(&run.app);
    }
}

fn show_words(run: &Rc<Run>) {
    if run.app.back_to(SHOW_ID) {
        return;
    }
    let session_ref = run.session.borrow();
    let Some(session) = session_ref.as_ref() else {
        return;
    };
    let words = session.view_words();
    let count = words.word_count();
    let mut page = PageBuilder::new(
        "Write down your passphrase",
        Some(&format!(
            "These {count} words are the passphrase of the {}. Write them on paper, in order, now. They are shown only until you confirm them and never again. Keystone never saves them, never logs them and never puts them on the clipboard.",
            run.what
        )),
    );
    let hide = gtk::ToggleButton::with_label("Hide the words");
    hide.set_halign(gtk::Align::Start);
    page.add(&hide);
    let hidden_note = StatusLine::new(&Line::new(
        Status::Info,
        "The words are hidden. Press Show the words to see them again.",
    ));
    hidden_note.set_visible(false);
    page.add(hidden_note.widget());
    let grid = gtk::Grid::new();
    grid.set_column_spacing(24);
    grid.set_row_spacing(18);
    let mut labels = Vec::new();
    for group in 1..=words.group_count() {
        let Some(display) = words.group(group) else {
            continue;
        };
        let column = gtk::Box::new(gtk::Orientation::Vertical, 6);
        let title = gtk::Label::new(Some(&format!("Group {group}")));
        title.add_css_class("heading");
        title.set_xalign(0.0);
        column.append(&title);
        for (number, word) in display.numbered_words() {
            let label = gtk::Label::new(Some(&format!("{number}. {word}")));
            label.add_css_class("title-3");
            label.add_css_class("monospace");
            label.set_xalign(0.0);
            label.set_selectable(false);
            column.append(&label);
            labels.push(label);
        }
        let index = i32::try_from(group - 1).unwrap_or(0);
        grid.attach(&column, index % 3, index / 3, 1, 1);
    }
    run.word_labels.borrow_mut().extend(labels);
    page.add(&grid);
    let tick = gtk::CheckButton::with_label(&session.written_down_prompt());
    tick.set_active(session.retyping_enabled());
    tick.set_margin_top(12);
    page.add(&tick);
    drop(session_ref);
    let cancel = page.secondary_button("_Cancel");
    let retype = page.primary_button("_Retype the words");
    retype.set_sensitive(tick.is_active());
    {
        let grid = grid.clone();
        hide.connect_toggled(move |hide| {
            let hidden = hide.is_active();
            grid.set_visible(!hidden);
            hidden_note.set_visible(hidden);
            hide.set_label(if hidden {
                "Show the words"
            } else {
                "Hide the words"
            });
        });
    }
    {
        let run = run.clone();
        let retype = retype.clone();
        tick.connect_toggled(move |tick| {
            if let Some(session) = run.session.borrow_mut().as_mut() {
                session.set_written_down(tick.is_active());
            }
            retype.set_sensitive(tick.is_active());
            if let Some(screen) = run.confirm.borrow().as_ref() {
                refresh(&run, screen);
            }
        });
    }
    run.tick.borrow_mut().replace(tick.clone());
    {
        let run = run.clone();
        cancel.connect_clicked(move |_| abort(&run));
    }
    {
        let run = run.clone();
        retype.connect_clicked(move |_| show_confirm(&run));
    }
    page.focus_on(&tick);
    run.app.push(SHOW_ID, &page.build());
}

fn show_confirm(run: &Rc<Run>) {
    if let Some(screen) = run.confirm.borrow().as_ref() {
        refresh(run, screen);
    }
    if run.confirm.borrow().is_some() && run.app.back_to(CONFIRM_ID) {
        return;
    }
    let (count, groups) = match run.session.borrow().as_ref() {
        Some(session) => (session.word_count(), session.group_count()),
        None => return,
    };
    let mut page = PageBuilder::new(
        "Type the words again",
        Some(
            "Type each word from your paper record. Each box accepts only words from the list: type the first letters and press Enter or Tab to complete a word. Check each group when it is filled in; a mistake marks only that group.",
        ),
    );
    let summary = StatusLine::new(&Line::new(Status::Info, ""));
    page.add(summary.widget());
    let mut entries = Vec::new();
    let mut feedback = Vec::new();
    let mut group_lines = Vec::new();
    let mut check_buttons = Vec::new();
    for group in 1..=groups {
        let (frame, inner) = widgets::group(&group_heading(group, count));
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        for number in group_words(group, count) {
            let cell = gtk::Box::new(gtk::Orientation::Vertical, 4);
            let label = gtk::Label::with_mnemonic(&format!("Word {number}"));
            label.set_xalign(0.0);
            let entry = gtk::Entry::new();
            entry.set_max_length(i32::try_from(MAX_WORD_LEN + 4).unwrap_or(13));
            entry.set_width_chars(12);
            entry.set_input_purpose(gtk::InputPurpose::FreeForm);
            entry.set_input_hints(gtk::InputHints::NO_SPELLCHECK | gtk::InputHints::LOWERCASE);
            harden_entry(&entry);
            label.set_mnemonic_widget(Some(&entry));
            let hint = gtk::Label::new(None);
            hint.set_xalign(0.0);
            hint.set_wrap(true);
            hint.set_max_width_chars(22);
            hint.add_css_class("caption");
            cell.append(&label);
            cell.append(&entry);
            cell.append(&hint);
            row.append(&cell);
            entries.push(entry);
            feedback.push(hint);
        }
        inner.append(&row);
        let line = StatusLine::new(&Line::new(Status::Info, ""));
        inner.append(line.widget());
        let check = gtk::Button::with_label(&format!("Check group {group}"));
        check.set_halign(gtk::Align::Start);
        inner.append(&check);
        group_lines.push(line);
        check_buttons.push(check);
        page.add(&frame);
    }
    let back = page.secondary_button("_View the words again");
    let cancel = page.secondary_button("_Cancel");
    let confirm_button = page.primary_button("C_onfirm passphrase");
    if let Some(first) = entries.first() {
        page.focus_on(first);
    }
    let screen = Rc::new(ConfirmScreen {
        entries,
        feedback,
        group_lines,
        check_buttons,
        summary,
        confirm_button,
    });
    for (index, entry) in screen.entries.iter().enumerate() {
        let number = index + 1;
        let weak_run = Rc::downgrade(run);
        let weak_screen = Rc::downgrade(&screen);
        entry.connect_changed(move |entry| {
            let (Some(run), Some(screen)) = (weak_run.upgrade(), weak_screen.upgrade()) else {
                return;
            };
            on_word_changed(&run, &screen, number, &entry.text());
        });
        let weak_run = Rc::downgrade(run);
        let weak_screen = Rc::downgrade(&screen);
        entry.connect_activate(move |entry| {
            complete_box(entry);
            let (Some(_run), Some(screen)) = (weak_run.upgrade(), weak_screen.upgrade()) else {
                return;
            };
            focus_after(&screen, number);
        });
        let focus = gtk::EventControllerFocus::new();
        let target = entry.clone();
        focus.connect_leave(move |_| complete_box(&target));
        entry.add_controller(focus);
    }
    for (index, button) in screen.check_buttons.iter().enumerate() {
        let group = index + 1;
        let weak_run = Rc::downgrade(run);
        let weak_screen = Rc::downgrade(&screen);
        button.connect_clicked(move |_| {
            let (Some(run), Some(screen)) = (weak_run.upgrade(), weak_screen.upgrade()) else {
                return;
            };
            check_group(&run, &screen, group);
        });
    }
    {
        let run = run.clone();
        back.connect_clicked(move |_| show_words(&run));
    }
    {
        let run = run.clone();
        cancel.connect_clicked(move |_| abort(&run));
    }
    {
        let run = run.clone();
        screen.confirm_button.connect_clicked(move |_| finish(&run));
    }
    refresh(run, &screen);
    run.confirm.borrow_mut().replace(screen);
    run.app.push(CONFIRM_ID, &page.build());
}

/// Autocomplete: a unique match replaces the typed letters.
fn complete_box(entry: &gtk::Entry) {
    let text = entry.text();
    if !text.is_empty()
        && !is_word(&text)
        && let Some(word) = autocomplete(&text)
    {
        entry.set_text(word);
        entry.set_position(-1);
    }
}

fn focus_after(screen: &ConfirmScreen, number: usize) {
    let group = (number - 1) / keystone_core::passphrase::GROUP_SIZE;
    let last_in_group = screen
        .entries
        .iter()
        .enumerate()
        .filter(|(i, _)| i / keystone_core::passphrase::GROUP_SIZE == group)
        .map(|(i, _)| i + 1)
        .max()
        .unwrap_or(number);
    if number == last_in_group {
        if let Some(button) = screen.check_buttons.get(group) {
            button.grab_focus();
        }
    } else if let Some(next) = screen.entries.get(number) {
        next.grab_focus();
    }
}

fn on_word_changed(run: &Rc<Run>, screen: &ConfirmScreen, number: usize, text: &str) {
    let feedback = word_feedback(text);
    if let Some(label) = screen.feedback.get(number - 1) {
        label.set_text(&feedback_text(&feedback));
    }
    if let Some(session) = run.session.borrow_mut().as_mut() {
        // Only list words are stored; anything else empties the box's stored word.
        // A refusal (group already confirmed, retyping not enabled) changes nothing.
        let _ = if is_word(text) {
            session.enter_word(number, text)
        } else {
            session.clear_word(number)
        };
    }
    refresh(run, screen);
}

fn check_group(run: &Rc<Run>, screen: &ConfirmScreen, group: usize) {
    let result = match run.session.borrow_mut().as_mut() {
        Some(session) => session.check_group(group),
        None => return,
    };
    let count = run
        .session
        .borrow()
        .as_ref()
        .map_or(0, ConfirmationSession::word_count);
    let numbers = group_words(group, count);
    match result {
        Ok(GroupCheck::Correct) => {
            for number in numbers {
                if let Some(entry) = screen.entries.get(number - 1) {
                    entry.set_text("");
                    entry.set_placeholder_text(Some("matches"));
                }
            }
            refresh(run, screen);
            let next = screen
                .entries
                .iter()
                .find(|e| e.is_sensitive() && e.text().is_empty())
                .map(|e| e.clone().upcast::<gtk::Widget>())
                .unwrap_or_else(|| screen.confirm_button.clone().upcast());
            next.grab_focus();
        }
        Ok(GroupCheck::Mistake) => {
            let first = *numbers.start();
            for number in numbers {
                if let Some(entry) = screen.entries.get(number - 1) {
                    entry.set_text("");
                }
            }
            refresh(run, screen);
            if let Some(entry) = screen.entries.get(first - 1) {
                entry.grab_focus();
            }
        }
        Err(error) => {
            screen
                .summary
                .set(&Line::new(Status::Blocked, error.to_string()));
        }
    }
}

fn refresh(run: &Rc<Run>, screen: &ConfirmScreen) {
    let session_ref = run.session.borrow();
    let Some(session) = session_ref.as_ref() else {
        return;
    };
    let enabled = session.retyping_enabled();
    for group in 1..=session.group_count() {
        let status = session.group_status(group).ok();
        let confirmed = status == Some(GroupStatus::Confirmed);
        for number in group_words(group, session.word_count()) {
            if let Some(entry) = screen.entries.get(number - 1) {
                entry.set_sensitive(enabled && !confirmed);
            }
        }
        if let Ok(line) = group_line(session, group) {
            screen.group_lines[group - 1].set(&line);
        }
        screen.check_buttons[group - 1]
            .set_sensitive(enabled && status == Some(GroupStatus::ReadyToCheck));
    }
    screen.summary.set(&summary_line(session));
    screen.confirm_button.set_sensitive(session.is_confirmed());
}

fn finish(run: &Rc<Run>) {
    let Some(session) = run.session.borrow_mut().take() else {
        return;
    };
    match session.finish() {
        Ok(confirmed) => {
            tear_down(run);
            if let Some(on_confirmed) = run.on_confirmed.borrow_mut().take() {
                on_confirmed(&run.app, confirmed);
            }
        }
        Err(session) => {
            run.session.borrow_mut().replace(session);
            if let Some(screen) = run.confirm.borrow().as_ref() {
                refresh(run, screen);
            }
        }
    }
}

/// Test hook (development builds): generate a master passphrase and open its
/// show-once screen directly, then report the outcome on a plain screen.
#[cfg(not(feature = "production"))]
pub fn start_test_hook(app: &Rc<App>, words: usize) {
    let passphrase = match NewPassphrase::generate_master(words) {
        Ok(passphrase) => passphrase,
        Err(error) => {
            hook_result(app, &Line::new(Status::Blocked, error.to_string()));
            return;
        }
    };
    start(
        app,
        passphrase,
        "master (test hook)",
        |app, confirmed| {
            use keystone_core::passphrase::PassphraseKind;
            let kind = match confirmed.kind() {
                PassphraseKind::Master => "master",
                PassphraseKind::SubIntermediate => "sub-intermediate",
            };
            let text = format!(
                "Passphrase confirmed: {} words for the {kind}, about {:.0} bits. It will not be shown again.",
                confirmed.word_count(),
                confirmed.entropy_bits()
            );
            drop(confirmed);
            hook_result(app, &Line::new(Status::Ok, text));
        },
        |app| {
            hook_result(
                app,
                &Line::new(Status::Info, "Passphrase confirmation cancelled."),
            )
        },
    );
}

#[cfg(not(feature = "production"))]
fn hook_result(app: &Rc<App>, line: &Line) {
    let mut page = PageBuilder::new("Passphrase test hook", None);
    page.add(StatusLine::new(line).widget());
    let quit = page.primary_button("_Quit");
    let window = app.window.clone();
    quit.connect_clicked(move |_| window.close());
    app.reset_to("passphrase-hook", &page.build());
}
