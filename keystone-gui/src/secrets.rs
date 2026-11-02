//! Secrets in the GUI (SEC-07, SEC-17, FR-03 AC3).
//!
//! - PIN, PUK and passphrase text is copied out of its entry into a core
//!   `SecretString` (locked, wiped on drop) only when the operator submits it, and the
//!   entry is cleared right after. While typing, only the length is read.
//! - Every entry that holds secret text refuses copy, cut, paste and selection (so
//!   nothing can be dragged out), and keeps no undo history.
//! - Nothing here logs or prints a secret.
//!
//! Limits of GTK (documented, not hidden): `gtk_editable_get_text` returns one
//! short-lived copy that GLib frees without wiping; `PasswordEntry` keeps its own text
//! in GTK's secure, wiped buffer. Word boxes on the confirmation screen show the typed
//! word by design (FR-03 AC4) and are cleared as soon as their group is checked.
#![forbid(unsafe_code)]

use gtk::prelude::*;

use keystone_core::crypto::CryptoError;
use keystone_core::crypto::secret::SecretString;

/// Copies the entry's text into a [`SecretString`] and clears the entry at once.
pub fn take_secret(entry: &impl IsA<gtk::Editable>) -> Result<SecretString, CryptoError> {
    let editable = entry.as_ref();
    let secret = {
        let text = editable.text();
        SecretString::from_str_copy(text.as_str())
    };
    editable.set_text("");
    secret
}

/// The inner `GtkText` of an entry (where the clipboard signals live).
fn inner_text(editable: &gtk::Editable) -> Option<gtk::Text> {
    if let Some(text) = editable.downcast_ref::<gtk::Text>() {
        return Some(text.clone());
    }
    editable
        .delegate()
        .and_then(|inner| inner.downcast::<gtk::Text>().ok())
}

/// Makes an entry safe for secret text: no copy, cut, paste or selection (so no drag),
/// and no undo history.
pub fn harden_entry(entry: &impl IsA<gtk::Editable>) {
    let editable: gtk::Editable = entry.as_ref().clone();
    editable.set_enable_undo(false);
    if let Some(text) = inner_text(&editable) {
        text.set_enable_undo(false);
        text.connect_copy_clipboard(|text| text.stop_signal_emission_by_name("copy-clipboard"));
        text.connect_cut_clipboard(|text| text.stop_signal_emission_by_name("cut-clipboard"));
        text.connect_paste_clipboard(|text| {
            text.stop_signal_emission_by_name("paste-clipboard");
        });
    }
    // No selection means nothing to copy or drag out of the box.
    editable.connect_notify_local(Some("selection-bound"), |editable, _| {
        if let Some((_, end)) = editable.selection_bounds() {
            editable.select_region(end, end);
        }
    });
}

/// A password entry hardened for a PIN, PUK or passphrase, with an accessible name
/// taken from `label` (its mnemonic label).
pub fn password_entry(label: &gtk::Label) -> gtk::PasswordEntry {
    let entry = gtk::PasswordEntry::new();
    entry.set_show_peek_icon(false);
    harden_entry(&entry);
    label.set_mnemonic_widget(Some(&entry));
    entry
}
