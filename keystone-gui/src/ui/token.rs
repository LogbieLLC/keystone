//! Detecting the YubiKey off the GUI thread (FR-05 AC3: serial and firmware are
//! shown before any action).
#![forbid(unsafe_code)]

use std::rc::Rc;

use super::App;
use crate::token;
use crate::vm::token::TokenState;
use crate::worker::gtk_glue;

/// Connects to the YubiKey if needed, reads it, and calls `on_done` with what it holds.
pub fn detect(app: &Rc<App>, on_done: impl FnOnce(&Rc<App>, TokenState) + 'static) {
    let existing = app.session.borrow().token.clone();
    let sim = app.options.sim;
    let app = app.clone();
    gtk_glue::run(
        "Reading the YubiKey",
        false,
        move |_| match existing {
            Some(token) => (token::read_state(&token), Some(token)),
            None => match token::connect(&sim) {
                Ok(token) => (token::read_state(&token), Some(token)),
                Err(state) => (state, None),
            },
        },
        |_| {},
        move |result| {
            let state = match result {
                Ok((state, token)) => {
                    if token.is_some() {
                        app.session.borrow_mut().token = token;
                    }
                    state
                }
                Err(failure) => TokenState::Unavailable(failure.to_string()),
            };
            on_done(&app, state);
        },
    );
}
