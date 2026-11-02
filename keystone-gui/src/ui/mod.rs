//! The GTK4 + libadwaita interface (English only, NFR-05).
//!
//! # Screen map
//! ```text
//! drive selection ─▶ start-up checks ─┬─▶ clock confirmation ─▶ home ─▶ flow wizard ─▶ progress ─▶ result
//!                         │           │        │                  │
//!                         │           │        └─ correct clock baseline (FR-17 AC3)
//!                         │           ├─▶ recovery screen (FR-22 AC8) ─▶ action confirmation ─▶ progress ─▶ result
//!                         │           └─ drive repair (FR-12 AC3), divergent histories side by side
//!                         └─ blocked: broken audit chain, divergent or damaged drives
//! home ─▶ issuance record (FR-11 AC2), CRL warning banner ─▶ Refresh CRL (FR-13 AC3)
//! ```
//! Every flow starts with drive selection and comparison, audit-log verification, the
//! recovery check and the clock confirmation, and ends with the write-and-verify
//! result and the SHA-256 fingerprints (PRD section 6, FR-20). A confirmed time is used
//! by one execute step; the next flow asks again (SEC-16).
//!
//! Navigation is a `gtk::Stack` without animations. Screens are rebuilt when shown;
//! wizard screens stay in the stack only while their wizard runs, and the passphrase
//! screens are removed the moment the passphrase is confirmed (SEC-17).
#![forbid(unsafe_code)]

mod clock;
mod drives;
mod exec;
mod flows;
mod forms;
mod home;
mod passphrase;
mod record;
mod recovery;
mod startup;
mod token;
pub mod widgets;

use std::cell::RefCell;
use std::process::ExitCode;
use std::rc::Rc;
use std::sync::Arc;

use adw::prelude::*;
use gtk::{gio, glib};

use crate::backend::{Backend, ClockConfirmation, DriveSelection, NotConnected, SharedToken};
use crate::cli::Options;
use crate::vm::drives::DriveMode;
use crate::vm::startup::{StartupData, StartupView};
use widgets::Page;

/// The application id (also the GSettings and D-Bus name; nothing is stored).
pub const APP_ID: &str = "org.logbie.Keystone";

/// What the session knows. Lives on the GUI thread only.
#[derive(Debug, Default)]
pub struct Session {
    /// The chosen drives.
    pub drives: Option<DriveSelection>,
    /// New CA or existing CA.
    pub mode: Option<DriveMode>,
    /// The last start-up check results.
    pub startup: Option<Rc<(StartupData, StartupView)>>,
    /// The confirmed time, used by the next execute step only (SEC-16).
    pub clock: Option<ClockConfirmation>,
    /// The YubiKey, once detected.
    pub token: Option<SharedToken>,
}

/// The window and its navigation.
#[derive(Debug)]
pub struct App {
    /// The main window.
    pub window: adw::ApplicationWindow,
    stack: gtk::Stack,
    toasts: adw::ToastOverlay,
    title: adw::WindowTitle,
    pages: RefCell<Vec<(String, Page)>>,
    /// The operations layer.
    pub backend: Arc<dyn Backend>,
    /// Session state.
    pub session: RefCell<Session>,
    /// The command line.
    pub options: Options,
}

impl App {
    /// Shows `page` under `id`, replacing an older screen with the same id. Other
    /// screens stay (wizards keep their earlier steps for Back).
    pub fn push(&self, id: &str, page: &Page) {
        if let Some(old) = self.stack.child_by_name(id)
            && old != page.root
        {
            self.stack.remove(&old);
        }
        if page.root.parent().is_none() {
            self.stack.add_named(&page.root, Some(id));
        }
        {
            let mut pages = self.pages.borrow_mut();
            pages.retain(|(name, _)| name != id);
            pages.push((id.to_string(), page.clone()));
        }
        self.present(page);
    }

    fn present(&self, page: &Page) {
        self.stack.set_visible_child(&page.root);
        self.title.set_title(&page.title);
        self.window.set_default_widget(page.default.as_ref());
        if let Some(focus) = &page.focus {
            focus.grab_focus();
        }
    }

    /// Shows `page` and removes every other screen (leaving a wizard or a flow).
    pub fn reset_to(&self, id: &str, page: &Page) {
        self.push(id, page);
        self.remove_all_except(&[id]);
    }

    /// Removes every screen except those named.
    pub fn remove_all_except(&self, keep: &[&str]) {
        let mut child = self.stack.first_child();
        while let Some(widget) = child {
            child = widget.next_sibling();
            let name = self.stack.page(&widget).name();
            if !name.is_some_and(|n| keep.contains(&n.as_str())) {
                self.stack.remove(&widget);
            }
        }
        self.pages
            .borrow_mut()
            .retain(|(name, _)| keep.contains(&name.as_str()));
    }

    /// Removes one screen (used for the passphrase screens, SEC-17).
    pub fn remove(&self, id: &str) {
        if let Some(widget) = self.stack.child_by_name(id) {
            self.stack.remove(&widget);
        }
        self.pages.borrow_mut().retain(|(name, _)| name != id);
    }

    /// Shows the screen `id` again if it is still there (wizard Back buttons).
    pub fn back_to(&self, id: &str) -> bool {
        let page = self
            .pages
            .borrow()
            .iter()
            .find(|(name, _)| name == id)
            .map(|(_, page)| page.clone());
        match page {
            Some(page) => {
                self.present(&page);
                true
            }
            None => false,
        }
    }

    /// A short message at the bottom of the window.
    pub fn toast(&self, text: &str) {
        self.toasts.add_toast(adw::Toast::new(text));
    }

    /// Shows the chosen drives under the window title.
    pub fn set_subtitle(&self, text: &str) {
        self.title.set_subtitle(text);
    }

    /// The chosen drives (always set after drive selection).
    pub fn drives(&self) -> Option<DriveSelection> {
        self.session.borrow().drives.clone()
    }
}

fn build_window(
    application: &adw::Application,
) -> (
    adw::ApplicationWindow,
    gtk::Stack,
    adw::ToastOverlay,
    adw::WindowTitle,
) {
    let window = adw::ApplicationWindow::new(application);
    window.set_title(Some("Keystone"));
    window.set_default_size(980, 780);
    let title = adw::WindowTitle::new("Keystone", "");
    let header = adw::HeaderBar::new();
    header.set_title_widget(Some(&title));
    let stack = gtk::Stack::new();
    stack.set_transition_type(gtk::StackTransitionType::None);
    stack.set_vexpand(true);
    let toasts = adw::ToastOverlay::new();
    toasts.set_child(Some(&stack));
    let layout = gtk::Box::new(gtk::Orientation::Vertical, 0);
    layout.append(&header);
    layout.append(&toasts);
    window.set_content(Some(&layout));
    (window, stack, toasts, title)
}

fn new_application() -> adw::Application {
    glib::set_prgname(Some("keystone"));
    glib::set_application_name("Keystone");
    adw::Application::builder()
        .application_id(APP_ID)
        .flags(gio::ApplicationFlags::NON_UNIQUE)
        .build()
}

/// Runs the application.
pub fn run(options: Options) -> ExitCode {
    let application = new_application();
    let options = Rc::new(RefCell::new(Some(options)));
    application.connect_activate(move |application| {
        let Some(options) = options.borrow_mut().take() else {
            return;
        };
        let (window, stack, toasts, title) = build_window(application);
        let app = Rc::new(App {
            window,
            stack,
            toasts,
            title,
            pages: RefCell::new(Vec::new()),
            backend: Arc::new(NotConnected),
            session: RefCell::new(Session::default()),
            options,
        });
        start(&app);
        app.window.present();
    });
    // GTK must not parse Keystone's own arguments.
    let status = application.run_with_args::<&str>(&[]);
    if status == glib::ExitCode::SUCCESS {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn start(app: &Rc<App>) {
    #[cfg(not(feature = "production"))]
    if let Some(crate::cli::TestHook::PassphraseConfirmation { words }) = app.options.test_hook {
        passphrase::start_test_hook(app, words);
        return;
    }
    drives::show(app);
}

/// Shows only an error and a Quit button (FR-01 AC1: refuse to start, naming the
/// interface; nothing else happens).
pub fn run_error_only(message: &str) {
    let application = new_application();
    let message = message.to_string();
    application.connect_activate(move |application| {
        let window = adw::ApplicationWindow::new(application);
        window.set_title(Some("Keystone cannot start"));
        window.set_default_size(640, 320);
        let mut page = widgets::PageBuilder::new("Keystone cannot start", None);
        page.add(
            &widgets::StatusLine::new(&crate::vm::Line::new(
                crate::vm::Status::Blocked,
                message.clone(),
            ))
            .widget()
            .clone(),
        );
        let quit = page.primary_button("_Quit");
        let page = page.build();
        let quit_window = window.clone();
        quit.connect_clicked(move |_| quit_window.close());
        window.set_content(Some(&page.root));
        window.set_default_widget(page.default.as_ref());
        window.present();
        quit.grab_focus();
    });
    let _ = application.run_with_args::<&str>(&[]);
}
