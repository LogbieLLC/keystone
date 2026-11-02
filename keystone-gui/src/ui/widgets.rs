//! Small building blocks shared by every screen (NFR-04).
//!
//! - Every interactive widget gets an accessible name: buttons and check boxes from
//!   their label, entries, spinners and drop-downs from a visible mnemonic label
//!   (GTK turns the mnemonic label into the "labelled by" relation).
//! - Every status is an icon *and* a leading word ("OK:", "Warning:", "Blocked:"),
//!   never colour alone.
//! - Tab order is the order widgets are added: content top to bottom, then the button
//!   bar left to right (Back first, the main action last).
#![forbid(unsafe_code)]

use gtk::prelude::*;

use crate::vm::{Line, Status};

/// A finished screen, ready to be shown.
#[derive(Debug, Clone)]
pub struct Page {
    /// The screen.
    pub root: gtk::Widget,
    /// Window title while it is shown.
    pub title: String,
    /// The widget that gets keyboard focus when the screen is shown.
    pub focus: Option<gtk::Widget>,
    /// The button Enter activates.
    pub default: Option<gtk::Button>,
}

/// Builds a screen: a heading, scrollable content and a button bar.
#[derive(Debug)]
pub struct PageBuilder {
    root: gtk::Box,
    content: gtk::Box,
    secondary: gtk::Box,
    primary: gtk::Box,
    title: String,
    focus: Option<gtk::Widget>,
    default: Option<gtk::Button>,
}

impl PageBuilder {
    /// A screen with a heading and an optional introduction.
    pub fn new(title: &str, intro: Option<&str>) -> Self {
        let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
        let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
        content.set_margin_top(18);
        content.set_margin_bottom(18);
        content.set_margin_start(18);
        content.set_margin_end(18);
        let heading = gtk::Label::new(Some(title));
        heading.add_css_class("title-1");
        heading.set_xalign(0.0);
        heading.set_wrap(true);
        content.append(&heading);
        if let Some(intro) = intro {
            content.append(&paragraph(intro));
        }
        let clamp = adw::Clamp::new();
        clamp.set_maximum_size(980);
        clamp.set_child(Some(&content));
        let scrolled = gtk::ScrolledWindow::new();
        scrolled.set_hscrollbar_policy(gtk::PolicyType::Never);
        scrolled.set_vexpand(true);
        scrolled.set_child(Some(&clamp));
        root.append(&scrolled);
        root.append(&gtk::Separator::new(gtk::Orientation::Horizontal));
        let bar = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        bar.set_margin_top(12);
        bar.set_margin_bottom(12);
        bar.set_margin_start(18);
        bar.set_margin_end(18);
        let secondary = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        secondary.set_hexpand(true);
        let primary = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        bar.append(&secondary);
        bar.append(&primary);
        root.append(&bar);
        PageBuilder {
            root,
            content,
            secondary,
            primary,
            title: title.to_string(),
            focus: None,
            default: None,
        }
    }

    /// Appends a widget to the content.
    pub fn add(&self, widget: &impl IsA<gtk::Widget>) {
        self.content.append(widget);
    }

    /// Adds a button on the left of the bar (Back, Cancel, Choose other drives).
    pub fn secondary_button(&self, label: &str) -> gtk::Button {
        let button = gtk::Button::with_mnemonic(label);
        self.secondary.append(&button);
        button
    }

    /// Adds the screen's main button on the right of the bar; Enter activates it.
    pub fn primary_button(&mut self, label: &str) -> gtk::Button {
        let button = gtk::Button::with_mnemonic(label);
        button.add_css_class("suggested-action");
        self.primary.append(&button);
        self.default = Some(button.clone());
        button
    }

    /// Gives `widget` the keyboard focus when the screen is shown.
    pub fn focus_on(&mut self, widget: &impl IsA<gtk::Widget>) {
        self.focus = Some(widget.as_ref().clone());
    }

    /// The finished screen.
    pub fn build(self) -> Page {
        let focus = self
            .focus
            .or_else(|| self.default.clone().map(|b| b.upcast::<gtk::Widget>()));
        Page {
            root: self.root.upcast(),
            title: self.title,
            focus,
            default: self.default,
        }
    }
}

/// A wrapping paragraph.
pub fn paragraph(text: &str) -> gtk::Label {
    let label = gtk::Label::new(Some(text));
    label.set_wrap(true);
    label.set_wrap_mode(gtk::pango::WrapMode::WordChar);
    label.set_xalign(0.0);
    label
}

/// A section heading.
pub fn heading(text: &str) -> gtk::Label {
    let label = gtk::Label::new(Some(text));
    label.add_css_class("title-3");
    label.set_xalign(0.0);
    label.set_wrap(true);
    label.set_margin_top(6);
    label
}

/// Text the operator may select and copy (fingerprints, serials, paths): monospace.
pub fn selectable(text: &str) -> gtk::Label {
    let label = gtk::Label::new(Some(text));
    label.set_selectable(true);
    label.set_wrap(true);
    label.set_wrap_mode(gtk::pango::WrapMode::Char);
    label.set_xalign(0.0);
    label.add_css_class("monospace");
    label
}

/// One status line: an icon and the text with its leading word (NFR-04).
#[derive(Debug, Clone)]
pub struct StatusLine {
    root: gtk::Box,
    icon: gtk::Image,
    label: gtk::Label,
}

impl StatusLine {
    /// A status line showing `line`.
    pub fn new(line: &Line) -> Self {
        let root = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let icon = gtk::Image::builder()
            .accessible_role(gtk::AccessibleRole::Presentation)
            .build();
        icon.set_valign(gtk::Align::Start);
        let label = paragraph("");
        label.set_hexpand(true);
        root.append(&icon);
        root.append(&label);
        let status = StatusLine { root, icon, label };
        status.set(line);
        status
    }

    /// Shows another line.
    pub fn set(&self, line: &Line) {
        self.icon.set_icon_name(Some(line.status.icon_name()));
        self.label.set_text(&line.status.line(&line.text));
        for status in [Status::Ok, Status::Info, Status::Warning, Status::Blocked] {
            self.root.remove_css_class(css_class(status));
        }
        self.root.add_css_class(css_class(line.status));
    }

    /// Hides or shows the line.
    pub fn set_visible(&self, visible: bool) {
        self.root.set_visible(visible);
    }

    /// The widget.
    pub fn widget(&self) -> &gtk::Box {
        &self.root
    }
}

fn css_class(status: Status) -> &'static str {
    match status {
        Status::Ok => "success",
        Status::Info => "dim-label",
        Status::Warning => "warning",
        Status::Blocked => "error",
    }
}

/// A box of status lines.
pub fn status_list(lines: &[Line]) -> gtk::Box {
    let list = gtk::Box::new(gtk::Orientation::Vertical, 6);
    for line in lines {
        list.append(StatusLine::new(line).widget());
    }
    list
}

/// Replaces the children of `container` with `lines`.
pub fn set_status_list(container: &gtk::Box, lines: &[Line]) {
    while let Some(child) = container.first_child() {
        container.remove(&child);
    }
    for line in lines {
        container.append(StatusLine::new(line).widget());
    }
}

/// A framed group with a heading.
pub fn group(title: &str) -> (gtk::Frame, gtk::Box) {
    let inner = gtk::Box::new(gtk::Orientation::Vertical, 8);
    inner.set_margin_top(10);
    inner.set_margin_bottom(10);
    inner.set_margin_start(12);
    inner.set_margin_end(12);
    let frame = gtk::Frame::new(None);
    let label = gtk::Label::new(Some(title));
    label.add_css_class("heading");
    frame.set_label_widget(Some(&label));
    frame.set_child(Some(&inner));
    (frame, inner)
}

/// A labelled one-line text entry. The label names the entry for assistive
/// technology (mnemonic label → "labelled by").
pub fn labelled_entry(container: &gtk::Box, label_text: &str) -> gtk::Entry {
    let label = gtk::Label::with_mnemonic(label_text);
    label.set_xalign(0.0);
    let entry = gtk::Entry::new();
    label.set_mnemonic_widget(Some(&entry));
    container.append(&label);
    container.append(&entry);
    entry
}

/// A labelled password entry, hardened for secrets.
pub fn labelled_password(container: &gtk::Box, label_text: &str) -> gtk::PasswordEntry {
    let label = gtk::Label::with_mnemonic(label_text);
    label.set_xalign(0.0);
    let entry = crate::secrets::password_entry(&label);
    container.append(&label);
    container.append(&entry);
    entry
}

/// A labelled drop-down.
pub fn labelled_dropdown(container: &gtk::Box, label_text: &str, items: &[&str]) -> gtk::DropDown {
    let label = gtk::Label::with_mnemonic(label_text);
    label.set_xalign(0.0);
    let dropdown = gtk::DropDown::from_strings(items);
    label.set_mnemonic_widget(Some(&dropdown));
    container.append(&label);
    container.append(&dropdown);
    dropdown
}

/// A labelled whole-number spinner.
pub fn labelled_spin(
    container: &gtk::Box,
    label_text: &str,
    min: u8,
    max: u8,
    value: u8,
) -> gtk::SpinButton {
    let label = gtk::Label::with_mnemonic(label_text);
    label.set_xalign(0.0);
    let spin = gtk::SpinButton::with_range(f64::from(min), f64::from(max), 1.0);
    spin.set_value(f64::from(value));
    spin.set_numeric(true);
    spin.set_digits(0);
    spin.set_halign(gtk::Align::Start);
    label.set_mnemonic_widget(Some(&spin));
    container.append(&label);
    container.append(&spin);
    spin
}

/// The value of a whole-number spinner.
pub fn spin_value(spin: &gtk::SpinButton) -> u8 {
    u8::try_from(spin.value_as_int().clamp(0, i32::from(u8::MAX))).unwrap_or(0)
}

/// A banner: an icon, a sentence and one button (FR-13 AC3 uses it for CRL warnings).
pub fn banner(line: &Line, button_label: &str) -> (gtk::Box, gtk::Button) {
    let root = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    root.add_css_class("card");
    root.set_margin_bottom(6);
    let status = StatusLine::new(line);
    status.widget().set_margin_top(10);
    status.widget().set_margin_bottom(10);
    status.widget().set_margin_start(12);
    status.widget().set_hexpand(true);
    let button = gtk::Button::with_mnemonic(button_label);
    button.set_valign(gtk::Align::Center);
    button.set_margin_end(12);
    root.append(status.widget());
    root.append(&button);
    (root, button)
}

/// Removes every child of a box.
pub fn clear(container: &gtk::Box) {
    while let Some(child) = container.first_child() {
        container.remove(&child);
    }
}
