//! Input forms with live validation (FR-02 AC4, FR-06 AC2, FR-07 AC4, FR-10 AC1,
//! FR-10 AC3, FR-18, FR-21 AC1, AC4). Every rule is core's, through `vm::forms`.
#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::rc::Rc;

use gtk::prelude::*;
use keystone_core::crypto::secret::SecretString;
use keystone_core::model::CaLevel;
use keystone_core::passphrase::EnteredPassphrase;
use keystone_core::profile::{
    CRL_NONE_WARNING, CrlLocation, NAME_CONSTRAINTS_OFF_WARNING, NameConstraintsChoice,
    ValidatedName,
};
use keystone_core::token::{DeviceInfo, WipeConfirmation};
use time::OffsetDateTime;

use super::widgets::{self, StatusLine};
use crate::secrets::take_secret;
use crate::vm::forms::{
    ConstraintsChoice, CrlChoice, credential_length_line, crl_location, default_years, name,
    name_constraints, name_constraints_lines, validity, validity_bounds, validity_line,
};
use crate::vm::{Line, Status};

/// Callbacks run when a form's value may have changed.
#[derive(Default)]
pub struct Listeners(RefCell<Vec<Box<dyn Fn()>>>);

impl std::fmt::Debug for Listeners {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Listeners")
    }
}

impl Listeners {
    /// Adds a callback.
    pub fn add(&self, listener: impl Fn() + 'static) {
        self.0.borrow_mut().push(Box::new(listener));
    }

    /// Runs every callback.
    pub fn emit(&self) {
        for listener in self.0.borrow().iter() {
            listener();
        }
    }
}

/// Name fields (FR-02 AC4).
#[derive(Debug)]
pub struct NameForm {
    common_name: gtk::Entry,
    organization: gtk::Entry,
    country: gtk::Entry,
    feedback: StatusLine,
    /// Change listeners.
    pub changed: Listeners,
}

impl NameForm {
    /// Adds the fields to `container`.
    pub fn new(container: &gtk::Box, what: &str) -> Rc<NameForm> {
        container.append(&widgets::paragraph(&format!(
            "The {what}'s name. The Common Name is required; Organization and Country are optional."
        )));
        let common_name = widgets::labelled_entry(container, "_Common Name (required)");
        let organization = widgets::labelled_entry(container, "_Organization (optional)");
        let country = widgets::labelled_entry(container, "Co_untry (optional, 2 letters)");
        country.set_max_length(2);
        let feedback = StatusLine::new(&Line::new(Status::Info, ""));
        container.append(feedback.widget());
        let form = Rc::new(NameForm {
            common_name,
            organization,
            country,
            feedback,
            changed: Listeners::default(),
        });
        for entry in [&form.common_name, &form.organization, &form.country] {
            let weak = Rc::downgrade(&form);
            entry.connect_changed(move |_| {
                if let Some(form) = weak.upgrade() {
                    form.refresh();
                    form.changed.emit();
                }
            });
        }
        form.refresh();
        form
    }

    fn refresh(&self) {
        match self.value() {
            Ok(validated) => self.feedback.set(&Line::new(
                Status::Ok,
                format!("The name is valid: {}", display_name(&validated)),
            )),
            Err(reason) => self.feedback.set(&Line::new(Status::Blocked, reason)),
        }
    }

    /// The validated name, or why it is refused.
    pub fn value(&self) -> Result<ValidatedName, String> {
        name(
            &self.common_name.text(),
            &self.organization.text(),
            &self.country.text(),
        )
    }

    /// The first field (for focus).
    pub fn first(&self) -> &gtk::Entry {
        &self.common_name
    }
}

/// `CN=…, O=…, C=…`.
pub fn display_name(name: &ValidatedName) -> String {
    let mut text = format!("CN={}", name.common_name());
    if let Some(org) = name.organization() {
        text.push_str(&format!(", O={org}"));
    }
    if let Some(country) = name.country() {
        text.push_str(&format!(", C={country}"));
    }
    text
}

/// Validity in whole years within the level's bounds, never past the issuer
/// (FR-10 AC1, AC3).
#[derive(Debug)]
pub struct ValidityForm {
    level: CaLevel,
    issuer_not_after: Option<OffsetDateTime>,
    spin: gtk::SpinButton,
    feedback: StatusLine,
    /// Change listeners.
    pub changed: Listeners,
}

impl ValidityForm {
    /// Adds the spinner to `container`.
    pub fn new(
        container: &gtk::Box,
        level: CaLevel,
        issuer_not_after: Option<OffsetDateTime>,
    ) -> Rc<ValidityForm> {
        let (min, max, _) = validity_bounds(level);
        let now = OffsetDateTime::now_utc();
        let value = default_years(level, now, issuer_not_after);
        let mut text = format!(
            "A {} certificate can be valid for {min} to {max} years.",
            level.display_name()
        );
        if issuer_not_after.is_some() {
            text.push_str(" It can never end after its issuer.");
        }
        container.append(&widgets::paragraph(&text));
        let spin = widgets::labelled_spin(container, "_Validity in years", min, max, value);
        let feedback = StatusLine::new(&Line::new(Status::Info, ""));
        container.append(feedback.widget());
        let form = Rc::new(ValidityForm {
            level,
            issuer_not_after,
            spin,
            feedback,
            changed: Listeners::default(),
        });
        let weak = Rc::downgrade(&form);
        form.spin.connect_value_changed(move |_| {
            if let Some(form) = weak.upgrade() {
                form.refresh();
                form.changed.emit();
            }
        });
        form.refresh();
        form
    }

    fn refresh(&self) {
        let result = validity(
            self.level,
            widgets::spin_value(&self.spin),
            OffsetDateTime::now_utc(),
            self.issuer_not_after,
        );
        self.feedback.set(&validity_line(&result));
    }

    /// The chosen years, or why they are refused.
    pub fn value(&self) -> Result<u8, String> {
        let years = widgets::spin_value(&self.spin);
        validity(
            self.level,
            years,
            OffsetDateTime::now_utc(),
            self.issuer_not_after,
        )
        .map(|_| years)
    }
}

/// The CRL address of an issuer (FR-18): an address, or explicitly none.
#[derive(Debug)]
pub struct CrlForm {
    use_address: gtk::CheckButton,
    entry: gtk::Entry,
    feedback: StatusLine,
    /// Change listeners.
    pub changed: Listeners,
}

impl CrlForm {
    /// Adds the choice to `container`. `issuer` names whose CRL this is.
    pub fn new(container: &gtk::Box, issuer: &str, children: &str) -> Rc<CrlForm> {
        container.append(&widgets::paragraph(&format!(
            "Where will the CRL of the {issuer} be hosted? Keystone writes this address into every {children} the {issuer} signs, and asks only once. Enter the address where StarnetAuth (or another system) will host it. Keystone never contacts it."
        )));
        let use_address = gtk::CheckButton::with_label("Use this CRL address");
        let no_address = gtk::CheckButton::with_label("No CRL address (not recommended)");
        no_address.set_group(Some(&use_address));
        use_address.set_active(true);
        container.append(&use_address);
        let entry = widgets::labelled_entry(container, "CRL _address (http:// or https://)");
        container.append(&no_address);
        let feedback = StatusLine::new(&Line::new(Status::Info, ""));
        container.append(feedback.widget());
        let form = Rc::new(CrlForm {
            use_address,
            entry,
            feedback,
            changed: Listeners::default(),
        });
        let weak = Rc::downgrade(&form);
        form.use_address.connect_toggled(move |_| {
            if let Some(form) = weak.upgrade() {
                form.refresh();
                form.changed.emit();
            }
        });
        let weak = Rc::downgrade(&form);
        form.entry.connect_changed(move |_| {
            if let Some(form) = weak.upgrade() {
                form.refresh();
                form.changed.emit();
            }
        });
        form.refresh();
        form
    }

    fn choice(&self) -> CrlChoice {
        if self.use_address.is_active() {
            CrlChoice::Address(self.entry.text().to_string())
        } else {
            CrlChoice::NoAddress
        }
    }

    fn refresh(&self) {
        self.entry.set_sensitive(self.use_address.is_active());
        match (self.choice(), self.value()) {
            (CrlChoice::NoAddress, _) => self
                .feedback
                .set(&Line::new(Status::Warning, CRL_NONE_WARNING)),
            (_, Ok(_)) => self.feedback.set(&Line::new(
                Status::Ok,
                "The address is valid. Keystone only writes it into certificates.",
            )),
            (_, Err(reason)) => self.feedback.set(&Line::new(Status::Blocked, reason)),
        }
    }

    /// The location, or why the address is refused.
    pub fn value(&self) -> Result<CrlLocation, String> {
        crl_location(&self.choice())
    }
}

/// Name constraints of a sub-intermediate (FR-21 AC1, AC4): on by default.
#[derive(Debug)]
pub struct ConstraintsForm {
    on: gtk::CheckButton,
    dns: gtk::Entry,
    ip: gtk::Entry,
    feedback: gtk::Box,
    /// Change listeners.
    pub changed: Listeners,
}

impl ConstraintsForm {
    /// Adds the choice to `container`.
    pub fn new(container: &gtk::Box) -> Rc<ConstraintsForm> {
        container.append(&widgets::paragraph(
            "Name constraints limit the names this sub-intermediate may issue for. Enter one or more DNS names: for example starnet covers starnet and every name under it. IP addresses, email addresses and URIs are excluded unless you enter IP ranges.",
        ));
        let on = gtk::CheckButton::with_label("Restrict to these names (recommended)");
        let off = gtk::CheckButton::with_label("No name constraints (not recommended)");
        off.set_group(Some(&on));
        on.set_active(true);
        container.append(&on);
        let dns = widgets::labelled_entry(
            container,
            "Permitted _DNS names (separate with commas or spaces)",
        );
        let ip = widgets::labelled_entry(
            container,
            "Permitted _IP ranges (optional, CIDR such as 10.0.0.0/8)",
        );
        container.append(&off);
        let feedback = gtk::Box::new(gtk::Orientation::Vertical, 4);
        container.append(&feedback);
        let form = Rc::new(ConstraintsForm {
            on,
            dns,
            ip,
            feedback,
            changed: Listeners::default(),
        });
        let notify = |form: &Rc<ConstraintsForm>| {
            let weak = Rc::downgrade(form);
            move || {
                if let Some(form) = weak.upgrade() {
                    form.refresh();
                    form.changed.emit();
                }
            }
        };
        let n = notify(&form);
        form.on.connect_toggled(move |_| n());
        let n = notify(&form);
        form.dns.connect_changed(move |_| n());
        let n = notify(&form);
        form.ip.connect_changed(move |_| n());
        form.refresh();
        form
    }

    fn choice(&self) -> ConstraintsChoice {
        if self.on.is_active() {
            ConstraintsChoice::On {
                dns: self.dns.text().to_string(),
                ip: self.ip.text().to_string(),
            }
        } else {
            ConstraintsChoice::Off
        }
    }

    fn refresh(&self) {
        let on = self.on.is_active();
        self.dns.set_sensitive(on);
        self.ip.set_sensitive(on);
        let lines = match self.value() {
            Ok(NameConstraintsChoice::ExplicitlyUnconstrained) => {
                vec![Line::new(Status::Warning, NAME_CONSTRAINTS_OFF_WARNING)]
            }
            Ok(choice) => name_constraints_lines(&choice)
                .into_iter()
                .map(|line| Line::new(Status::Ok, line))
                .collect(),
            Err(reason) => vec![Line::new(Status::Blocked, reason)],
        };
        widgets::set_status_list(&self.feedback, &lines);
    }

    /// The choice, or why the entries block the action.
    pub fn value(&self) -> Result<NameConstraintsChoice, String> {
        name_constraints(&self.choice())
    }
}

/// A new PIN or PUK, entered twice (FR-06 AC2). Only the length is read while typing.
#[derive(Debug)]
pub struct CredentialPair {
    what: &'static str,
    first: gtk::PasswordEntry,
    second: gtk::PasswordEntry,
    feedback: StatusLine,
}

impl CredentialPair {
    /// Adds the two fields for `what` ("PIN" or "PUK").
    pub fn new(container: &gtk::Box, what: &'static str) -> CredentialPair {
        let first = widgets::labelled_password(container, &format!("New {what}"));
        let second = widgets::labelled_password(container, &format!("New {what} again"));
        let feedback = StatusLine::new(&credential_length_line(what, 0));
        container.append(feedback.widget());
        let line = feedback.clone();
        first.connect_changed(move |entry| {
            let chars = entry.text_length_chars();
            line.set(&credential_length_line(what, chars));
        });
        CredentialPair {
            what,
            first,
            second,
            feedback,
        }
    }

    /// Copies both entries into secrets and clears them (SEC-07).
    pub fn take(&self) -> Result<(SecretString, SecretString), String> {
        let first = take_secret(&self.first).map_err(|e| e.to_string())?;
        let second = take_secret(&self.second).map_err(|e| e.to_string())?;
        self.feedback.set(&credential_length_line(self.what, 0));
        Ok((first, second))
    }
}

trait TextLength {
    fn text_length_chars(&self) -> usize;
}

impl TextLength for gtk::PasswordEntry {
    /// The number of characters typed, without copying the text.
    fn text_length_chars(&self) -> usize {
        self.delegate()
            .and_then(|inner| inner.downcast::<gtk::Text>().ok())
            .map_or(0, |text| usize::from(text.text_length()))
    }
}

/// The current YubiKey PIN.
#[derive(Debug)]
pub struct PinField {
    entry: gtk::PasswordEntry,
}

impl PinField {
    /// Adds the field.
    pub fn new(container: &gtk::Box, label: &str) -> PinField {
        PinField {
            entry: widgets::labelled_password(container, label),
        }
    }

    /// Copies the PIN into a secret and clears the field (SEC-07).
    pub fn take(&self) -> Result<SecretString, String> {
        let pin = take_secret(&self.entry).map_err(|e| e.to_string())?;
        if pin.is_empty() {
            return Err("Enter the YubiKey PIN.".to_string());
        }
        Ok(pin)
    }

    /// The entry (for focus).
    pub fn entry(&self) -> &gtk::PasswordEntry {
        &self.entry
    }
}

/// The master passphrase, to unlock the master key (FR-04).
#[derive(Debug)]
pub struct MasterPassphraseField {
    entry: gtk::PasswordEntry,
}

impl MasterPassphraseField {
    /// Adds the field.
    pub fn new(container: &gtk::Box) -> MasterPassphraseField {
        container.append(&widgets::paragraph(
            "Type the master passphrase from your paper record: the words separated by spaces.",
        ));
        MasterPassphraseField {
            entry: widgets::labelled_password(container, "_Master passphrase"),
        }
    }

    /// Copies the passphrase into a secret, clears the field and parses it: only list
    /// words are accepted (FR-03 AC1).
    pub fn take(&self) -> Result<EnteredPassphrase, String> {
        let secret = take_secret(&self.entry).map_err(|e| e.to_string())?;
        EnteredPassphrase::parse(secret.expose()).map_err(|e| {
            let text = e.to_string();
            let mut chars = text.chars();
            chars
                .next()
                .map(|c| c.to_uppercase().chain(chars).collect())
                .unwrap_or(text)
        })
    }

    /// The entry (for focus).
    pub fn entry(&self) -> &gtk::PasswordEntry {
        &self.entry
    }
}

/// FR-07 AC4: the typed serial number that confirms a slot wipe.
#[derive(Debug)]
pub struct TypedSerialForm {
    entry: gtk::Entry,
    device: DeviceInfo,
    feedback: StatusLine,
    /// Change listeners.
    pub changed: Listeners,
}

impl TypedSerialForm {
    /// Adds the field.
    pub fn new(container: &gtk::Box, device: DeviceInfo) -> Rc<TypedSerialForm> {
        container.append(&widgets::paragraph(&format!(
            "To wipe the signing slot, type this YubiKey's serial number exactly as shown on the previous screen ({}). Only the signing slot's key and certificate are deleted; nothing else on the YubiKey changes.",
            device.serial
        )));
        let entry = widgets::labelled_entry(container, "_Serial number of this YubiKey");
        let feedback = StatusLine::new(&Line::new(Status::Info, ""));
        container.append(feedback.widget());
        let form = Rc::new(TypedSerialForm {
            entry,
            device,
            feedback,
            changed: Listeners::default(),
        });
        let weak = Rc::downgrade(&form);
        form.entry.connect_changed(move |_| {
            if let Some(form) = weak.upgrade() {
                form.refresh();
                form.changed.emit();
            }
        });
        form.refresh();
        form
    }

    fn refresh(&self) {
        let line = match self.value() {
            Ok(_) => Line::new(Status::Ok, "The serial number matches this YubiKey."),
            Err(_) if self.entry.text().is_empty() => {
                Line::new(Status::Info, "Type the serial number to enable the wipe.")
            }
            Err(reason) => Line::new(Status::Blocked, reason),
        };
        self.feedback.set(&line);
    }

    /// The confirmation, when the typed serial matches.
    pub fn value(&self) -> Result<WipeConfirmation, String> {
        WipeConfirmation::new(&self.entry.text(), &self.device).map_err(|e| {
            let text = e.to_string();
            let mut chars = text.chars();
            chars
                .next()
                .map(|c| c.to_uppercase().chain(chars).collect())
                .unwrap_or(text)
        })
    }

    /// The entry (for focus).
    pub fn entry(&self) -> &gtk::Entry {
        &self.entry
    }
}
