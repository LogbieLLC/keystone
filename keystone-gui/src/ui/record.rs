//! The issuance record (FR-11 AC2, FR-21 AC6, FR-20, FR-22 AC3).
#![forbid(unsafe_code)]

use std::rc::Rc;

use gtk::prelude::*;
use keystone_core::model::Serial;
use keystone_core::store::IssuanceRecord;
use time::OffsetDateTime;

use super::widgets::{self, PageBuilder, StatusLine};
use super::{App, home};
use crate::vm::record::{RecordRow, STATUS_CHOICES, issuer_choices, rows};
use crate::vm::{Line, Status};

/// Page id.
pub const ID: &str = "record";

/// Builds the widget of one record row. Fingerprints and serials are selectable.
pub fn row_widget(row: &RecordRow) -> gtk::Frame {
    let (frame, inner) = widgets::group(&row.title);
    inner.append(StatusLine::new(&Line::new(row.status, row.status_text.clone())).widget());
    for detail in &row.details {
        if detail.starts_with("SHA-256") || detail.starts_with("Serial") {
            inner.append(&widgets::selectable(detail));
        } else {
            inner.append(&widgets::paragraph(detail));
        }
    }
    frame
}

/// Shows the issuance record with issuer and status filters.
pub fn show(app: &Rc<App>) {
    let record = app
        .session
        .borrow()
        .startup
        .as_ref()
        .and_then(|s| s.0.record.clone());
    let mut page = PageBuilder::new(
        "Issuance record",
        Some("Every certificate Keystone signed. Filter by issuer and status."),
    );
    let back = page.secondary_button("_Back");
    let app_ref = app.clone();
    back.connect_clicked(move |_| home::show(&app_ref));
    let record = match record {
        Some(Ok(record)) => record,
        Some(Err(error)) => {
            page.add(
                StatusLine::new(&Line::new(
                    Status::Blocked,
                    format!("The issuance record could not be read: {error}"),
                ))
                .widget(),
            );
            app.push(ID, &page.build());
            return;
        }
        None => IssuanceRecord::empty(),
    };
    let filters = gtk::Box::new(gtk::Orientation::Horizontal, 18);
    let issuer_box = gtk::Box::new(gtk::Orientation::Vertical, 4);
    let issuers = issuer_choices(&record);
    let issuer_names: Vec<&str> = issuers.iter().map(|(_, name)| name.as_str()).collect();
    let issuer_drop = widgets::labelled_dropdown(&issuer_box, "_Issuer", &issuer_names);
    let status_box = gtk::Box::new(gtk::Orientation::Vertical, 4);
    let status_names: Vec<&str> = STATUS_CHOICES.iter().map(|(_, name)| *name).collect();
    let status_drop = widgets::labelled_dropdown(&status_box, "_Status", &status_names);
    filters.append(&issuer_box);
    filters.append(&status_box);
    page.add(&filters);
    let count = widgets::paragraph("");
    page.add(&count);
    let list = gtk::Box::new(gtk::Orientation::Vertical, 10);
    page.add(&list);
    let record = Rc::new(record);
    let issuers: Rc<Vec<Option<Serial>>> = Rc::new(issuers.iter().map(|(s, _)| *s).collect());
    let refresh = {
        let record = record.clone();
        let issuer_drop = issuer_drop.clone();
        let status_drop = status_drop.clone();
        let list = list.clone();
        let count = count.clone();
        Rc::new(move || {
            let issuer = issuers
                .get(issuer_drop.selected() as usize)
                .copied()
                .flatten();
            let status = STATUS_CHOICES
                .get(status_drop.selected() as usize)
                .and_then(|(filter, _)| *filter);
            let shown = rows(&record, issuer, status, OffsetDateTime::now_utc());
            widgets::clear(&list);
            count.set_text(&format!(
                "{} of {} certificates shown.",
                shown.len(),
                record.certificates().len()
            ));
            for row in &shown {
                list.append(&row_widget(row));
            }
        })
    };
    refresh();
    let r = refresh.clone();
    issuer_drop.connect_selected_notify(move |_| r());
    let r = refresh.clone();
    status_drop.connect_selected_notify(move |_| r());
    page.focus_on(&issuer_drop);
    app.push(ID, &page.build());
}
