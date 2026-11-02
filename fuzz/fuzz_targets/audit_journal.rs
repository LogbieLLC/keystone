//! Fuzz target 3 (SEC-08): audit-log and operation-journal parsing.
#![no_main]
#![forbid(unsafe_code)]

use keystone_core::store::{parse_audit_log, parse_journal_entry};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(log) = parse_audit_log(data) {
        // Exercise the accessors on whatever parsed (chain links are verified by the parser).
        let _ = log.head();
        for entry in log.entries() {
            let _ = log.entry_hash(entry.seq);
        }
    }
    let _ = parse_journal_entry(data);
});
