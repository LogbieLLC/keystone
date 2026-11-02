//! Fuzz target 4 (SEC-08): issuance-record parsing, plus the small drive metadata
//! files read at start (drive identity, binary hash record).
#![no_main]
#![forbid(unsafe_code)]

use keystone_core::store::{parse_binary_hash_record, parse_drive_identity, parse_record};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_record(data);
    let _ = parse_drive_identity(data);
    let _ = parse_binary_hash_record(data);
});
