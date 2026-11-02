//! Fuzz target 2 (SEC-08): certificate and CRL parsing (DER and PEM).
#![no_main]
#![forbid(unsafe_code)]

use keystone_core::cert::{parse_certificate_der, parse_certificate_pem};
use keystone_core::crl::{parse_crl_der, parse_crl_pem};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_certificate_der(data);
    let _ = parse_certificate_pem(data);
    let _ = parse_crl_der(data);
    let _ = parse_crl_pem(data);
});
