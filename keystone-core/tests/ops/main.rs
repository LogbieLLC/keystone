//! Integration tests of the operations layer (`keystone_core::ops`): Flows A to E end
//! to end, opening an existing CA, recovery and fault injection, against the YubiKey
//! simulator (NFR-08), temporary drives (TEST-12) and cached synthetic test keys
//! (TEST-11).
//!
//! One test binary, so the cached RSA 8,192 test key is generated once per run. The
//! binary uses the test seams of `ops::testing`, which a `production` build does not
//! contain, so it is compiled only without that feature.
#![forbid(unsafe_code)]
#![cfg(not(feature = "production"))]

mod fault_injection;
mod flow_a;
mod flow_b;
mod flow_c;
mod flow_d;
mod flow_e;
mod recovery;
mod startup;
mod support;
