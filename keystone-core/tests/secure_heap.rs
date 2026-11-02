//! OpenSSL's secure heap (SEC-07): private keys live in locked, no-dump memory, and
//! Keystone refuses to create or load a key when that memory cannot be locked.
//!
//! Each check runs in a fresh child process (this test binary run again with
//! `KEYSTONE_SECURE_HEAP_CHILD` set), so the heap starts empty and no parallel test
//! disturbs the measurements. The memory-lock tests set `RLIMIT_MEMLOCK` with
//! `prlimit` and, when running as root, drop `CAP_IPC_LOCK` with `setpriv` (both from
//! util-linux), because that capability makes the kernel ignore the limit. Reports
//! are written to `tempfile` directories (TEST-12). Test keys come from
//! keystone-testkit (TEST-11).
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use keystone_core::crypto::pkcs8::{decrypt_key_pem, encrypt_sub_key_pem};
use keystone_core::crypto::secret::SecretString;
use keystone_core::crypto::secure_heap::{self, SECURE_HEAP_BYTES};
use keystone_core::crypto::{CancelFlag, CryptoError, generate_rsa};
use keystone_testkit::keys;

const CHILD_VAR: &str = "KEYSTONE_SECURE_HEAP_CHILD";

/// Bytes of the private numbers of an RSA 2,048 key: d (256) plus p, q, dP, dQ and
/// qInv (128 each).
const RSA2048_PRIVATE_BYTES: usize = 256 + 5 * 128;

/// Ubuntu's default `RLIMIT_MEMLOCK`.
const DEFAULT_MEMLOCK: u64 = 8 * 1024 * 1024;

fn child_dir() -> Option<PathBuf> {
    std::env::var_os(CHILD_VAR).map(PathBuf::from)
}

fn write_report(dir: &Path, report: &[(&str, String)]) {
    let text: String = report
        .iter()
        .map(|(key, value)| format!("{key}={value}\n"))
        .collect();
    std::fs::write(dir.join("report.txt"), text).expect("write report");
}

/// Runs the test `name` alone in a child process and returns its report. `inputs`
/// are written to the child's directory first. With `memlock`, the child runs under
/// that `RLIMIT_MEMLOCK` and without `CAP_IPC_LOCK`.
fn run_child(
    name: &str,
    memlock: Option<u64>,
    inputs: &[(&str, &[u8])],
) -> BTreeMap<String, String> {
    let dir = tempfile::tempdir().expect("temporary directory");
    for (file, contents) in inputs {
        std::fs::write(dir.path().join(file), contents).expect("write child input");
    }
    let exe = std::env::current_exe().expect("test binary path");
    let mut command = match memlock {
        None => Command::new(&exe),
        Some(limit) => {
            let mut command = Command::new("prlimit");
            command.arg(format!("--memlock={limit}:{limit}"));
            if rustix::process::getuid().is_root() {
                command.args([
                    "setpriv",
                    "--bounding-set=-ipc_lock",
                    "--inh-caps=-ipc_lock",
                    "--",
                ]);
            }
            command.arg(&exe);
            command
        }
    };
    let output = command
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD_VAR, dir.path())
        .output()
        .expect("start the child test (prlimit and setpriv come with util-linux)");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "child test {name} failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = std::fs::read_to_string(dir.path().join("report.txt")).expect("child report");
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

/// What the kernel applies to this process: the `RLIMIT_MEMLOCK` soft limit and
/// whether `CAP_IPC_LOCK` (capability 14, which lifts the limit) is effective.
fn memlock_conditions() -> [(&'static str, String); 2] {
    let limit = rustix::process::getrlimit(rustix::process::Resource::Memlock)
        .current
        .map_or_else(|| "unlimited".to_owned(), |bytes| bytes.to_string());
    let status = std::fs::read_to_string("/proc/self/status").expect("/proc/self/status");
    let effective = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
        .expect("CapEff");
    [
        ("memlock_limit", limit),
        ("cap_ipc_lock", (effective & (1 << 14) != 0).to_string()),
    ]
}

fn assert_limit_applied(report: &BTreeMap<String, String>, limit: u64) {
    assert_eq!(report["memlock_limit"], limit.to_string(), "{report:?}");
    assert_eq!(report["cap_ipc_lock"], "false", "{report:?}");
}

fn number(report: &BTreeMap<String, String>, key: &str) -> usize {
    report
        .get(key)
        .unwrap_or_else(|| panic!("{key} missing from {report:?}"))
        .parse()
        .unwrap_or_else(|_| panic!("{key} is not a number in {report:?}"))
}

/// Child half of `sec07_private_keys_are_allocated_in_the_locked_secure_heap`.
#[test]
fn child_key_lifecycle() {
    let Some(dir) = child_dir() else {
        assert!(SECURE_HEAP_BYTES.is_power_of_two());
        return;
    };
    let fresh = secure_heap::status();
    secure_heap::init().expect("secure heap");
    // OpenSSL's random generator keeps its own seed state in the heap from its first
    // use on; start it first so the measurements below show only the keys.
    keystone_core::crypto::rand::fill(&mut [0u8; 32]).expect("random");
    let after_init = secure_heap::status();

    // A generated key.
    let generated = keys::generate_uncached(2048);
    let with_generated = secure_heap::status().used_bytes;
    drop(generated);
    let after_generated = secure_heap::status().used_bytes;

    // A decrypted key.
    let words = SecretString::from_str_copy("KEYSTONE TEST secure heap words").expect("lock");
    let source = keys::generate_uncached(2048);
    let pem = encrypt_sub_key_pem(&source, &words).expect("encrypt");
    drop(source);
    let before_loaded = secure_heap::status().used_bytes;
    let loaded = decrypt_key_pem(pem.as_bytes(), &words).expect("decrypt");
    let with_loaded = secure_heap::status().used_bytes;
    drop(loaded);
    let after_loaded = secure_heap::status().used_bytes;

    // The most the heap holds while an RSA 8,192 key is generated, sampled at every
    // progress step.
    let peak = AtomicUsize::new(0);
    let master = generate_rsa(8192, &CancelFlag::new(), &|_| {
        peak.fetch_max(secure_heap::status().used_bytes, Ordering::Relaxed);
    })
    .expect("RSA 8192");
    let with_master = secure_heap::status().used_bytes;
    drop(master);

    write_report(
        &dir,
        &[
            ("initialized_before", fresh.initialized.to_string()),
            ("initialized_after", after_init.initialized.to_string()),
            ("used_after_init", after_init.used_bytes.to_string()),
            ("used_with_generated", with_generated.to_string()),
            ("used_after_generated", after_generated.to_string()),
            ("used_before_loaded", before_loaded.to_string()),
            ("used_with_loaded", with_loaded.to_string()),
            ("used_after_loaded", after_loaded.to_string()),
            (
                "peak_rsa8192_generation",
                peak.load(Ordering::Relaxed).to_string(),
            ),
            ("used_with_rsa8192", with_master.to_string()),
        ],
    );
}

#[test]
fn sec07_private_keys_are_allocated_in_the_locked_secure_heap() {
    // Covers: SEC-07
    let report = run_child("child_key_lifecycle", None, &[]);
    assert_eq!(report["initialized_before"], "false", "{report:?}");
    assert_eq!(report["initialized_after"], "true", "{report:?}");
    let base = number(&report, "used_after_init");
    // The private numbers of a generated key are in the heap while the key lives,
    // and are freed (and cleared) with it.
    assert!(
        number(&report, "used_with_generated") >= base + RSA2048_PRIVATE_BYTES,
        "{report:?}"
    );
    assert_eq!(number(&report, "used_after_generated"), base, "{report:?}");
    // The same for a key decrypted from an encrypted PKCS#8 file.
    let before_loaded = number(&report, "used_before_loaded");
    assert!(
        number(&report, "used_with_loaded") >= before_loaded + RSA2048_PRIVATE_BYTES,
        "{report:?}"
    );
    assert_eq!(
        number(&report, "used_after_loaded"),
        before_loaded,
        "{report:?}"
    );
    // An RSA 8,192 key and its generation fit easily into the 1 MiB heap.
    assert!(
        number(&report, "used_with_rsa8192") >= base + 4 * RSA2048_PRIVATE_BYTES,
        "{report:?}"
    );
    let peak = number(&report, "peak_rsa8192_generation");
    assert!(peak > base, "{report:?}");
    assert!(peak < SECURE_HEAP_BYTES / 8, "{report:?}");
}

/// Child half of `sec07_the_default_8_mib_memory_lock_limit_is_enough`.
#[test]
fn child_under_default_memlock() {
    let Some(dir) = child_dir() else {
        return;
    };
    secure_heap::init().expect("the 1 MiB heap locks under an 8 MiB limit");
    // Far more secret buffers than any flow holds at once (passphrases, their
    // confirmations, PIN, PUK): 128 buffers of one locked page each (512 KiB).
    let secrets: Vec<SecretString> = (0..128)
        .map(|_| SecretString::with_capacity(512).expect("locked page"))
        .collect();
    let words = SecretString::from_str_copy("KEYSTONE TEST memlock words").expect("lock");
    let key = keys::generate_uncached(4096);
    let pem = encrypt_sub_key_pem(&key, &words).expect("encrypt");
    let loaded = decrypt_key_pem(pem.as_bytes(), &words).expect("decrypt");
    let [limit, capability] = memlock_conditions();
    write_report(
        &dir,
        &[
            ("secrets", secrets.len().to_string()),
            ("bits", loaded.bits().to_string()),
            ("used", secure_heap::status().used_bytes.to_string()),
            limit,
            capability,
        ],
    );
}

#[test]
fn sec07_the_default_8_mib_memory_lock_limit_is_enough() {
    // Covers: SEC-07
    let report = run_child("child_under_default_memlock", Some(DEFAULT_MEMLOCK), &[]);
    assert_limit_applied(&report, DEFAULT_MEMLOCK);
    assert_eq!(report["secrets"], "128", "{report:?}");
    assert_eq!(report["bits"], "4096", "{report:?}");
    assert!(number(&report, "used") > 0, "{report:?}");
}

/// Child half of `sec07_a_too_small_memory_lock_limit_is_a_clear_error`.
#[test]
fn child_under_small_memlock() {
    let Some(dir) = child_dir() else {
        return;
    };
    let first = secure_heap::init().unwrap_err();
    let again = secure_heap::init().unwrap_err();
    let generation = generate_rsa(2048, &CancelFlag::new(), &|_| {}).unwrap_err();
    let words = SecretString::from_str_copy(SMALL_LIMIT_WORDS).expect("one locked page");
    let pem = std::fs::read(dir.join("key.pem")).expect("input key");
    let decryption = decrypt_key_pem(&pem, &words).unwrap_err();
    let random = keystone_core::crypto::rand::fill(&mut [0u8; 16]).unwrap_err();
    let unavailable =
        |error: &CryptoError| matches!(error, CryptoError::SecureHeapUnavailable { .. });
    let [limit, capability] = memlock_conditions();
    write_report(
        &dir,
        &[
            limit,
            capability,
            ("first", unavailable(&first).to_string()),
            ("again", unavailable(&again).to_string()),
            ("generation", unavailable(&generation).to_string()),
            ("decryption", unavailable(&decryption).to_string()),
            ("random", unavailable(&random).to_string()),
            ("initialized", secure_heap::status().initialized.to_string()),
            ("message", first.to_string()),
        ],
    );
}

const SMALL_LIMIT_WORDS: &str = "KEYSTONE TEST small limit words";

#[test]
fn sec07_a_too_small_memory_lock_limit_is_a_clear_error() {
    // Covers: SEC-07
    // 512 KiB cannot hold the 1 MiB heap: Keystone stops with a clear error instead
    // of generating or loading a private key in memory that could be swapped out.
    let words = SecretString::from_str_copy(SMALL_LIMIT_WORDS).expect("lock");
    let pem = encrypt_sub_key_pem(keys::rsa2048(0), &words).expect("encrypt");
    let report = run_child(
        "child_under_small_memlock",
        Some(512 * 1024),
        &[("key.pem", pem.as_bytes())],
    );
    assert_limit_applied(&report, 512 * 1024);
    for key in ["first", "again", "generation", "decryption", "random"] {
        assert_eq!(report[key], "true", "{key}: {report:?}");
    }
    // The heap that could not be locked was released again.
    assert_eq!(report["initialized"], "false", "{report:?}");
    assert!(
        report["message"].contains("RLIMIT_MEMLOCK") && report["message"].contains("8 MiB"),
        "{report:?}"
    );
}
