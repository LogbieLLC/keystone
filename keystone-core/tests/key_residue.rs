//! No copy of a private key is left in ordinary memory (SEC-07, T-07).
//!
//! After a key is decrypted, or encrypted with its read-back decryption, and every
//! secret object is dropped, the process memory must hold no copy of the key's
//! private numbers outside OpenSSL's locked secure heap. Freed heap memory is not
//! cleared by the allocator, so a plaintext copy that OpenSSL frees without wiping
//! stays readable until the memory is reused (review finding N1).
//!
//! How the check works:
//! - Each check runs in a fresh child process: this test binary run again with
//!   `KEYSTONE_KEY_RESIDUE_CHILD` set, as in `tests/secure_heap.rs`.
//! - The child does the key operations and drops the secrets. It then copies every
//!   readable anonymous or writable mapping of its own memory (`/proc/self/mem`) to a
//!   file in a `tempfile` directory (TEST-12), with a list of the mappings. The child
//!   never learns the private numbers, so the search cannot find its own search
//!   strings.
//! - The parent reads the private exponent d and the prime p from the encrypted key
//!   file with the `openssl` command line. It then looks for them in the copy, both
//!   big-endian (DER, as in an encoded key) and little-endian (OpenSSL's BIGNUM words
//!   on x86_64), in 32-byte windows. A window can only match a real copy: 32 bytes of
//!   a random prime do not occur by chance.
//! - The only allowed place is the secure heap: the one 1 MiB mapping that is locked
//!   (`lo`) and excluded from core dumps (`dd`) in `/proc/self/smaps`.
//! - Positive control: one decrypted (or generated) key stays alive in the child, so
//!   its little-endian p must be found in the secure heap. That proves the copy and
//!   the search work, so a pass is not vacuous.
//!
//! Test keys come from keystone-testkit (TEST-11).
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use keystone_core::crypto::pkcs8::{decrypt_key_pem, encrypt_master_key_pem, encrypt_sub_key_pem};
use keystone_core::crypto::secret::SecretString;
use keystone_core::crypto::secure_heap::{self, SECURE_HEAP_BYTES};
use keystone_testkit::keys;
use zeroize::Zeroize;

const CHILD_VAR: &str = "KEYSTONE_KEY_RESIDUE_CHILD";
const WORDS: &str = "KEYSTONE TEST residue words lantern mosaic falcon";
const KEY_FILE: &str = "key.pem";
const WORDS_FILE: &str = "words.txt";
const MEMORY_FILE: &str = "memory.bin";
const MAPS_FILE: &str = "mappings.txt";
/// Length of each search window.
const WINDOW: usize = 32;

fn child_dir() -> Option<PathBuf> {
    std::env::var_os(CHILD_VAR).map(PathBuf::from)
}

// ---------------------------------------------------------------------------
// Child side: copy this process's memory
// ---------------------------------------------------------------------------

/// One mapping from `/proc/self/smaps`. `path` is a range of the copier's text buffer.
#[derive(Clone, Copy, Default)]
struct Mapping {
    start: u64,
    len: u64,
    readable: bool,
    writable: bool,
    locked: bool,
    no_dump: bool,
    path: (usize, usize),
}

/// Copies this process's memory to a file without allocating once the key
/// operations have started.
///
/// A plaintext copy that OpenSSL freed without wiping sits in a free heap chunk, and
/// the next `malloc` of a smaller size may be carved out of that chunk and overwrite
/// it. If the copier allocated (reading `smaps` into a growing `String`, building
/// paths), it would destroy the very evidence it looks for. So every file, buffer and
/// list is created in [`MemoryCopier::prepare`], before the key operations, and
/// [`MemoryCopier::copy`] only reads and writes through them.
struct MemoryCopier {
    smaps: File,
    memory: File,
    out: File,
    list: File,
    text: Vec<u8>,
    mappings: Vec<Mapping>,
    buffer: Box<[u8]>,
}

impl MemoryCopier {
    fn prepare(dir: &Path) -> Self {
        MemoryCopier {
            smaps: File::open("/proc/self/smaps").expect("/proc/self/smaps"),
            memory: File::open("/proc/self/mem").expect("/proc/self/mem"),
            out: File::create(dir.join(MEMORY_FILE)).expect("memory copy"),
            list: File::create(dir.join(MAPS_FILE)).expect("mapping list"),
            text: vec![0u8; 16 << 20],
            mappings: Vec::with_capacity(1 << 16),
            buffer: vec![0u8; 64 * 1024].into_boxed_slice(),
        }
    }

    /// Reads `/proc/self/smaps` into the text buffer and parses the mappings.
    fn read_mappings(&mut self) {
        self.smaps.seek(SeekFrom::Start(0)).expect("rewind smaps");
        let mut len = 0;
        loop {
            let read = self.smaps.read(&mut self.text[len..]).expect("read smaps");
            if read == 0 {
                break;
            }
            len += read;
            assert!(len < self.text.len(), "smaps larger than the text buffer");
        }
        self.mappings.clear();
        let mut at = 0;
        while at < len {
            let end = self.text[at..len]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(len, |position| at + position);
            self.parse_line(at, end);
            at = end + 1;
        }
        assert!(
            self.mappings.len() < self.mappings.capacity(),
            "more mappings than the list holds"
        );
    }

    fn parse_line(&mut self, start: usize, end: usize) {
        let line = &self.text[start..end];
        if let Some(flags) = line.strip_prefix(b"VmFlags:") {
            if let Some(last) = self.mappings.last_mut() {
                for flag in flags.split(|byte| *byte == b' ') {
                    last.locked |= flag == b"lo";
                    last.no_dump |= flag == b"dd";
                }
            }
            return;
        }
        // Header: "start-end perms offset dev inode [path]". Other lines start with a
        // field name ("Rss:"), which is not two hex numbers joined by '-'.
        let mut fields = line
            .split(|byte| *byte == b' ')
            .filter(|field| !field.is_empty());
        let Some(range) = fields.next() else { return };
        let Some(dash) = range.iter().position(|byte| *byte == b'-') else {
            return;
        };
        let hex = |bytes: &[u8]| {
            if bytes.is_empty() {
                return None;
            }
            bytes.iter().try_fold(0u64, |acc, byte| {
                char::from(*byte)
                    .to_digit(16)
                    .map(|digit| (acc << 4) | u64::from(digit))
            })
        };
        let (Some(from), Some(to)) = (hex(&range[..dash]), hex(&range[dash + 1..])) else {
            return;
        };
        let perms = fields.next().unwrap_or_default();
        // The path is the sixth field and runs to the end of the line (it may contain
        // spaces); anonymous mappings have none.
        let mut seen = 0;
        let mut path = (end, end);
        let mut in_field = false;
        for (index, byte) in line.iter().enumerate() {
            let space = *byte == b' ';
            if !space && !in_field {
                seen += 1;
                if seen == 6 {
                    path = (start + index, end);
                    break;
                }
            }
            in_field = !space;
        }
        self.mappings.push(Mapping {
            start: from,
            len: to - from,
            readable: perms.first() == Some(&b'r'),
            writable: perms.get(1) == Some(&b'w'),
            locked: false,
            no_dump: false,
            path,
        });
    }

    fn path(&self, mapping: &Mapping) -> &[u8] {
        &self.text[mapping.path.0..mapping.path.1]
    }

    fn anonymous(&self, mapping: &Mapping) -> bool {
        let path = self.path(mapping);
        path.is_empty() || path.starts_with(b"[")
    }

    /// Readable, and anonymous or writable: the heap, stacks, `mmap` arenas, the secure
    /// heap and the writable data of the binary and its libraries. Read-only file
    /// mappings (program text) cannot hold a key.
    fn worth_copying(&self, mapping: &Mapping) -> bool {
        let path = self.path(mapping);
        mapping.readable
            && (self.anonymous(mapping) || mapping.writable)
            && !path.starts_with(b"[vvar")
            && path != b"[vsyscall]"
    }

    /// OpenSSL's secure heap: exactly `SECURE_HEAP_BYTES`, anonymous, writable, locked
    /// into RAM and excluded from core dumps.
    fn is_secure_heap(&self, mapping: &Mapping) -> bool {
        mapping.len == SECURE_HEAP_BYTES as u64
            && self.anonymous(mapping)
            && mapping.writable
            && mapping.locked
            && mapping.no_dump
    }

    /// Copies every mapping worth copying to `memory.bin` and lists them in
    /// `mappings.txt` (`file offset, address, length, secure heap, path`).
    ///
    /// The read buffer is wiped after every chunk, so the copy of the secure heap
    /// that passes through it is gone before the buffer's own memory is copied.
    fn copy(mut self) {
        self.read_mappings();
        let mut offset = 0u64;
        for index in 0..self.mappings.len() {
            let mapping = self.mappings[index];
            if !self.worth_copying(&mapping) {
                continue;
            }
            let secure = self.is_secure_heap(&mapping);
            write!(
                self.list,
                "{offset} {} {} {secure} ",
                mapping.start, mapping.len
            )
            .expect("write mapping list");
            let path = &self.text[mapping.path.0..mapping.path.1];
            self.list
                .write_all(if path.is_empty() { b"-" } else { path })
                .and_then(|()| self.list.write_all(b"\n"))
                .expect("write mapping list");
            let mut done = 0u64;
            while done < mapping.len {
                let n = usize::try_from((mapping.len - done).min(self.buffer.len() as u64))
                    .expect("chunk size");
                let read = self
                    .memory
                    .seek(SeekFrom::Start(mapping.start + done))
                    .and_then(|_| self.memory.read(&mut self.buffer[..n]))
                    .unwrap_or(0);
                self.buffer[read..n].fill(0);
                self.out
                    .write_all(&self.buffer[..n])
                    .expect("write memory copy");
                self.buffer.zeroize();
                done += n as u64;
            }
            offset += mapping.len;
        }
    }
}

fn words() -> SecretString {
    SecretString::from_str_copy(WORDS).expect("locked passphrase")
}

/// Sets up the child: the secure heap, the random generator (which keeps state in
/// the heap from its first use) and the memory copier.
fn start_child() -> Option<(PathBuf, MemoryCopier)> {
    let dir = child_dir()?;
    secure_heap::init().expect("secure heap");
    keystone_core::crypto::rand::fill(&mut [0u8; 32]).expect("random");
    let copier = MemoryCopier::prepare(&dir);
    Some((dir, copier))
}

/// Child half of `sec07_decrypting_a_key_leaves_no_copy_outside_the_secure_heap`.
#[test]
fn child_decrypt() {
    let Some((dir, copier)) = start_child() else {
        return;
    };
    let pem = std::fs::read(dir.join(KEY_FILE)).expect("key file");
    let words = words();
    let kept = decrypt_key_pem(&pem, &words).expect("decrypt");
    let dropped = decrypt_key_pem(&pem, &words).expect("decrypt again");
    drop(dropped);
    drop(words);
    copier.copy();
    drop(kept);
}

/// Child half of `sec07_a_decrypted_key_used_for_signing_leaves_no_copy_after_drop`.
#[test]
fn child_decrypt_sign() {
    let Some((dir, copier)) = start_child() else {
        return;
    };
    let pem = std::fs::read(dir.join(KEY_FILE)).expect("key file");
    let words = words();
    let kept = decrypt_key_pem(&pem, &words).expect("decrypt");
    let used = decrypt_key_pem(&pem, &words).expect("decrypt again");
    drop(words);
    let signature = used
        .sign_sha384_pkcs1(b"KEYSTONE TEST residue message")
        .expect("sign");
    assert_eq!(signature.len(), 256);
    drop(used);
    copier.copy();
    drop(kept);
}

fn child_encrypt(master: bool) {
    let Some((dir, copier)) = start_child() else {
        return;
    };
    let mut key_file = File::create(dir.join(KEY_FILE)).expect("key file");
    // The testkit key stays alive (cached) for the rest of the child: the control.
    let key = keys::rsa2048(0);
    let words = words();
    let pem = if master {
        encrypt_master_key_pem(key, &words)
    } else {
        encrypt_sub_key_pem(key, &words)
    }
    .expect("encrypt");
    drop(words);
    key_file
        .write_all(pem.as_bytes())
        .expect("write encrypted key");
    drop(pem);
    copier.copy();
}

/// Child half of `sec07_encrypting_a_master_key_leaves_no_copy_outside_the_secure_heap`.
#[test]
fn child_encrypt_master() {
    child_encrypt(true);
}

/// Child half of `sec07_encrypting_a_sub_key_leaves_no_copy_outside_the_secure_heap`.
#[test]
fn child_encrypt_sub() {
    child_encrypt(false);
}

// ---------------------------------------------------------------------------
// Parent side: run the child, read the key's numbers, search the copy
// ---------------------------------------------------------------------------

/// Runs the test `name` alone in a child process with `inputs` in its directory.
fn run_child(name: &str, inputs: &[(&str, &[u8])]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temporary directory");
    for (file, contents) in inputs {
        std::fs::write(dir.path().join(file), contents).expect("write child input");
    }
    let exe = std::env::current_exe().expect("test binary path");
    let output = Command::new(&exe)
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD_VAR, dir.path())
        .output()
        .expect("start the child test");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "child test {name} failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    dir
}

/// One DER element: (tag, content, rest).
fn der(input: &[u8]) -> (u8, &[u8], &[u8]) {
    let tag = input[0];
    let first = input[1];
    let (len, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        let len = input[2..2 + count]
            .iter()
            .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
        (len, 2 + count)
    };
    (tag, &input[header..header + len], &input[header + len..])
}

/// An INTEGER's magnitude, big-endian, without leading zero bytes.
fn integer(content: &[u8]) -> Vec<u8> {
    let start = content.iter().position(|byte| *byte != 0).unwrap_or(0);
    content[start..].to_vec()
}

/// The private numbers of the key, read with the `openssl` command line (not with
/// Keystone, whose code is under test).
struct PrivateNumbers {
    d: Vec<u8>,
    p: Vec<u8>,
}

fn private_numbers(dir: &Path) -> PrivateNumbers {
    std::fs::write(dir.join(WORDS_FILE), WORDS).expect("write passphrase file");
    let output = Command::new("openssl")
        .args([
            "pkey",
            "-in",
            KEY_FILE,
            "-passin",
            &format!("file:{WORDS_FILE}"),
            "-outform",
            "DER",
        ])
        .current_dir(dir)
        .output()
        .expect("the openssl command line must be installed");
    assert!(
        output.status.success(),
        "openssl pkey: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Either PrivateKeyInfo { version, algorithm SEQUENCE, privateKey OCTET STRING
    // { RSAPrivateKey } } or RSAPrivateKey itself, depending on the OpenSSL version.
    let (_, outer, _) = der(&output.stdout);
    let (_, _, after_version) = der(outer);
    let fields = if after_version[0] == 0x30 {
        let (_, _, rest) = der(after_version);
        let (tag, rsa, _) = der(rest);
        assert_eq!(tag, 0x04, "privateKey OCTET STRING");
        der(rsa).1
    } else {
        outer
    };
    // RSAPrivateKey { version, n, e, d, p, q, dP, dQ, qInv }
    let mut numbers = Vec::new();
    let mut rest = fields;
    for _ in 0..5 {
        let (tag, content, next) = der(rest);
        assert_eq!(tag, 0x02, "INTEGER");
        numbers.push(integer(content));
        rest = next;
    }
    let p = numbers.pop().expect("p");
    let d = numbers.pop().expect("d");
    assert!(p.len() >= 128 && d.len() >= 250, "an RSA 2,048 key");
    PrivateNumbers { d, p }
}

struct Region {
    offset: u64,
    start: u64,
    len: u64,
    secure_heap: bool,
    path: String,
}

fn regions(dir: &Path) -> Vec<Region> {
    std::fs::read_to_string(dir.join(MAPS_FILE))
        .expect("mapping list")
        .lines()
        .map(|line| {
            let fields: Vec<&str> = line.splitn(5, ' ').collect();
            Region {
                offset: fields[0].parse().unwrap(),
                start: fields[1].parse().unwrap(),
                len: fields[2].parse().unwrap(),
                secure_heap: fields[3] == "true",
                path: fields[4].to_owned(),
            }
        })
        .collect()
}

/// Every non-overlapping 32-byte window of `bytes`.
fn windows(bytes: &[u8]) -> Vec<Vec<u8>> {
    bytes
        .as_chunks::<WINDOW>()
        .0
        .iter()
        .map(|chunk| chunk.to_vec())
        .collect()
}

/// Where the private numbers were found in the child's memory.
#[derive(Debug, Default)]
struct Findings {
    /// Hits in the secure heap, per needle label.
    in_secure_heap: BTreeMap<String, usize>,
    /// Hits anywhere else: (needle label, address, mapping).
    elsewhere: Vec<(String, u64, String)>,
}

fn search(dir: &Path, numbers: &PrivateNumbers) -> Findings {
    let memory = std::fs::read(dir.join(MEMORY_FILE)).expect("memory copy");
    let regions = regions(dir);
    assert_eq!(
        regions.iter().filter(|region| region.secure_heap).count(),
        1,
        "exactly one secure heap mapping in the child"
    );
    let reversed = |bytes: &[u8]| bytes.iter().rev().copied().collect::<Vec<u8>>();
    let mut needles: Vec<(String, Vec<u8>)> = Vec::new();
    for (name, value) in [("d", &numbers.d), ("p", &numbers.p)] {
        for (index, window) in windows(value).into_iter().enumerate() {
            needles.push((format!("{name} big-endian window {index}"), window));
        }
        for (index, window) in windows(&reversed(value)).into_iter().enumerate() {
            needles.push((format!("{name} little-endian window {index}"), window));
        }
    }
    // Needles by first byte, so the copy is read once.
    let mut by_first: Vec<Vec<usize>> = vec![Vec::new(); 256];
    for (index, (_, needle)) in needles.iter().enumerate() {
        by_first[usize::from(needle[0])].push(index);
    }
    let mut findings = Findings::default();
    let last = memory.len().saturating_sub(WINDOW);
    for at in 0..=last {
        for &index in &by_first[usize::from(memory[at])] {
            let (label, needle) = &needles[index];
            if memory[at..at + WINDOW] != needle[..] {
                continue;
            }
            let at = at as u64;
            let region = regions
                .iter()
                .find(|region| at >= region.offset && at < region.offset + region.len)
                .expect("hit inside a copied mapping");
            if region.secure_heap {
                *findings.in_secure_heap.entry(label.clone()).or_default() += 1;
            } else {
                findings.elsewhere.push((
                    label.clone(),
                    region.start + (at - region.offset),
                    region.path.clone(),
                ));
            }
        }
    }
    findings
}

fn assert_no_copy_outside_the_secure_heap(findings: &Findings) {
    let listing: Vec<String> = findings
        .elsewhere
        .iter()
        .map(|(label, address, path)| format!("{label} at {address:#x} in {path}"))
        .collect();
    assert!(
        findings.elsewhere.is_empty(),
        "{} piece(s) of the private key outside the secure heap:\n{}",
        listing.len(),
        listing.join("\n")
    );
}

/// The live control key's p, as OpenSSL's BIGNUM words, is in the secure heap: the
/// copy and the search work.
fn assert_control_key_found(findings: &Findings) {
    let windows_found = findings
        .in_secure_heap
        .keys()
        .filter(|label| label.starts_with("p little-endian"))
        .count();
    assert_eq!(
        windows_found,
        128 / WINDOW,
        "the live key's p must be found in the secure heap: {findings:?}"
    );
}

/// A testkit key encrypted for a sub-intermediate, as the child's input.
fn encrypted_test_key(index: usize) -> String {
    let words = SecretString::from_str_copy(WORDS).expect("lock");
    encrypt_sub_key_pem(keys::rsa2048(index), &words).expect("encrypt")
}

#[test]
fn sec07_decrypting_a_key_leaves_no_copy_outside_the_secure_heap() {
    // Covers: SEC-07, FR-04 AC2
    // Two decryptions of the same file; one key is dropped, the other stays alive.
    let pem = encrypted_test_key(2);
    let dir = run_child("child_decrypt", &[(KEY_FILE, pem.as_bytes())]);
    let findings = search(dir.path(), &private_numbers(dir.path()));
    assert_no_copy_outside_the_secure_heap(&findings);
    assert_control_key_found(&findings);
}

#[test]
fn sec07_a_decrypted_key_used_for_signing_leaves_no_copy_after_drop() {
    // Covers: SEC-07, FR-04 AC2
    // The signing key is dropped; a second decryption, never used, stays alive.
    let pem = encrypted_test_key(3);
    let dir = run_child("child_decrypt_sign", &[(KEY_FILE, pem.as_bytes())]);
    let findings = search(dir.path(), &private_numbers(dir.path()));
    assert_no_copy_outside_the_secure_heap(&findings);
    assert_control_key_found(&findings);
}

#[test]
fn sec07_encrypting_a_master_key_leaves_no_copy_outside_the_secure_heap() {
    // Covers: SEC-07, SEC-04, FR-04 AC1
    // scrypt encryption and its read-back decryption; the testkit key stays alive.
    let dir = run_child("child_encrypt_master", &[]);
    let findings = search(dir.path(), &private_numbers(dir.path()));
    assert_no_copy_outside_the_secure_heap(&findings);
    assert_control_key_found(&findings);
}

#[test]
fn sec07_encrypting_a_sub_key_leaves_no_copy_outside_the_secure_heap() {
    // Covers: SEC-07, SEC-04, FR-04 AC1
    // PBKDF2 encryption and its read-back decryption; the testkit key stays alive.
    let dir = run_child("child_encrypt_sub", &[]);
    let findings = search(dir.path(), &private_numbers(dir.path()));
    assert_no_copy_outside_the_secure_heap(&findings);
    assert_control_key_found(&findings);
}
