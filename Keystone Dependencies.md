# Keystone — Dependency Decisions

Date: November 1, 2026  
Based on: **Keystone PRD6 — final**  
Target: **Ubuntu 26.04.1 desktop, x86-64**

## Status

The library choices below form the selected dependency baseline. The owner approved an exactly pinned YubiKey release candidate after review and hardware testing.

This document records the decisions. No project manifests, lockfile, vendor patch, builds, dependency audits or hardware tests have been completed as part of this dependency review. The YubiKey driver requires changes before it can meet the production requirements.

## Rust toolchain

- **Rust 1.99.1**, the current stable release on the date of this review.
- **Rust 2024 edition**.
- **Target:** `x86_64-unknown-linux-gnu`.
- Pin the exact compiler version in `rust-toolchain.toml`; do not use a floating `stable` channel for reproducible release builds.

Source: [Rust 1.99.1 announcement](https://blog.rust-lang.org/2026/10/15/Rust-1.99.1/).

## Application dependencies

Use exact version requirements for the selected baseline and commit `Cargo.lock` to pin the complete dependency graph.

| Purpose | Package | Selected version | Decision |
| --- | --- | --- | --- |
| GTK interface | `gtk4` | `0.11.5` | Thin GUI over the core library. Use the `gtk` alias. |
| GNOME interface components | `libadwaita` | `0.9.2` | Use the `adw` alias and the compatible GTK/GLib family. |
| Software cryptography | `openssl` | `0.10.81` | Link to Ubuntu's OpenSSL 3. Leave the `vendored` feature disabled. |
| Certificate and CRL encoding | `x509-cert` | `0.3.0` | Assemble structures signed by the token; reuse its DER reexports. |
| Native YubiKey PIV | `yubikey` | `=0.9.0-rc.0` | Reviewed local patch required before production; see below. |
| Record serialization | `serde` | `1.0.229` | Enable `derive` for typed records. |
| JSON files | `serde_json` | `1.0.154` | Issuance record, operation journal and audit entries; enforce input limits. |
| Dates and validity | `time` | `0.3.55` | Use UTC for persisted timestamps and certificate calculations. |
| Secret wiping | `zeroize` | `1.9.1` | Wipe application-owned secret buffers; also require locked memory. |
| Linux file and memory protection | `rustix` | `1.1.6` | Enable the required `fs`, `mm` and `process` modules. |
| Socket restrictions | `seccompiler` | `0.5.0` | Define the fixed Linux policy in Rust; optional JSON support is unnecessary. |
| Structured errors | `thiserror` | `2.0.21` | Typed errors suitable for the core library and guided GUI. |

Package sources: [GTK4](https://docs.rs/crate/gtk4/0.11.5), [libadwaita](https://docs.rs/crate/libadwaita/0.9.2), [OpenSSL](https://docs.rs/openssl/latest/openssl/), [X.509](https://docs.rs/x509-cert/latest/x509_cert/), [YubiKey release metadata](https://crates.io/api/v1/crates/yubikey/0.9.0-rc.0), [Serde](https://docs.rs/serde/latest/serde/), [JSON](https://docs.rs/serde_json/latest/serde_json/), [time](https://docs.rs/time/latest/time/), [zeroize](https://docs.rs/zeroize/latest/zeroize/), [rustix](https://docs.rs/rustix/latest/rustix/), [seccompiler](https://docs.rs/seccompiler/latest/seccompiler/), [thiserror](https://docs.rs/thiserror/latest/thiserror/).

### Dependency boundaries

- Keep GTK and libadwaita in `keystone-gui`; the core must remain testable without a display.
- Reuse GTK's GLib/GIO reexports rather than selecting another incompatible version family.
- Enable only GUI API features actually needed. Ubuntu's verified API ceilings are GTK `v4_22` and libadwaita `v1_9`.
- Keep `pcsc 2.9.0` transitive through `yubikey` unless Keystone directly uses PC/SC APIs.
- The reviewed native bridge may directly use `openssl-sys 0.9.117` and the compatible support crates already required by OpenSSL. Keep unsafe operations confined to the reviewed boundary.
- Use OpenSSL for application software key generation, hashing, randomness and encryption. Do not add separate algorithm libraries for those same application operations.
- The YubiKey driver itself requires RustCrypto dependencies. Its current package features cannot remove that additional crypto family; include it in the dependency review.
- The YubiKey driver enables `x509-cert` features including `builder` and `hazmat`. Cargo combines features across users of the same package, so disabling them only in Keystone's direct declaration does not remove them from the complete build.

Sources: [OpenSSL dependency manifest](https://docs.rs/crate/openssl/latest/source/Cargo.toml), [YubiKey dependency manifest](https://github.com/iqlusioninc/yubikey.rs/blob/24339f5a5a1121417aaa8052c13d8942d6931d48/Cargo.toml), [PC/SC package](https://docs.rs/crate/pcsc/latest/source/Cargo.toml.orig).

## YubiKey driver: required production work

The stable `yubikey 0.8.0` does not cover the PRD's RSA-4096 and AES management-key requirements. The selected release candidate supplies the needed base functionality, but the unmodified package does not satisfy all Keystone requirements.

Use an explicitly reviewed local patch based on:

- Package: **`yubikey 0.9.0-rc.0`**.
- Source commit: **`24339f5a5a1121417aaa8052c13d8942d6931d48`**.
- Published archive SHA-256: **`666409240f19e7820baf7a22497e66db1c7df9efc87c9c29a9e2d540d9b0c286`**.
- This release candidate has no Cargo feature flags; do not add the older `untested` flag.

The following work is required before production acceptance:

1. **Secret lifetime:** replace the driver's unwiped PIN cache and review temporary PIN, PUK, authentication and management-key buffers. Application-level `zeroize` cannot wipe private copies retained inside the driver.
2. **Sensitive logging:** remove or redact raw token-command logging that can expose secrets. Compile dependency diagnostic logging out of release builds; a runtime log-level setting is insufficient as the production control.
3. **SHA-384 signatures:** add a reviewed adapter or generalize the driver's existing RSA signing helper, which hardcodes SHA-256. Verify certificate and CRL signatures independently with OpenSSL.
4. **Explicit AES-256 selection:** select the AES-256 management-key algorithm explicitly. The driver's automatic selection uses AES-192 on firmware 5.7+, which does not match the PRD.
5. **Hardening verification:** reopen the token and confirm PIN-protected management-key recovery and authentication after setup. Do not treat a successful setter return as proof that all metadata writes succeeded.
6. **Occupied-slot protection:** inspect both key metadata and certificate storage. Certificate listing alone misses a generated key whose certificate has not yet been written.
7. **Explicit slot wipe:** supply the missing per-slot private-key deletion operation. Deleting a certificate object does not delete its key, and resetting the entire PIV application is a different operation.
8. **Offline attestation:** implement and test full chain verification, public-key matching, serial matching and PIN/touch policy checks using the embedded Yubico trust material.

Keep the patch as a separately reviewable local dependency override. Do not silently edit a Cargo-generated vendor directory. Record the patch diff and its checksum alongside the upstream identity.

Sources: [PIN cache](https://github.com/iqlusioninc/yubikey.rs/blob/24339f5a5a1121417aaa8052c13d8942d6931d48/src/yubikey.rs#L77), [RSA signing helper](https://github.com/iqlusioninc/yubikey.rs/blob/24339f5a5a1121417aaa8052c13d8942d6931d48/src/certificate.rs#L423), [management-key operations](https://github.com/iqlusioninc/yubikey.rs/blob/24339f5a5a1121417aaa8052c13d8942d6931d48/src/mgm.rs), [token-command logging](https://github.com/iqlusioninc/yubikey.rs/blob/24339f5a5a1121417aaa8052c13d8942d6931d48/src/apdu.rs#L121), [Yubico PIV extensions](https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html), [Yubico attestation verification](https://developers.yubico.com/yubico-piv-tool/Attestation.html).

## Ubuntu dependencies

Use distribution packages for the native libraries and services.

| Environment | Packages |
| --- | --- |
| Build | `build-essential`, `pkg-config`, `libgtk-4-dev`, `libadwaita-1-dev`, `libssl-dev`, `libpcsclite-dev` |
| Runtime | `libgtk-4-1`, `libadwaita-1-0`, `libssl3t64`, `libpcsclite1`, `pcscd`, `libccid` |
| GUI test environment | `python3-dogtail` and its packaged dependencies, in a GNOME accessibility-enabled session |

The reviewed Ubuntu archive provides GTK 4.22, libadwaita 1.9 and OpenSSL 3.5. Freeze the actual build/test image and its complete package manifest. A Rust lockfile does not pin native libraries or their security revisions.

Sources: [Ubuntu package index](https://packages.ubuntu.com/resolute-updates/allpackages), [Dogtail Wayland instructions](https://gitlab.com/dogtail/dogtail/-/blob/master/README.md).

## Development and CI

| Purpose | Selection |
| --- | --- |
| Property tests | `proptest 1.12.0` |
| Temporary test directories | `tempfile 3.27.0` |
| Vulnerability and dependency policy checks | `cargo audit`, `cargo deny`, `cargo vet` |
| Formatting and linting | Rustfmt and Clippy from the pinned toolchain |
| Core coverage | `cargo llvm-cov` |
| Parser fuzzing | `cargo-fuzz` with separate fuzz targets and a separately pinned compatible fuzzing toolchain |
| GUI E2E | Dogtail through GTK accessibility on the target desktop environment |
| Certificate and CRL interoperability | Ubuntu OpenSSL CLI, plus a pinned RFC 5280 lint tool verified against the private-CA profiles |
| Network-policy verification | `strace` and negative tests for prohibited sockets |
| Hardware acceptance | Real YubiKey 5 with firmware 5.7+ and operator touch |

Pin external CI tool versions when the workspace and CI image are created; they are not production application dependencies. Keep StarnetAuth network integration testing outside the production binary.

Sources: [proptest](https://docs.rs/proptest/latest/proptest/), [tempfile](https://docs.rs/tempfile/latest/tempfile/).

## Release and offline build policy

1. Commit the workspace manifests, exact Rust toolchain and `Cargo.lock`.
2. Vendor the complete Rust dependency graph, including the reviewed local driver override.
3. Configure Cargo to use the local sources and build with `--frozen`.
4. Leave OpenSSL's `vendored` Cargo feature disabled. Vendoring Rust crate sources is separate from bundling a private OpenSSL build.
5. Freeze the build image, native package versions and relevant build inputs.
6. Run the dependency checks, acceptance tests and real-token tests required by the PRD.
7. Require matching hashes from the two independent production builds before transfer to the offline laptop.

Sources: [Cargo vendoring](https://doc.rust-lang.org/cargo/commands/cargo-vendor.html), [Cargo frozen builds](https://doc.rust-lang.org/cargo/commands/cargo-build.html), [OpenSSL build configuration](https://docs.rs/openssl/latest/openssl/).

## PRD clarification required

The literal requirement that no dependency contain networking code conflicts with using distribution GTK/GIO, which includes networking APIs. Cargo feature selection cannot remove those APIs from Ubuntu's shared GIO library.

Recommended wording for review:

> Keystone implements no application networking features. Production denies nonlocal network access while permitting AF_UNIX communication required by the desktop and PC/SC.

The implementation must also account for inherited network descriptors and alternative socket-creation paths; filtering only the `socket()` call does not prove the broader guarantee. Keep those checks in the network-policy tests.

Sources: [GIO networking API](https://docs.gtk.org/gio/class.SocketClient.html), [kernel seccomp documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html).

## Remaining acceptance gates

- Reviewed YubiKey patch, secret-buffer handling and SHA-384 interoperability.
- Explicit key-encryption parameters and cancellable key generation through the reviewed OpenSSL boundary.
- Clean Ubuntu build, complete dependency audit and native-library inventory.
- Real-token PIV, attestation, recovery and seccomp tests.
- Reproducible builds from frozen inputs.
- The PRD's StarnetAuth encrypted-key import and CRL-hosting acceptance tests.

These are outstanding validation and implementation requirements, not completed checks. The dependency selection does not by itself establish production readiness.
