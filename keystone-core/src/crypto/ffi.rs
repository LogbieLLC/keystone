//! The single reviewed FFI module (SEC-18). The only file in the workspace where
//! `unsafe` code is allowed. Every unsafe block carries a `// SAFETY:` comment.
//!
//! Contents are added by the crypto work (explicit PKCS#8 encryption parameters,
//! cancellable RSA key generation, locked memory for secrets).
