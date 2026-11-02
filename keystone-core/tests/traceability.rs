//! `scripts/traceability.py` counts `Covers:` lines only in test code (TEST-01,
//! NFR-06; review finding N4).
//!
//! Each case builds a small synthetic repository in a `tempfile` directory (TEST-12)
//! with the script, a four-requirement PRD and a few files, runs the script with
//! `--report` and checks which requirements it counts as tested.
//!
//! The marker is assembled at run time (`TAG`), so this file itself carries no
//! `Covers:` line for the synthetic requirements and cannot cover them in the real
//! repository.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

const TAG: &str = concat!("Cov", "ers:");

/// Requirements: FR-01 AC1, FR-01 AC2, SEC-01, SEC-02.
const PRD: &str = "# KEYSTONE TEST PRD\n\n## 7. Functional requirements\n\n**FR-01 Test requirement**\n- AC1: first\n- AC2: second\n\n## 9. Security requirements\n\n| ID | Requirement | Threats |\n| --- | --- | --- |\n| SEC-01 | first | T-01 |\n| SEC-02 | second | T-02 |\n";

struct Outcome {
    passed: bool,
    report: String,
}

impl Outcome {
    fn tested(&self, requirement: &str) -> bool {
        self.report
            .lines()
            .any(|line| line.starts_with(requirement) && line.contains(" tested ("))
    }
}

fn rust_line(requirement: &str) -> String {
    format!("// {TAG} {requirement}")
}

fn python_line(requirement: &str) -> String {
    format!("# {TAG} {requirement}")
}

fn run(files: &[(&str, String)]) -> Outcome {
    let dir = tempfile::tempdir().expect("temporary directory");
    let root = dir.path();
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("scripts")
        .join("traceability.py");
    write(
        root,
        "scripts/traceability.py",
        &std::fs::read_to_string(script).expect("script"),
    );
    write(root, "Keystone PRD6 - final.md", PRD);
    for (path, contents) in files {
        write(root, path, contents);
    }
    let output = Command::new("python3")
        .arg("-I")
        .arg(root.join("scripts/traceability.py"))
        .arg("--report")
        .output()
        .expect("python3 must be installed");
    Outcome {
        passed: output.status.success(),
        report: String::from_utf8_lossy(&output.stdout).into_owned(),
    }
}

fn write(root: &Path, path: &str, contents: &str) {
    let path = root.join(path);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("create directory");
    std::fs::write(path, contents).expect("write test file");
}

#[test]
fn nfr06_covers_lines_outside_test_code_do_not_count() {
    // Covers: NFR-06
    // The reviewer's trick: one never-compiled shell file naming every requirement.
    let notes: String = ["FR-01 AC1", "FR-01 AC2", "SEC-01", "SEC-02"]
        .iter()
        .map(|id| format!("{}\n", python_line(id)))
        .collect();
    let outcome = run(&[("keystone-core/notes.sh", notes)]);
    assert!(!outcome.passed, "{}", outcome.report);
    assert!(
        outcome.report.contains("4 requirements; 0 accounted for."),
        "{}",
        outcome.report
    );
    assert!(
        outcome
            .report
            .contains("not test code: keystone-core/notes.sh:1"),
        "{}",
        outcome.report
    );

    // Application code, an example, a helper Python module, a Go helper that no
    // Rust test runs, and a `cfg(any(test, ...))` module are not test code either.
    let outcome = run(&[
        (
            "keystone-core/src/lib.rs",
            format!(
                "pub fn f() {{\n    {}\n}}\n\n#[cfg(any(test, feature = \"x\"))]\nmod helpers {{\n    {}\n}}\n",
                rust_line("FR-01 AC1"),
                rust_line("FR-01 AC2")
            ),
        ),
        (
            "keystone-testkit/examples/sample.rs",
            format!("fn main() {{\n    {}\n}}\n", rust_line("SEC-01")),
        ),
        (
            "keystone-gui/tests/e2e/helper.py",
            format!("{}\n", python_line("SEC-02")),
        ),
        (
            "keystone-core/tests/interop/unused.go",
            format!("{}\npackage main\n", rust_line("SEC-02")),
        ),
    ]);
    assert!(
        outcome.report.contains("4 requirements; 0 accounted for."),
        "{}",
        outcome.report
    );
}

#[test]
fn nfr06_covers_lines_in_test_code_count() {
    // Covers: NFR-06
    let outcome = run(&[
        // An inline #[cfg(test)] module; the line after it is not test code.
        (
            "keystone-core/src/lib.rs",
            format!(
                "mod x;\n\n#[cfg(test)]\nmod tests {{\n    #[test]\n    fn t() {{\n        let _ = \"}}\";\n        {}\n    }}\n}}\n\npub fn after() {{\n    {}\n}}\n",
                rust_line("FR-01 AC1"),
                rust_line("SEC-02")
            ),
        ),
        // A file declared as #[cfg(test)] mod tests;
        (
            "keystone-core/src/x.rs",
            "pub fn f() {}\n\n#[cfg(test)]\nmod tests;\n".to_owned(),
        ),
        (
            "keystone-core/src/x/tests.rs",
            format!("#[test]\nfn t() {{\n    {}\n}}\n", rust_line("FR-01 AC2")),
        ),
        // A Python E2E test.
        (
            "keystone-gui/tests/e2e/test_flow.py",
            format!("def test_flow():\n    {}\n", python_line("SEC-01")),
        ),
    ]);
    assert!(outcome.tested("FR-01 AC1"), "{}", outcome.report);
    assert!(outcome.tested("FR-01 AC2"), "{}", outcome.report);
    assert!(outcome.tested("SEC-01"), "{}", outcome.report);
    assert!(!outcome.tested("SEC-02"), "{}", outcome.report);
    assert!(!outcome.passed, "{}", outcome.report);

    // A Rust integration test, a fuzz target, and a Go helper that a Rust test runs.
    let outcome = run(&[
        (
            "keystone-core/tests/flow.rs",
            format!(
                "#[test]\nfn t() {{\n    {}\n    let _ = \"tests/interop/verify.go\";\n}}\n",
                rust_line("FR-01 AC1")
            ),
        ),
        (
            "fuzz/fuzz_targets/parse.rs",
            format!("{}\n", rust_line("FR-01 AC2")),
        ),
        (
            "keystone-core/tests/interop/verify.go",
            format!("{}\npackage main\n", rust_line("SEC-01")),
        ),
        (
            "keystone-core/tests/interop/main.rs",
            format!("{}\n", rust_line("SEC-02")),
        ),
    ]);
    assert!(outcome.passed, "{}", outcome.report);
    assert!(
        outcome.report.contains("4 requirements; 4 accounted for."),
        "{}",
        outcome.report
    );
}
