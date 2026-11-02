//! Process hardening: no core dumps (SEC-07).
#![forbid(unsafe_code)]

use rustix::process::{
    DumpableBehavior, Resource, Rlimit, dumpable_behavior, getrlimit, set_dumpable_behavior,
    setrlimit,
};

use super::HardeningError;

/// SEC-07: disables core dumps for the whole process: `RLIMIT_CORE` soft and hard limits
/// 0 (cannot be raised again) and `PR_SET_DUMPABLE` 0. Secrets in memory can then never
/// be written to a core file.
pub fn disable_core_dumps() -> Result<(), HardeningError> {
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|e| HardeningError::CoreDumps(format!("RLIMIT_CORE: {e}")))?;
    set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .map_err(|e| HardeningError::CoreDumps(format!("PR_SET_DUMPABLE: {e}")))?;
    Ok(())
}

/// True when core dumps are disabled as [`disable_core_dumps`] leaves them.
pub fn core_dumps_disabled() -> Result<bool, HardeningError> {
    let limit = getrlimit(Resource::Core);
    let dumpable = dumpable_behavior()
        .map_err(|e| HardeningError::CoreDumps(format!("PR_GET_DUMPABLE: {e}")))?;
    Ok(limit.current == Some(0)
        && limit.maximum == Some(0)
        && dumpable == DumpableBehavior::NotDumpable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardening::child;

    /// Child half of `sec07_core_dumps_are_disabled`: changes this process only when it
    /// runs as the child; in the normal test run it only checks the read-back works.
    #[test]
    fn sec07_core_dump_child() {
        let Some(dir) = child::child_dir() else {
            assert!(core_dumps_disabled().is_ok());
            return;
        };
        disable_core_dumps().expect("disable");
        let disabled = core_dumps_disabled().expect("read");
        // The hard limit cannot be raised again.
        let raised = setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(1 << 20),
                maximum: Some(1 << 20),
            },
        );
        std::fs::write(
            dir.join("result.txt"),
            format!("disabled={disabled} raise_refused={}", raised.is_err()),
        )
        .expect("write result");
    }

    #[test]
    fn sec07_core_dumps_are_disabled() {
        // Covers: SEC-07
        let dir = tempfile::tempdir().expect("tempdir");
        child::run(
            "hardening::process::tests::sec07_core_dump_child",
            dir.path(),
        );
        let result = std::fs::read_to_string(dir.path().join("result.txt")).expect("result");
        assert!(result.contains("disabled=true"), "{result}");
        // Root may raise a hard limit again (CAP_SYS_RESOURCE); everyone else may not.
        let is_root = rustix::process::geteuid().is_root();
        if !is_root {
            assert!(result.contains("raise_refused=true"), "{result}");
        }
    }
}
