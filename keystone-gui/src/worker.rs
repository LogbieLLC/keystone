//! Long-running work off the GUI thread (FR-16 AC1, AC2, NFR-03).
//!
//! A job runs on its own `std::thread`. It reports progress through a [`Progress`]
//! handle; the GUI thread polls a `std::sync::mpsc` channel from a GLib timeout every
//! [`POLL_INTERVAL`] and never waits on the job, so the main loop is never blocked
//! (NFR-03: no frame blocked for more than 100 ms). No async runtime is used.
//!
//! # Cancel (FR-16 AC2)
//! A job that may be cancelled starts *cancellable*. The GUI offers Cancel only while
//! the job is still cancellable. Before its first persistent change (a signature, a
//! YubiKey credential change, an on-device key, or an output moved into place) the job
//! calls [`Progress::begin_persistent_change`]: that atomically ends the cancellable
//! phase, or fails with [`Cancelled`] when the operator already pressed Cancel. There
//! is no window in which a cancel request is accepted after the point of no return.
//! The same request also sets the core [`CancelFlag`] that RSA key generation polls.
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use keystone_core::crypto::CancelFlag;

/// How often the GUI thread looks for progress messages.
pub const POLL_INTERVAL: Duration = Duration::from_millis(40);

/// Most messages handled per poll, so a chatty job can never stall the main loop.
pub const MAX_MESSAGES_PER_POLL: usize = 64;

const NOT_CANCELLABLE: u8 = 0;
const CANCELLABLE: u8 = 1;
const CANCEL_REQUESTED: u8 = 2;
const COMMITTED: u8 = 3;

/// The operator cancelled before the first persistent change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("cancelled before any persistent change")]
pub struct Cancelled;

/// Where a job is in its cancel life cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelPhase {
    /// The job cannot be cancelled (read-only work, or a job that never allowed it).
    NotCancellable,
    /// Cancel is offered.
    Cancellable,
    /// The operator pressed Cancel; the job will stop at its next check.
    CancelRequested,
    /// The first persistent change happened: the job finishes or is resumed on the
    /// recovery screen (FR-22).
    Committed,
}

impl CancelPhase {
    fn from_raw(raw: u8) -> Self {
        match raw {
            CANCELLABLE => CancelPhase::Cancellable,
            CANCEL_REQUESTED => CancelPhase::CancelRequested,
            COMMITTED => CancelPhase::Committed,
            _ => CancelPhase::NotCancellable,
        }
    }
}

/// A progress message from a job.
#[derive(Debug, Clone, PartialEq)]
pub struct ProgressUpdate {
    /// Fraction done (0.0 to 1.0), or `None` when unknown (the bar pulses).
    pub fraction: Option<f64>,
    /// One plain sentence: what is happening now.
    pub message: String,
}

#[derive(Debug)]
struct Shared {
    phase: AtomicU8,
    flag: CancelFlag,
}

/// The job's side: report progress and honour Cancel. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Progress {
    shared: Arc<Shared>,
    sender: mpsc::Sender<ProgressUpdate>,
}

impl Progress {
    /// A handle and the receiving end of its messages.
    pub fn new(cancellable: bool) -> (Progress, mpsc::Receiver<ProgressUpdate>) {
        let (sender, receiver) = mpsc::channel();
        let phase = if cancellable {
            CANCELLABLE
        } else {
            NOT_CANCELLABLE
        };
        (
            Progress {
                shared: Arc::new(Shared {
                    phase: AtomicU8::new(phase),
                    flag: CancelFlag::new(),
                }),
                sender,
            },
            receiver,
        )
    }

    /// The current cancel phase.
    pub fn phase(&self) -> CancelPhase {
        CancelPhase::from_raw(self.shared.phase.load(Ordering::SeqCst))
    }

    /// The GUI's Cancel button. Accepted only while the job is cancellable; returns
    /// whether it was accepted.
    pub fn request_cancel(&self) -> bool {
        let accepted = self
            .shared
            .phase
            .compare_exchange(
                CANCELLABLE,
                CANCEL_REQUESTED,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok();
        if accepted {
            self.shared.flag.cancel();
        }
        accepted
    }
}

/// The job's side. The operations layer calls these through `ExecContext::progress`.
impl Progress {
    /// Reports progress. Never blocks; a closed window is ignored.
    pub fn report(&self, fraction: Option<f64>, message: impl Into<String>) {
        let fraction = fraction.map(|f| f.clamp(0.0, 1.0));
        // The receiver is gone only when the window closed; nothing to report to.
        let _ = self.sender.send(ProgressUpdate {
            fraction,
            message: message.into(),
        });
    }

    /// Ends the cancellable phase just before the first persistent change (FR-16 AC2).
    /// Fails when the operator already pressed Cancel: then the job must clean up its
    /// staged files, mark its journal entry cancelled and stop.
    pub fn begin_persistent_change(&self) -> Result<(), Cancelled> {
        loop {
            let current = self.shared.phase.load(Ordering::SeqCst);
            match current {
                CANCEL_REQUESTED => return Err(Cancelled),
                COMMITTED => return Ok(()),
                _ => {
                    if self
                        .shared
                        .phase
                        .compare_exchange(current, COMMITTED, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// True once the operator pressed Cancel.
    pub fn cancel_requested(&self) -> bool {
        self.phase() == CancelPhase::CancelRequested
    }

    /// The core cancel flag (for `crypto::generate_rsa`). Set when Cancel is accepted.
    pub fn cancel_flag(&self) -> CancelFlag {
        self.shared.flag.clone()
    }
}

/// What the progress screen shows (a pure view of the job's state).
#[derive(Debug, Clone, PartialEq)]
pub struct ProgressView {
    /// Fraction done, or `None` (pulsing bar).
    pub fraction: Option<f64>,
    /// The latest message.
    pub message: String,
    /// Cancel phase.
    pub phase: CancelPhase,
}

impl ProgressView {
    /// The view before the first message.
    pub fn new(message: impl Into<String>, phase: CancelPhase) -> Self {
        ProgressView {
            fraction: None,
            message: message.into(),
            phase,
        }
    }

    /// Applies one message.
    pub fn apply(&mut self, update: &ProgressUpdate) {
        if update.fraction.is_some() {
            self.fraction = update.fraction;
        }
        if !update.message.is_empty() {
            self.message.clone_from(&update.message);
        }
    }

    /// The Cancel button is shown and can be pressed only while the job is cancellable.
    pub fn cancel_offered(&self) -> bool {
        self.phase == CancelPhase::Cancellable
    }

    /// One sentence about cancelling, shown next to the bar (never colour alone).
    pub fn cancel_note(&self) -> Option<&'static str> {
        match self.phase {
            CancelPhase::NotCancellable => None,
            CancelPhase::Cancellable => {
                Some("You can still cancel: nothing permanent has been done yet.")
            }
            CancelPhase::CancelRequested => {
                Some("Cancelling: Keystone stops before anything permanent is done.")
            }
            CancelPhase::Committed => Some(
                "This step can no longer be cancelled. It will finish, or it can be resumed on the recovery screen.",
            ),
        }
    }
}

/// How a job ended when it did not return normally.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkerFailure {
    /// The job panicked or its thread stopped without a result.
    #[error(
        "the background task stopped unexpectedly; nothing more was done. Check the drives on the start-up checks screen before continuing"
    )]
    Stopped,
    /// The background thread could not be started.
    #[error("Keystone could not start a background task: {0}")]
    Spawn(String),
}

/// Runs `job` on a new thread. Returns the job's [`Progress`] handle (for the Cancel
/// button) and a receiver for its result.
pub fn spawn<T, F>(
    cancellable: bool,
    job: F,
) -> Result<(Progress, mpsc::Receiver<ProgressUpdate>, mpsc::Receiver<T>), WorkerFailure>
where
    T: Send + 'static,
    F: FnOnce(&Progress) -> T + Send + 'static,
{
    let (progress, updates) = Progress::new(cancellable);
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let job_progress = progress.clone();
    std::thread::Builder::new()
        .name("keystone-worker".to_string())
        .spawn(move || {
            let result = job(&job_progress);
            // The window may have closed; then nobody waits for the result.
            let _ = result_tx.send(result);
        })
        .map_err(|e| WorkerFailure::Spawn(e.to_string()))?;
    Ok((progress, updates, result_rx))
}

/// GTK glue: runs `job` off the GUI thread and calls `on_update` with the progress
/// view and `on_done` once with the result, both on the GUI thread.
pub mod gtk_glue {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::mpsc::TryRecvError;

    use gtk::glib;

    use super::{
        CancelPhase, MAX_MESSAGES_PER_POLL, POLL_INTERVAL, Progress, ProgressView, WorkerFailure,
        spawn,
    };

    /// Starts `job`; returns its progress handle (for Cancel) or a spawn failure, which
    /// is also delivered to `on_done`.
    pub fn run<T, F>(
        initial_message: &str,
        cancellable: bool,
        job: F,
        on_update: impl Fn(&ProgressView) + 'static,
        on_done: impl FnOnce(Result<T, WorkerFailure>) + 'static,
    ) -> Option<Progress>
    where
        T: Send + 'static,
        F: FnOnce(&Progress) -> T + Send + 'static,
    {
        let (progress, updates, results) = match spawn(cancellable, job) {
            Ok(parts) => parts,
            Err(failure) => {
                on_done(Err(failure));
                return None;
            }
        };
        let phase = if cancellable {
            CancelPhase::Cancellable
        } else {
            CancelPhase::NotCancellable
        };
        let view = Rc::new(RefCell::new(ProgressView::new(initial_message, phase)));
        on_update(&view.borrow());
        let mut on_done = Some(on_done);
        let poll_progress = progress.clone();
        glib::timeout_add_local(POLL_INTERVAL, move || {
            let mut changed = false;
            for _ in 0..MAX_MESSAGES_PER_POLL {
                match updates.try_recv() {
                    Ok(update) => {
                        view.borrow_mut().apply(&update);
                        changed = true;
                    }
                    Err(_) => break,
                }
            }
            let phase = poll_progress.phase();
            if view.borrow().phase != phase {
                view.borrow_mut().phase = phase;
                changed = true;
            }
            if changed {
                on_update(&view.borrow());
            }
            match results.try_recv() {
                Ok(result) => {
                    if let Some(done) = on_done.take() {
                        done(Ok(result));
                    }
                    glib::ControlFlow::Break
                }
                Err(TryRecvError::Empty) => glib::ControlFlow::Continue,
                Err(TryRecvError::Disconnected) => {
                    if let Some(done) = on_done.take() {
                        done(Err(WorkerFailure::Stopped));
                    }
                    glib::ControlFlow::Break
                }
            }
        });
        Some(progress)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr16_ac2_cancel_is_accepted_only_while_cancellable() {
        // Covers: FR-16 AC2
        let (progress, _rx) = Progress::new(true);
        assert_eq!(progress.phase(), CancelPhase::Cancellable);
        assert!(progress.request_cancel());
        assert!(progress.cancel_requested());
        assert!(progress.cancel_flag().is_cancelled());
        assert_eq!(progress.begin_persistent_change(), Err(Cancelled));
        // A second press changes nothing.
        assert!(!progress.request_cancel());
    }

    #[test]
    fn fr16_ac2_no_cancel_after_the_first_persistent_change() {
        // Covers: FR-16 AC2
        let (progress, _rx) = Progress::new(true);
        assert_eq!(progress.begin_persistent_change(), Ok(()));
        assert_eq!(progress.phase(), CancelPhase::Committed);
        assert!(!progress.request_cancel());
        assert!(!progress.cancel_flag().is_cancelled());
        // Further persistent changes are fine.
        assert_eq!(progress.begin_persistent_change(), Ok(()));
    }

    #[test]
    fn read_only_jobs_are_never_cancellable() {
        let (progress, _rx) = Progress::new(false);
        assert_eq!(progress.phase(), CancelPhase::NotCancellable);
        assert!(!progress.request_cancel());
        assert_eq!(progress.begin_persistent_change(), Ok(()));
    }

    #[test]
    fn fr16_ac2_cancel_button_follows_the_phase() {
        // Covers: FR-16 AC2, NFR-04 (state also given in words)
        let mut view = ProgressView::new("Generating the key", CancelPhase::Cancellable);
        assert!(view.cancel_offered());
        assert!(view.cancel_note().expect("note").contains("still cancel"));
        view.phase = CancelPhase::CancelRequested;
        assert!(!view.cancel_offered());
        view.phase = CancelPhase::Committed;
        assert!(!view.cancel_offered());
        assert!(
            view.cancel_note()
                .expect("note")
                .contains("can no longer be cancelled")
        );
        view.phase = CancelPhase::NotCancellable;
        assert!(view.cancel_note().is_none());
    }

    #[test]
    fn progress_view_keeps_the_last_known_values() {
        let mut view = ProgressView::new("Starting", CancelPhase::NotCancellable);
        view.apply(&ProgressUpdate {
            fraction: Some(0.25),
            message: "Writing to the primary drive".to_string(),
        });
        view.apply(&ProgressUpdate {
            fraction: None,
            message: String::new(),
        });
        assert_eq!(view.fraction, Some(0.25));
        assert_eq!(view.message, "Writing to the primary drive");
    }

    #[test]
    fn nfr03_jobs_run_off_the_calling_thread_and_report_progress() {
        // Covers: FR-16 AC1, NFR-03
        let caller = std::thread::current().id();
        let (progress, updates, result) = spawn(true, move |progress: &Progress| {
            progress.report(Some(2.0), "almost");
            std::thread::current().id()
        })
        .expect("spawn");
        let worker = result
            .recv_timeout(Duration::from_secs(10))
            .expect("result");
        assert_ne!(worker, caller);
        let update = updates
            .recv_timeout(Duration::from_secs(1))
            .expect("update");
        assert_eq!(update.fraction, Some(1.0), "fractions are clamped");
        assert_eq!(progress.phase(), CancelPhase::Cancellable);
    }

    #[test]
    fn fr16_ac2_cancel_reaches_a_running_job() {
        // Covers: FR-16 AC2
        let (progress, _updates, result) = spawn(true, |progress: &Progress| {
            let flag = progress.cancel_flag();
            let start = std::time::Instant::now();
            while !flag.is_cancelled() && start.elapsed() < Duration::from_secs(10) {
                std::thread::sleep(Duration::from_millis(5));
            }
            progress.begin_persistent_change()
        })
        .expect("spawn");
        assert!(progress.request_cancel());
        assert_eq!(
            result
                .recv_timeout(Duration::from_secs(10))
                .expect("result"),
            Err(Cancelled)
        );
    }
}
