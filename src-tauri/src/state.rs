use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use antivirus_core::Core;

/// Shared state managed by Tauri and injected into every command.
pub struct AppState {
    pub core: Core,
    pub cancel: Arc<AtomicBool>,
    pub running: Arc<AtomicBool>,
}

impl AppState {
    pub fn new(core: Core) -> Self {
        Self {
            core,
            cancel: Arc::new(AtomicBool::new(false)),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Requests cancellation and reports whether a scan was running.
    pub fn request_cancel(&self) -> bool {
        self.cancel.store(true, Ordering::SeqCst);
        self.running.load(Ordering::SeqCst)
    }
}

/// Marks a scan as running and clears the flag when the guard is dropped.
pub struct ScanActivity {
    running: Arc<AtomicBool>,
}

impl ScanActivity {
    pub fn begin(cancel: &Arc<AtomicBool>, running: &Arc<AtomicBool>) -> Self {
        cancel.store(false, Ordering::SeqCst);
        running.store(true, Ordering::SeqCst);
        Self {
            running: Arc::clone(running),
        }
    }
}

impl Drop for ScanActivity {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }
}
