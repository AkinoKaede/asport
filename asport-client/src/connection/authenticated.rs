use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;

struct AuthenticatedInner {
    port: AtomicCell<Option<u16>>,
    broadcast: Mutex<Vec<Waker>>,
}

#[derive(Clone)]
pub struct Authenticated(Arc<AuthenticatedInner>);

impl Authenticated {
    pub fn new() -> Self {
        Self(Arc::new(AuthenticatedInner {
            port: AtomicCell::new(None),
            broadcast: Mutex::new(Vec::new()),
        }))
    }

    pub fn set(&self, port: u16) {
        self.0.port.store(Some(port));

        for waker in self.0.broadcast.lock().drain(..) {
            waker.wake();
        }
    }

    pub fn get(&self) -> Option<u16> {
        self.0.port.load()
    }
}

impl Future for Authenticated {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.get().is_some() {
            Poll::Ready(())
        } else {
            self.0.broadcast.lock().push(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl Display for Authenticated {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        if let Some(port) = self.get() {
            write!(f, "{port}")
        } else {
            write!(f, "unauthenticated")
        }
    }
}
