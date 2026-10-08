use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, ready},
    time::Duration,
};

use http::Response;
use pin_project_lite::pin_project;
use wreq_proto::rt::Sleep;

use super::body::TimeoutBody;
use crate::{
    error::{BoxError, Error, TimedOut},
    rt::Timer,
    tls::{CapturedChainDerError, TlsCaptureSlot},
};

pin_project! {
    /// Waits for response headers, then moves the total timeout into the response body.
    pub struct ResponseFuture<Fut> {
        #[pin]
        pub(super) fut: Fut,
        pub(super) timer: Timer,
        pub(super) tls_capture: Option<TlsCaptureSlot>,
        pub(super) read_timeout: Option<Duration>,
        pub(super) read_timeout_fut: Option<Pin<Box<dyn Sleep>>>,
        pub(super) total_timeout_fut: Option<Pin<Box<dyn Sleep>>>,
    }
}

fn timeout_error(tls_capture: Option<&TlsCaptureSlot>) -> BoxError {
    if let Some(chain) = tls_capture.and_then(TlsCaptureSlot::captured_chain_der) {
        return Error::request(CapturedChainDerError::new(
            TimedOut,
            chain.into_iter().map(|der| der.to_vec()).collect(),
        ))
        .into();
    }

    Error::request(TimedOut).into()
}

impl<Fut, ResBody, E> Future for ResponseFuture<Fut>
where
    Fut: Future<Output = Result<Response<ResBody>, E>>,
    E: Into<BoxError>,
{
    type Output = Result<Response<TimeoutBody<ResBody>>, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        // The total timer covers response headers and body. Poll it first so an
        // expired timeout wins, then move it into `TimeoutBody` below.
        if let Some(timeout) = this.total_timeout_fut.as_mut()
            && timeout.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Err(timeout_error(this.tls_capture.as_ref())));
        }

        // Before headers arrive, the read timer limits that wait. The body starts
        // and resets its own read timer after each successful frame.
        if let Some(timeout) = this.read_timeout_fut.as_mut()
            && timeout.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Err(timeout_error(this.tls_capture.as_ref())));
        }

        // Poll the request after both timers so every pending future registers the
        // current waker before `ready!` returns.
        let response = ready!(this.fut.poll(cx)).map_err(Into::into)?;

        // Moving the running total timer preserves the original deadline.
        Poll::Ready(Ok(response.map(|body| {
            TimeoutBody::new(
                body,
                this.timer.clone(),
                *this.read_timeout,
                this.total_timeout_fut.take(),
            )
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::timeout_error;
    use crate::tls::TlsCaptureSlot;

    #[test]
    fn timeout_error_includes_captured_tls_chain() {
        let capture = TlsCaptureSlot::default();
        capture.store_chain_der(vec![vec![1, 2, 3], vec![4, 5, 6]]);

        let err = timeout_error(Some(&capture));
        let err = err.downcast::<crate::Error>().expect("wreq error");
        let chain = err
            .captured_chain_der()
            .expect("captured chain")
            .map(|der| der.to_vec())
            .collect::<Vec<_>>();

        assert_eq!(chain, vec![vec![1, 2, 3], vec![4, 5, 6]]);
    }
}
