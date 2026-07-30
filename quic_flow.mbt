// QUIC flow control (RFC 9000 §4): a receiver advertises how many bytes a sender may
// transmit — per stream (MAX_STREAM_DATA) and across the connection (MAX_DATA) — and the
// sender must not exceed it. `SendFlow` tracks what we have sent against the peer's
// limit; `RecvFlow` enforces the peer stays under the limit we advertised and decides
// when to extend it. The same accounting drives both the connection-wide and per-stream
// windows; it holds only counters, so it is pure and testable.

///|
/// A flow-control violation: the peer sent past the limit we advertised (RFC 9000
/// §4.1), or our own accounting was asked to exceed the peer's limit.
pub suberror FlowError {
  FlowError(String)
}

///|
/// The send side of one flow-control window: bytes we have sent toward the peer's
/// advertised `limit`.
pub struct SendFlow {
  mut sent : UInt64
  mut limit : UInt64
}

///|
/// A send window with the peer's initial maximum.
pub fn SendFlow::new(initial_max : UInt64) -> SendFlow {
  { sent: 0, limit: initial_max }
}

///|
/// How many more bytes may be sent right now (0 when blocked).
pub fn SendFlow::available(self : SendFlow) -> UInt64 {
  if self.sent >= self.limit {
    0
  } else {
    self.limit - self.sent
  }
}

///|
/// Whether the window is exhausted (a STREAM_DATA_BLOCKED / DATA_BLOCKED condition).
pub fn SendFlow::is_blocked(self : SendFlow) -> Bool {
  self.sent >= self.limit
}

///|
/// Total bytes sent so far.
pub fn SendFlow::sent(self : SendFlow) -> UInt64 {
  self.sent
}

///|
/// Account for sending `n` bytes; raises if that would exceed the peer's limit.
pub fn SendFlow::record_sent(
  self : SendFlow,
  n : UInt64,
) -> Unit raise FlowError {
  if self.sent + n > self.limit {
    raise FlowError("send would exceed the peer's flow-control limit")
  }
  self.sent = self.sent + n
}

///|
/// Adopt a new limit from a MAX_DATA / MAX_STREAM_DATA frame; the limit only ever
/// increases (an old, smaller value is ignored — RFC 9000 §4.1).
pub fn SendFlow::update_limit(self : SendFlow, new_max : UInt64) -> Unit {
  if new_max > self.limit {
    self.limit = new_max
  }
}

///|
/// The receive side of one flow-control window: the peer may send up to the `limit` we
/// advertised; we grow it as the application consumes data, keeping `window` bytes of
/// headroom available.
pub struct RecvFlow {
  mut received : UInt64
  mut consumed : UInt64
  mut limit : UInt64
  window : UInt64
}

///|
/// A receive window of `window` bytes (the initial advertised limit).
pub fn RecvFlow::new(window : UInt64) -> RecvFlow {
  { received: 0, consumed: 0, limit: window, window }
}

///|
/// The current advertised limit.
pub fn RecvFlow::limit(self : RecvFlow) -> UInt64 {
  self.limit
}

///|
/// Record that data up to absolute byte offset `highest_offset` has arrived; raises if
/// it passes the limit we advertised (a flow-control violation).
pub fn RecvFlow::record_received(
  self : RecvFlow,
  highest_offset : UInt64,
) -> Unit raise FlowError {
  if highest_offset > self.limit {
    raise FlowError("peer exceeded the advertised flow-control limit")
  }
  if highest_offset > self.received {
    self.received = highest_offset
  }
}

///|
/// Account for the application consuming `n` more bytes, freeing window space.
pub fn RecvFlow::consume(self : RecvFlow, n : UInt64) -> Unit {
  self.consumed = self.consumed + n
}

///|
/// Whether the limit should be extended: the limit we could advertise (consumed plus a
/// full window) is at least half a window beyond the current one, so an update is worth
/// sending (RFC 9000 §4.1 auto-tuning; avoids a MAX_DATA per byte).
pub fn RecvFlow::should_extend(self : RecvFlow) -> Bool {
  let desired = self.consumed + self.window
  desired >= self.limit + self.window / 2
}

///|
/// Extend the advertised limit to `consumed + window` and return the new value — the
/// MAX_DATA / MAX_STREAM_DATA to send.
pub fn RecvFlow::extend_limit(self : RecvFlow) -> UInt64 {
  self.limit = self.consumed + self.window
  self.limit
}
