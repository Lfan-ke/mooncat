// The send side of QUIC flow control across a connection (RFC 9000 §4.1): a sender is bounded
// on each stream by two windows at once — the connection-wide limit the peer advertised with
// MAX_DATA, and that stream's limit from MAX_STREAM_DATA — and may send only the smaller of the
// two, debiting both. This composes the per-window `SendFlow` accounting into the connection
// state a sender consults before putting stream data on the wire; it holds only counters.

///|
/// The send-side flow control for a whole connection: the connection-wide window and a window
/// per stream, each created at the peer's initial maximum on first use.
pub struct QuicSendFlow {
  connection : SendFlow
  streams : Map[UInt64, SendFlow]
  initial_max_stream_data : UInt64
}

///|
/// A fresh send-flow state at the peer's initial connection and per-stream maxima.
pub fn QuicSendFlow::new(
  initial_max_data : UInt64,
  initial_max_stream_data : UInt64,
) -> QuicSendFlow {
  {
    connection: SendFlow::new(initial_max_data),
    streams: Map([]),
    initial_max_stream_data,
  }
}

///|
/// The send window for stream `id`, created at the initial per-stream maximum on first use.
fn QuicSendFlow::stream_flow(self : QuicSendFlow, id : UInt64) -> SendFlow {
  match self.streams.get(id) {
    Some(s) => s
    None => {
      let s = SendFlow::new(self.initial_max_stream_data)
      self.streams[id] = s
      s
    }
  }
}

///|
/// The bytes that may be sent on stream `id` right now: the smaller of the connection-wide and
/// the stream's available windows (RFC 9000 §4.1).
pub fn QuicSendFlow::stream_window(self : QuicSendFlow, id : UInt64) -> UInt64 {
  let c = self.connection.available()
  let s = self.stream_flow(id).available()
  if c < s {
    c
  } else {
    s
  }
}

///|
/// Account for sending `n` bytes on stream `id`, debiting both the stream and the connection
/// window. Raises if either window would be exceeded — checked before debiting, so neither is
/// left partially charged on failure (RFC 9000 §4.1).
pub fn QuicSendFlow::record_stream_sent(
  self : QuicSendFlow,
  id : UInt64,
  n : UInt64,
) -> Unit raise FlowError {
  let s = self.stream_flow(id)
  if s.available() < n {
    raise FlowError("send would exceed the stream flow-control limit")
  }
  if self.connection.available() < n {
    raise FlowError("send would exceed the connection flow-control limit")
  }
  s.record_sent(n)
  self.connection.record_sent(n)
}

///|
/// Raise the connection-wide limit from a MAX_DATA frame.
pub fn QuicSendFlow::on_max_data(self : QuicSendFlow, new_max : UInt64) -> Unit {
  self.connection.update_limit(new_max)
}

///|
/// Raise stream `id`'s limit from a MAX_STREAM_DATA frame.
pub fn QuicSendFlow::on_max_stream_data(
  self : QuicSendFlow,
  id : UInt64,
  new_max : UInt64,
) -> Unit {
  self.stream_flow(id).update_limit(new_max)
}

///|
/// The connection-wide bytes still sendable across all streams.
pub fn QuicSendFlow::connection_available(self : QuicSendFlow) -> UInt64 {
  self.connection.available()
}
