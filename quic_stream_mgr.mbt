// QUIC receive-side stream management (RFC 9000 §2, §4). A STREAM frame names a stream
// by id and carries a fragment; the manager routes it to that stream's reassembler,
// enforces the per-stream and connection-wide flow-control limits, and hands back the
// contiguous bytes now deliverable to the application. Connection flow control counts
// the sum of the highest offset received on every stream (RFC 9000 §4.1), so a fragment
// that advances one stream's high-water mark consumes that much connection credit. This
// composes the stream primitives — reassembly, flow control, ids — into the routing the
// connection drives; it is pure and synchronous.

///|
/// One receive stream: its reassembly buffer, per-stream flow window, and highest byte
/// offset seen (used to charge connection-level flow control incrementally).
struct RecvStream {
  reassembler : StreamReassembler
  flow : RecvFlow
  mut highest : UInt64
}

///|
/// The set of receive streams plus the connection-level receive window.
pub struct StreamManager {
  streams : Map[UInt64, RecvStream]
  conn_flow : RecvFlow
  mut conn_bytes : UInt64
  stream_window : UInt64
}

///|
/// A manager advertising `conn_window` of connection-level credit and `stream_window`
/// per stream.
pub fn StreamManager::new(
  conn_window : UInt64,
  stream_window : UInt64,
) -> StreamManager {
  {
    streams: Map([]),
    conn_flow: RecvFlow::new(conn_window),
    conn_bytes: 0,
    stream_window,
  }
}

///|
/// The receive stream for `id`, creating it (with a fresh per-stream window) on first
/// reference.
fn StreamManager::get_or_create(
  self : StreamManager,
  id : UInt64,
) -> RecvStream {
  match self.streams.get(id) {
    Some(s) => s
    None => {
      let s = {
        reassembler: StreamReassembler::new(),
        flow: RecvFlow::new(self.stream_window),
        highest: 0,
      }
      self.streams[id] = s
      s
    }
  }
}

///|
/// Route a STREAM frame for `id` carrying `data` at `offset` (with `fin` on the last
/// fragment): enforce the stream and connection flow-control limits, reassemble, and
/// return the contiguous bytes now deliverable, charging that read against both windows.
pub fn StreamManager::on_stream_frame(
  self : StreamManager,
  id : UInt64,
  offset : UInt64,
  data : Bytes,
  fin : Bool,
) -> Bytes raise {
  let s = self.get_or_create(id)
  let new_high = offset + data.length().to_uint64()
  // Per-stream flow control: the peer must stay under the window we advertised.
  s.flow.record_received(new_high)
  // Connection flow control: charge only the growth of this stream's high-water mark.
  if new_high > s.highest {
    self.conn_bytes = self.conn_bytes + (new_high - s.highest)
    s.highest = new_high
  }
  self.conn_flow.record_received(self.conn_bytes)
  s.reassembler.insert(offset, data, fin)
  let delivered = s.reassembler.read()
  let n = delivered.length().to_uint64()
  if n > 0 {
    s.flow.consume(n)
    self.conn_flow.consume(n)
  }
  delivered
}

///|
/// Deliver any further contiguous bytes now readable on `id` (empty if the stream is
/// unknown or nothing new is contiguous), charging them against both windows.
pub fn StreamManager::read(self : StreamManager, id : UInt64) -> Bytes {
  match self.streams.get(id) {
    Some(s) => {
      let delivered = s.reassembler.read()
      let n = delivered.length().to_uint64()
      if n > 0 {
        s.flow.consume(n)
        self.conn_flow.consume(n)
      }
      delivered
    }
    None => b""
  }
}

///|
/// The number of streams currently tracked.
pub fn StreamManager::stream_count(self : StreamManager) -> Int {
  self.streams.length()
}

///|
/// Whether the connection-level receive limit should be extended, and the new MAX_DATA
/// value to advertise (RFC 9000 §4.1). Call `extend` counterpart on the returned flow if
/// non-`None`.
pub fn StreamManager::connection_max_data_update(
  self : StreamManager,
) -> UInt64? {
  if self.conn_flow.should_extend() {
    Some(self.conn_flow.extend_limit())
  } else {
    None
  }
}
