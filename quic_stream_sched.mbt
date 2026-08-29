// The send-side stream scheduler (RFC 9000 §2, §4): a connection multiplexes many streams over
// one packet flow, so a sender must decide, each turn, which stream sends how many bytes at
// what offset. This schedules that round-robin across the streams with data queued, bounding
// every frame by the send flow control (`QuicSendFlow`) — the smaller of the connection and
// stream windows — and a maximum frame size, and rides the FIN on the frame that drains a
// stream (or a FIN-only frame when the stream closes with no data left). It yields scheduling
// decisions; copying the bytes onto the wire is the caller's trivial step.

///|
/// A stream's queued output: bytes still to frame, the next offset to send from, and whether a
/// FIN is queued and has been emitted.
pub(all) struct StreamOut {
  mut pending : UInt64
  mut offset : UInt64
  mut fin_queued : Bool
  mut fin_sent : Bool
}

///|
/// A scheduling decision: send `length` bytes on `stream` at `offset`, ending the stream when
/// `fin`.
pub(all) struct StreamSend {
  stream : UInt64
  offset : UInt64
  length : UInt64
  fin : Bool
}

///|
/// A round-robin send scheduler over a connection's streams, bounded by `flow` and a maximum
/// per-frame payload.
pub struct QuicStreamScheduler {
  flow : QuicSendFlow
  streams : Map[UInt64, StreamOut]
  order : Array[UInt64]
  mut cursor : Int
  max_frame : UInt64
}

///|
/// A fresh scheduler over `flow` with frames capped at `max_frame` bytes.
pub fn QuicStreamScheduler::new(
  flow : QuicSendFlow,
  max_frame : UInt64,
) -> QuicStreamScheduler {
  { flow, streams: Map([]), order: [], cursor: 0, max_frame, }
}

///|
fn QuicStreamScheduler::ensure(
  self : QuicStreamScheduler,
  id : UInt64,
) -> StreamOut {
  match self.streams.get(id) {
    Some(o) => o
    None => {
      let o = { pending: 0, offset: 0, fin_queued: false, fin_sent: false, }
      self.streams[id] = o
      self.order.push(id)
      o
    }
  }
}

///|
/// Queue `n` more bytes of application data to send on stream `id`.
pub fn QuicStreamScheduler::queue(
  self : QuicStreamScheduler,
  id : UInt64,
  n : UInt64,
) -> Unit {
  let out = self.ensure(id)
  out.pending = out.pending + n
}

///|
/// Mark stream `id` finished: a FIN will ride the frame that drains it, or a FIN-only frame.
pub fn QuicStreamScheduler::queue_fin(
  self : QuicStreamScheduler,
  id : UInt64,
) -> Unit {
  let out = self.ensure(id)
  out.fin_queued = true
}

///|
/// Raise the connection-wide send limit from a MAX_DATA frame.
pub fn QuicStreamScheduler::on_max_data(
  self : QuicStreamScheduler,
  new_max : UInt64,
) -> Unit {
  self.flow.on_max_data(new_max)
}

///|
/// Raise stream `id`'s send limit from a MAX_STREAM_DATA frame.
pub fn QuicStreamScheduler::on_max_stream_data(
  self : QuicStreamScheduler,
  id : UInt64,
  new_max : UInt64,
) -> Unit {
  self.flow.on_max_stream_data(id, new_max)
}

///|
fn sched_min(a : UInt64, b : UInt64) -> UInt64 {
  if a < b {
    a
  } else {
    b
  }
}

///|
/// The next scheduling decision, or `None` when no stream can send (all drained or flow-control
/// blocked). Round-robins fairly across the streams and debits the flow control for the bytes
/// scheduled. Raises only on a flow-control accounting error, which the bounds here preclude.
pub fn QuicStreamScheduler::next(
  self : QuicStreamScheduler,
) -> StreamSend? raise FlowError {
  let n = self.order.length()
  if n == 0 {
    return None
  }
  for k = 0; k < n; k = k + 1 {
    let idx = (self.cursor + k) % n
    let id = self.order[idx]
    let out = match self.streams.get(id) {
      Some(o) => o
      None => abort("scheduler order and streams out of sync")
    }
    let window = self.flow.stream_window(id)
    let send_n = sched_min(sched_min(out.pending, window), self.max_frame)
    if send_n > 0UL {
      let is_last = send_n == out.pending &&
        out.fin_queued &&
        out.fin_sent == false
      self.flow.record_stream_sent(id, send_n)
      let decision = {
        stream: id,
        offset: out.offset,
        length: send_n,
        fin: is_last,
      }
      out.offset = out.offset + send_n
      out.pending = out.pending - send_n
      if is_last {
        out.fin_sent = true
      }
      self.cursor = (idx + 1) % n
      return Some(decision)
    }
    if out.pending == 0UL && out.fin_queued && out.fin_sent == false {
      out.fin_sent = true
      self.cursor = (idx + 1) % n
      return Some({ stream: id, offset: out.offset, length: 0UL, fin: true, })
    }
  }
  None
}
