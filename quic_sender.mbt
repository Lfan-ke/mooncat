// The QUIC send loop, assembled (RFC 9000 §13, RFC 9002): the deterministic core a connection
// drives to put stream data on the wire and recover from loss. It composes the stream scheduler
// (which stream sends how much, bounded by flow control), the loss-recovery state (RTT,
// congestion window, loss detection), and a record of which STREAM data each packet carried.
// `poll_send` yields the next packet — a retransmission first, else freshly scheduled data —
// charging the congestion window; `on_ack` clears acknowledged packets and re-queues the stream
// data of any the ACK reveals as lost. The async UDP transport is the thin glue over this: send
// what `poll_send` returns, feed received ACKs to `on_ack`.

///|
/// A connection's send state for one packet-number space.
pub struct QuicSender {
  sched : QuicStreamScheduler
  recovery : QuicRecovery
  data : Map[UInt64, Bytes]
  in_packet : Map[Int64, Array[StreamSend]]
  retransmit : Array[StreamSend]
  mut next_pn : Int64
}

///|
/// A fresh sender: `initial_max_data`/`initial_max_stream_data` are the peer's advertised flow
/// limits, `max_datagram_size` sizes the congestion window, `max_ack_delay`/`granularity` tune
/// the timers (microseconds), and `max_frame` caps a STREAM frame's payload.
pub fn QuicSender::new(
  initial_max_data : UInt64,
  initial_max_stream_data : UInt64,
  max_datagram_size : Int64,
  max_ack_delay : Int64,
  granularity : Int64,
  max_frame : UInt64,
) -> QuicSender {
  {
    sched: QuicStreamScheduler::new(
      QuicSendFlow::new(initial_max_data, initial_max_stream_data),
      max_frame,
    ),
    recovery: QuicRecovery::new(max_datagram_size, max_ack_delay, granularity),
    data: Map([]),
    in_packet: Map([]),
    retransmit: [],
    next_pn: 0L,
  }
}

///|
/// Queue `bytes` of application data to send on stream `id`.
pub fn QuicSender::queue_stream(
  self : QuicSender,
  id : UInt64,
  bytes : Bytes,
) -> Unit {
  self.data[id] = bytes
  self.sched.queue(id, bytes.length().to_uint64())
}

///|
/// Mark stream `id` finished.
pub fn QuicSender::queue_fin(self : QuicSender, id : UInt64) -> Unit {
  self.sched.queue_fin(id)
}

///|
/// Raise the connection-wide send limit from a received MAX_DATA frame.
pub fn QuicSender::on_max_data(self : QuicSender, new_max : UInt64) -> Unit {
  self.sched.on_max_data(new_max)
}

///|
fn QuicSender::materialize(self : QuicSender, send : StreamSend) -> QuicFrame {
  let full = match self.data.get(send.stream) {
    Some(b) => b
    None => b""
  }
  let off = send.offset.to_int()
  let len = send.length.to_int()
  Stream(
    id=send.stream,
    offset=send.offset,
    fin=send.fin,
    data=full[off:off + len].to_owned(),
  )
}

///|
/// The next packet to send at `now`, or `None` when the congestion window is closed or nothing
/// is queued (RFC 9002 §7). Retransmissions go first, then freshly scheduled stream data; the
/// packet is recorded in the recovery state and its stream sends remembered for retransmission.
pub fn QuicSender::poll_send(
  self : QuicSender,
  now : Int64,
) -> (Int64, Array[QuicFrame])? raise {
  if self.recovery.can_send(1L) {
    let send = match self.retransmit.pop() {
      Some(x) => Some(x)
      None => self.sched.next()
    }
    match send {
      None => None
      Some(s) => {
        let pn = self.next_pn
        self.next_pn = self.next_pn + 1L
        let frame = self.materialize(s)
        self.recovery.on_packet_sent(pn, now, s.length.reinterpret_as_int64())
        self.in_packet[pn] = [s]
        Some((pn, [frame]))
      }
    }
  } else {
    None
  }
}

///|
/// Process a received ACK `frame` at `now`: clear acknowledged packets from the recovery state
/// and re-queue the stream data of any packet the ACK reveals as lost, to be retransmitted by a
/// later `poll_send` (RFC 9002 §6). Raises on a malformed ACK.
pub fn QuicSender::on_ack(
  self : QuicSender,
  frame : QuicFrame,
  now : Int64,
) -> Unit raise {
  let lost = self.recovery.on_ack_received(frame, now, 0L)
  for pn in lost {
    match self.in_packet.get(pn) {
      Some(sends) =>
        for s in sends {
          self.retransmit.push(s)
        }
      None => ()
    }
  }
}

///|
/// Handle the probe timeout firing at `now` (RFC 9002 §6.2.4). If the PTO deadline has passed with
/// packets still outstanding, re-queue the oldest outstanding packet's stream data as a probe — a
/// later `poll_send` puts it back on the wire — and back off the timer for the next arming. Unlike
/// loss detection, this neither declares packets lost nor reduces the congestion window. Returns
/// whether a probe was armed.
pub fn QuicSender::on_pto_timeout(self : QuicSender, now : Int64) -> Bool {
  guard self.recovery.pto_deadline() is Some(deadline) else { return false }
  guard now >= deadline else { return false }
  let out = self.recovery.outstanding()
  guard out.length() > 0 else { return false }
  let mut oldest = out[0]
  for pn in out {
    if pn < oldest {
      oldest = pn
    }
  }
  match self.in_packet.get(oldest) {
    Some(sends) =>
      for s in sends {
        self.retransmit.push(s)
      }
    None => ()
  }
  self.recovery.on_pto()
  true
}

///|
/// The packet numbers still outstanding (sent, not yet acknowledged or declared lost).
pub fn QuicSender::outstanding(self : QuicSender) -> Array[Int64] {
  self.recovery.outstanding()
}

///|
/// The current congestion window (bytes).
pub fn QuicSender::window(self : QuicSender) -> Int64 {
  self.recovery.window()
}
