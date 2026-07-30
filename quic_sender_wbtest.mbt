// The assembled QUIC send loop (RFC 9000 §13, RFC 9002): scheduling, congestion control, and
// loss-driven retransmission, deterministic.

///|
fn sender_poll(s : QuicSender, now : Int64) -> (Int64, Array[QuicFrame]) raise {
  match s.poll_send(now) {
    Some(p) => p
    None => abort("expected a packet to send")
  }
}

///|
test "sender: schedules queued stream data into packets and an ACK clears them" {
  let s = QuicSender::new(100000UL, 100000UL, 1200L, 25000L, 1000L, 8UL)
  s.queue_stream(0UL, b"abcdefghij") // 10 bytes, max frame 8 → 8 then 2
  s.queue_fin(0UL)
  let (pn0, f0) = sender_poll(s, 0L)
  assert_eq(pn0, 0L)
  match f0[0] {
    Stream(id~, offset~, fin~, data~) => {
      assert_eq(id, 0UL)
      assert_eq(offset, 0UL)
      assert_eq(fin, false)
      assert_eq(data, b"abcdefgh")
    }
    _ => abort("expected a STREAM frame")
  }
  let (pn1, f1) = sender_poll(s, 1L)
  assert_eq(pn1, 1L)
  match f1[0] {
    Stream(offset~, fin~, data~, ..) => {
      assert_eq(offset, 8UL)
      assert_eq(fin, true) // FIN rides the draining frame
      assert_eq(data, b"ij")
    }
    _ => abort("expected a STREAM frame")
  }
  // Nothing more to send.
  match s.poll_send(2L) {
    None => ()
    Some(_) => abort("expected the streams drained")
  }
  // An ACK for packets 0 and 1 clears the outstanding set.
  let ack : QuicFrame = Ack(largest=1UL, delay=0UL, first_range=1UL, ranges=[])
  s.on_ack(ack, 10L)
  assert_eq(s.outstanding(), [])
}

///|
test "sender: a probe timeout re-queues the oldest outstanding packet's data" {
  let s = QuicSender::new(100000UL, 100000UL, 1200L, 25000L, 1000L, 8UL)
  s.queue_stream(0UL, b"0123") // 4 bytes → one packet
  let (pn0, _) = sender_poll(s, 0L)
  assert_eq(pn0, 0L)
  // Nothing new is queued before the timeout fires.
  match s.poll_send(1L) {
    None => ()
    Some(_) => abort("expected nothing queued before the probe timeout")
  }
  // The probe timer is armed; firing it before the deadline is a no-op.
  guard s.recovery.pto_deadline() is Some(deadline) else {
    abort("expected the probe timer armed")
  }
  assert_eq(s.on_pto_timeout(deadline - 1L), false)
  assert_eq(s.recovery.pto_count(), 0)
  // At the deadline the oldest outstanding packet's data is re-queued and the timer backs off.
  assert_eq(s.on_pto_timeout(deadline), true)
  assert_eq(s.recovery.pto_count(), 1)
  // A later poll_send puts the probe on the wire as a new packet carrying the same stream data.
  let (pn1, f1) = sender_poll(s, deadline + 1L)
  assert_eq(pn1, 1L)
  match f1[0] {
    Stream(id~, offset~, data~, ..) => {
      assert_eq(id, 0UL)
      assert_eq(offset, 0UL)
      assert_eq(data, b"0123")
    }
    _ => abort("expected the probe to carry the stream data")
  }
  // A probe does not clear the original: both packets are now outstanding.
  assert_eq(s.outstanding().length(), 2)
}

///|
test "sender: a lost packet's stream data is re-queued and retransmitted" {
  let s = QuicSender::new(100000UL, 100000UL, 1200L, 25000L, 1000L, 4UL)
  s.queue_stream(0UL, b"0123456789abcdefghij") // 20 bytes, max frame 4 → five packets 0..4
  for i = 0; i < 5; i = i + 1 {
    let _ = sender_poll(s, i.to_int64())
  }
  assert_eq(s.outstanding().length(), 5)
  // Acknowledge only [2,4]; 0 and 1 are three-plus before the largest → lost, and re-queued.
  let ack : QuicFrame = Ack(largest=4UL, delay=0UL, first_range=2UL, ranges=[])
  s.on_ack(ack, 10L)
  assert_eq(s.outstanding(), [])
  // The next packet retransmits a lost chunk (offset 4, the "4567" bytes) as a new packet.
  let (pn5, f5) = sender_poll(s, 20L)
  assert_eq(pn5, 5L)
  match f5[0] {
    Stream(id~, offset~, data~, ..) => {
      assert_eq(id, 0UL)
      assert_eq(offset, 4UL)
      assert_eq(data, b"4567")
    }
    _ => abort("expected a retransmitted STREAM frame")
  }
  // The other lost chunk (offset 0) retransmits next.
  let (pn6, f6) = sender_poll(s, 21L)
  assert_eq(pn6, 6L)
  match f6[0] {
    Stream(offset~, data~, ..) => {
      assert_eq(offset, 0UL)
      assert_eq(data, b"0123")
    }
    _ => abort("expected a retransmitted STREAM frame")
  }
}
