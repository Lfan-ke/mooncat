// The send-side stream scheduler (RFC 9000 §2, §4): round-robin multiplexing bounded by flow
// control, with FIN handling.

///|
fn next_send(sch : QuicStreamScheduler) -> StreamSend raise {
  match sch.next() {
    Some(d) => d
    None => abort("expected a scheduling decision")
  }
}

///|
test "scheduler: round-robins streams and caps each frame by the max frame size" {
  let sch = QuicStreamScheduler::new(QuicSendFlow::new(1000UL, 1000UL), 300UL)
  sch.queue(0UL, 500UL)
  sch.queue(4UL, 500UL)
  // Stream 0 first, capped at the 300-byte frame size.
  let d0 = next_send(sch)
  assert_eq(d0.stream, 0UL)
  assert_eq(d0.offset, 0UL)
  assert_eq(d0.length, 300UL)
  assert_eq(d0.fin, false)
  // Round-robin to stream 4.
  let d1 = next_send(sch)
  assert_eq(d1.stream, 4UL)
  assert_eq(d1.offset, 0UL)
  assert_eq(d1.length, 300UL)
  // Back to stream 0 for the remaining 200.
  let d2 = next_send(sch)
  assert_eq(d2.stream, 0UL)
  assert_eq(d2.offset, 300UL)
  assert_eq(d2.length, 200UL)
  // Stream 4's remaining 200 — the connection window (1000) is now exactly spent.
  let d3 = next_send(sch)
  assert_eq(d3.stream, 4UL)
  assert_eq(d3.offset, 300UL)
  assert_eq(d3.length, 200UL)
  // Nothing left to schedule.
  match sch.next() {
    None => ()
    Some(_) => abort("expected no more frames")
  }
}

///|
test "scheduler: a frame is bounded by the connection window, freed by MAX_DATA" {
  // Connection window 400, generous per-stream window, one stream with 1000 bytes.
  let sch = QuicStreamScheduler::new(QuicSendFlow::new(400UL, 5000UL), 5000UL)
  sch.queue(0UL, 1000UL)
  let d = next_send(sch)
  assert_eq(d.length, 400UL) // capped by the connection window, not the 1000 pending
  // The connection window is now exhausted: nothing more until MAX_DATA.
  match sch.next() {
    None => ()
    Some(_) => abort("connection window should be blocked")
  }
  // A MAX_DATA frame frees the window and the remaining 600 bytes flow.
  sch.on_max_data(1000UL)
  let d2 = next_send(sch)
  assert_eq(d2.offset, 400UL)
  assert_eq(d2.length, 600UL)
}

///|
test "scheduler: FIN rides the draining frame, or a FIN-only frame when empty" {
  let sch = QuicStreamScheduler::new(QuicSendFlow::new(1000UL, 1000UL), 1000UL)
  sch.queue(0UL, 100UL)
  sch.queue_fin(0UL)
  let d = next_send(sch)
  assert_eq(d.stream, 0UL)
  assert_eq(d.length, 100UL)
  assert_eq(d.fin, true) // rides the last data
  match sch.next() {
    None => ()
    Some(_) => abort("FIN already sent")
  }
  // A stream that closes with no data: a FIN-only frame.
  sch.queue_fin(4UL)
  let f = next_send(sch)
  assert_eq(f.stream, 4UL)
  assert_eq(f.offset, 0UL)
  assert_eq(f.length, 0UL)
  assert_eq(f.fin, true)
}
