// Connection-wide send-side flow control (RFC 9000 §4.1).

///|
test "send flow: a stream is bounded by the smaller of its window and the connection window" {
  let f = QuicSendFlow::new(1000UL, 600UL)
  // Stream 0: min(connection 1000, stream 600) = 600.
  assert_eq(f.stream_window(0UL), 600UL)
  f.record_stream_sent(0UL, 400UL) // stream 200 left, connection 600 left
  assert_eq(f.stream_window(0UL), 200UL)
  // A fresh stream 4: its own window is 600, but the connection has 600 left → 600.
  assert_eq(f.stream_window(4UL), 600UL)
  f.record_stream_sent(4UL, 500UL) // connection 100 left, stream 4 100 left
  assert_eq(f.connection_available(), 100UL)
  assert_eq(f.stream_window(4UL), 100UL)
  // Stream 0 is now bounded by the connection window (100), not its own (200).
  assert_eq(f.stream_window(0UL), 100UL)
}

///|
test "send flow: exceeding either window raises" {
  // Over the stream's own limit.
  let f = QuicSendFlow::new(1000UL, 300UL)
  let stream_over = try {
    f.record_stream_sent(0UL, 400UL)
    false
  } catch {
    _ => true
  }
  assert_eq(stream_over, true)
  // Within the stream but over the connection limit.
  let g = QuicSendFlow::new(100UL, 1000UL)
  let conn_over = try {
    g.record_stream_sent(0UL, 200UL)
    false
  } catch {
    _ => true
  }
  assert_eq(conn_over, true)
}

///|
test "send flow: MAX_DATA and MAX_STREAM_DATA raise the limits" {
  let f = QuicSendFlow::new(500UL, 500UL)
  f.record_stream_sent(0UL, 500UL) // both windows exhausted
  assert_eq(f.stream_window(0UL), 0UL)
  f.on_max_data(1200UL) // connection 500 → 1200
  f.on_max_stream_data(0UL, 900UL) // stream 0 500 → 900
  // stream available 400, connection available 700 → 400.
  assert_eq(f.stream_window(0UL), 400UL)
  f.record_stream_sent(0UL, 400UL)
  assert_eq(f.stream_window(0UL), 0UL)
}
