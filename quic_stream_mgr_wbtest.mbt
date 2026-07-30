// QUIC receive-side stream management (RFC 9000 §2, §4): routing STREAM frames to
// per-stream reassembly, independence across streams, per-stream and connection-level
// flow-control enforcement, and connection MAX_DATA auto-tuning.

///|
test "stream mgr: a stream delivers contiguous data, reordering fragments" {
  let m = StreamManager::new(100, 100)
  assert_eq(m.on_stream_frame(0, 3, b"def", false), b"") // gap before it
  assert_eq(m.on_stream_frame(0, 0, b"abc", false), b"abcdef")
  assert_eq(m.stream_count(), 1)
}

///|
test "stream mgr: streams are independent" {
  let m = StreamManager::new(100, 100)
  assert_eq(m.on_stream_frame(0, 0, b"hello", false), b"hello")
  assert_eq(m.on_stream_frame(4, 0, b"world", false), b"world")
  assert_eq(m.stream_count(), 2)
  // A later fragment on stream 0 continues its own sequence.
  assert_eq(m.on_stream_frame(0, 5, b"!", false), b"!")
}

///|
test "stream mgr: per-stream flow control rejects data past the window" {
  let m = StreamManager::new(100, 10)
  let violation = try {
    // Offset 8 + 4 bytes = 12, past the 10-byte per-stream window.
    let _ = m.on_stream_frame(0, 8, b"abcd", false)
    false
  } catch {
    _ => true
  }
  assert_eq(violation, true)
}

///|
test "stream mgr: connection flow control sums across streams" {
  // 10 bytes of connection credit, generous per-stream windows.
  let m = StreamManager::new(10, 100)
  let _ = m.on_stream_frame(0, 0, b"abcdef", false) // 6 bytes, ok
  let violation = try {
    let _ = m.on_stream_frame(4, 0, b"ghijkl", false) // +6 = 12 > 10
    false
  } catch {
    _ => true
  }
  assert_eq(violation, true)
}

///|
test "stream mgr: connection MAX_DATA extends as data is consumed" {
  let m = StreamManager::new(10, 100)
  // Receive and deliver 6 bytes; the read consumes them against the connection window.
  assert_eq(m.on_stream_frame(0, 0, b"abcdef", false), b"abcdef")
  // Consumed 6 of a 10-byte window: the advertisable limit (6 + 10) is half a window
  // past the current 10, so an update is due.
  assert_eq(m.connection_max_data_update(), Some(16))
  // Immediately after, no further update is due.
  assert_eq(m.connection_max_data_update(), None)
}

///|
test "stream mgr: reading an unknown stream yields nothing" {
  let m = StreamManager::new(100, 100)
  assert_eq(m.read(9), b"")
}
