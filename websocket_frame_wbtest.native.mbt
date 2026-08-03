// The `ws_read_message` control-frame path (RFC 6455 §5.4/§5.5) drives a real `@pipe.pipe()` writer
// for the pong reply, so these cases are native-only. The pure frame codec and the reader-only
// `ws_read_frame` path stay all-target in websocket_frame_wbtest.mbt.

///|
async test "ws_read_message reassembles a fragmented text message (RFC 6455 §5.4)" {
  @async.with_task_group(_g => {
    // "Hel" (text, not final) + "lo" (continuation, final).
    let f1 = ws_encode_frame(false, Text, b"Hel")
    let f2 = ws_encode_frame(true, Continuation, b"lo")
    let reader : &@io.Reader = @io.MemoryReader(async fn(w) {
      w.write(f1)
      w.write(f2)
    })
    let (_pr, pw) = @pipe.pipe()
    let writer : &@io.Writer = pw
    assert_eq(ws_read_message(reader, writer), WsText(b"Hello"))
  })
}

///|
async test "ws_read_message answers an interleaved ping with a pong and returns the data (§5.5)" {
  @async.with_task_group(_g => {
    // A ping, then a binary message.
    let ping = ws_encode_frame(true, Ping, b"p</>")
    let data = ws_encode_frame(true, Binary, b"\x01\x02\x03")
    let reader : &@io.Reader = @io.MemoryReader(async fn(w) {
      w.write(ping)
      w.write(data)
    })
    let (pr, pw) = @pipe.pipe()
    let writer : &@io.Writer = pw
    let msg = ws_read_message(reader, writer)
    assert_eq(msg, WsBinary(b"\x01\x02\x03"))
    // The pong was written back with the ping's payload, unmasked (server → client).
    let pong = ws_read_frame(pr)
    assert_eq(pong.opcode, Pong)
    assert_eq(pong.payload, b"p</>")
  })
}

///|
async test "ws_read_message decodes a close frame's code and reason (§5.5.1)" {
  @async.with_task_group(_g => {
    // Close with status 1000 (0x03e8) and reason "bye".
    let close = ws_encode_frame(true, Close, b"\x03\xe8\x62\x79\x65")
    let reader : &@io.Reader = @io.MemoryReader(async fn(w) { w.write(close) })
    let (_pr, pw) = @pipe.pipe()
    let writer : &@io.Writer = pw
    assert_eq(ws_read_message(reader, writer), WsClose(1000, b"bye"))
  })
}
