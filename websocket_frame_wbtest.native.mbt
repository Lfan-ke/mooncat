// The `ws_read_message` control-frame path (RFC 6455 §5.4/§5.5) drives a real `@pipe.pipe()` writer
// for the pong and close replies, so these cases are native-only. The pure frame codec and the
// reader-only `ws_read_frame` path stay all-target in websocket_frame_wbtest.mbt.
//
// Every inbound frame here is masked, because every frame a client sends must be (§5.1).

///|
/// The masking key the client-side frames below are built with. Any four bytes will do; these are
/// the ones RFC 6455 §5.7 uses.
let test_mask : Bytes = b"\x37\xfa\x21\x3d"

///|
/// A reader over `bytes` that leaves no task blocked on a tail the test abandons: the bytes go
/// into a pipe which is then closed, where `@io.MemoryReader`'s feeder task would sit forever
/// waiting for a reader that has already failed the connection. Only for payloads that fit a
/// pipe buffer, which is every fixture here.
async fn bytes_reader(bytes : Bytes) -> @pipe.PipeRead {
  let (r, w) = @pipe.pipe()
  w.write(bytes)
  w.close()
  r
}

///|
/// Read one server → client frame, giving up rather than blocking when the server never sends it.
/// A frame that should have been written and was not has to fail the test; left unbounded it
/// wedges the whole suite instead, which is how a regression hides.
async fn expect_frame(r : @pipe.PipeRead) -> WsFrame {
  match
    @async.with_timeout_opt(3000, () => ws_read_frame(r, from_client=false)) {
    Some(f) => f
    None => fail("expected a frame from the server, none arrived")
  }
}

///|
/// The close code `ws_read_message` fails the stream with, or `0` when it returns a message.
async fn ws_message_reject(
  frames : Bytes,
  max_size? : Int = ws_max_size,
) -> Int {
  let reader = bytes_reader(frames)
  let (_pr, pw) = @pipe.pipe()
  let writer : &@io.Writer = pw
  try {
    ignore(ws_read_message(reader, writer, max_size~))
    0
  } catch {
    WsError(code, _) => code
    _ => -1
  }
}

///|
async test "ws_read_message reassembles a fragmented text message (RFC 6455 §5.4)" {
  @async.with_task_group(_g => {
    // "Hel" (text, not final) + "lo" (continuation, final).
    let f1 = ws_encode_frame(false, Text, b"Hel", mask=test_mask)
    let f2 = ws_encode_frame(true, Continuation, b"lo", mask=test_mask)
    let reader : &@io.Reader = @io.MemoryReader(async fn(w) {
      w.write(f1)
      w.write(f2)
    })
    let (_pr, pw) = @pipe.pipe()
    let writer : &@io.Writer = pw
    assert_eq(ws_read_message(reader, writer), WsText("Hello"))
  })
}

///|
async test "ws_read_message answers an interleaved ping with a pong and returns the data (§5.5)" {
  @async.with_task_group(_g => {
    // A ping, then a binary message.
    let ping = ws_encode_frame(true, Ping, b"p</>", mask=test_mask)
    let data = ws_encode_frame(true, Binary, b"\x01\x02\x03", mask=test_mask)
    let reader : &@io.Reader = @io.MemoryReader(async fn(w) {
      w.write(ping)
      w.write(data)
    })
    let (pr, pw) = @pipe.pipe()
    let writer : &@io.Writer = pw
    let msg = ws_read_message(reader, writer)
    assert_eq(msg, WsBinary(b"\x01\x02\x03"))
    // The pong was written back with the ping's payload, unmasked (server → client).
    let pong = expect_frame(pr)
    assert_eq(pong.opcode, Pong)
    assert_eq(pong.payload, b"p</>")
  })
}

///|
async test "ws_read_message decodes a close frame's code and reason (§5.5.1)" {
  @async.with_task_group(_g => {
    // Close with status 1000 (0x03e8) and reason "bye".
    let close = ws_encode_frame(
      true,
      Close,
      b"\x03\xe8\x62\x79\x65",
      mask=test_mask,
    )
    let reader : &@io.Reader = @io.MemoryReader(async fn(w) { w.write(close) })
    let (_pr, pw) = @pipe.pipe()
    let writer : &@io.Writer = pw
    assert_eq(ws_read_message(reader, writer), WsClose(1000, b"bye"))
  })
}

///|
/// §5.5.1: an endpoint that receives a close MUST send one back. Without the echo the peer waits
/// out its own close timeout on every clean shutdown instead of seeing the handshake complete.
async test "ws_read_message echoes a close frame back (§5.5.1)" {
  @async.with_task_group(_g => {
    let close = ws_encode_frame(
      true,
      Close,
      b"\x03\xe8\x62\x79\x65",
      mask=test_mask,
    )
    let reader : &@io.Reader = @io.MemoryReader(async fn(w) { w.write(close) })
    let (pr, pw) = @pipe.pipe()
    let writer : &@io.Writer = pw
    assert_eq(ws_read_message(reader, writer), WsClose(1000, b"bye"))
    // The echo carries the peer's own status code, unmasked and with no reason of its own.
    let echoed = expect_frame(pr)
    assert_eq(echoed.opcode, Close)
    assert_eq(echoed.payload, b"\x03\xe8")
  })
}

///|
/// A close that carried no status is echoed with none either: 1005 is a local sentinel for
/// "nothing was sent" and §7.4.1 forbids putting it on the wire.
async test "ws_read_message echoes a statusless close statuslessly (§5.5.1)" {
  @async.with_task_group(_g => {
    let close = ws_encode_frame(true, Close, b"", mask=test_mask)
    let reader : &@io.Reader = @io.MemoryReader(async fn(w) { w.write(close) })
    let (pr, pw) = @pipe.pipe()
    let writer : &@io.Writer = pw
    assert_eq(ws_read_message(reader, writer), WsClose(1005, b""))
    let echoed = expect_frame(pr)
    assert_eq(echoed.opcode, Close)
    assert_eq(echoed.payload, b"")
  })
}

///|
/// §8.1: a text message's payload must be valid UTF-8, and an endpoint that finds it is not fails
/// the connection with 1007. Decoding lossily instead would hand the app replacement characters
/// the peer never sent and lose the error entirely.
async test "ws_read_message fails invalid UTF-8 text with 1007 (§8.1)" {
  @async.with_task_group(_g => {
    // 0xFF is not a legal UTF-8 lead byte anywhere.
    let bad = ws_encode_frame(true, Text, b"\xff\xfe", mask=test_mask)
    assert_eq(ws_message_reject(bad), 1007)
    // The same bytes as a *binary* message are fine — §8.1 constrains text only.
    let ok = ws_encode_frame(true, Binary, b"\xff\xfe", mask=test_mask)
    assert_eq(ws_message_reject(ok), 0)
  })
}

///|
/// A message split into enough fragments passes any per-frame ceiling, so the ceiling has to
/// count the reassembled total as well.
async test "ws_read_message fails an over-long reassembled message with 1009" {
  @async.with_task_group(_g => {
    let buf = Buffer()
    // Three 4-byte fragments = 12 bytes, past a ceiling of 8, though no single frame is.
    buf.write_bytes(ws_encode_frame(false, Binary, b"aaaa", mask=test_mask))
    buf.write_bytes(
      ws_encode_frame(false, Continuation, b"bbbb", mask=test_mask),
    )
    buf.write_bytes(
      ws_encode_frame(true, Continuation, b"cccc", mask=test_mask),
    )
    assert_eq(ws_message_reject(buf.to_bytes(), max_size=8), 1009)
    // The same message under a ceiling that fits it is delivered.
    assert_eq(ws_message_reject(buf.to_bytes(), max_size=12), 0)
  })
}

///|
/// §5.1 again, this time through the whole message reader rather than the frame decoder: an
/// unmasked client frame never becomes a message.
async test "ws_read_message fails an unmasked client frame with 1002 (§5.1)" {
  @async.with_task_group(_g => {
    assert_eq(ws_message_reject(ws_encode_frame(true, Text, b"hi")), 1002)
    assert_eq(
      ws_message_reject(ws_encode_frame(true, Text, b"hi", mask=test_mask)),
      0,
    )
  })
}
