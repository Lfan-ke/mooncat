// The raw-stream WebSocket bridge (`serve_websocket_raw`) driven end to end by a real moonasgi app.

///|
/// A minimal ASGI WebSocket echo app: accept with the `chat` subprotocol, then echo every text /
/// binary message back until the peer disconnects.
async fn ws_raw_echo_app(
  scope : @moonasgi.Scope,
  receive : @moonasgi.Receive,
  send : @moonasgi.Send,
) -> Unit {
  guard scope is WebSocket(_) else { return }
  for ;; {
    match receive() {
      WebSocketConnect =>
        send(
          @moonasgi.Event::WebSocketAccept(subprotocol=Some("chat"), headers=[]),
        )
      WebSocketReceive(text~, bytes~) =>
        match text {
          Some(t) => send(@moonasgi.Event::WebSocketSendText(t))
          None =>
            match bytes {
              Some(b) => send(@moonasgi.Event::WebSocketSendBytes(b))
              None => ()
            }
        }
      WebSocketDisconnect(..) => break
      _ => ()
    }
  }
}

///|
/// The RFC 6455 §1.3 handshake request headers (key `dGhlIHNhbXBsZSBub25jZQ==`), offering the
/// `chat` and `superchat` subprotocols.
fn ws_upgrade_request() -> Http1Request {
  {
    http_method: "GET",
    target: "/chat",
    version: "HTTP/1.1",
    headers: Map([
      ("upgrade", "websocket"),
      ("connection", "Upgrade"),
      ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
      ("sec-websocket-version", "13"),
      ("sec-websocket-protocol", "chat, superchat"),
    ]),
    content_length: 0,
    chunked: false,
    expect_continue: false,
  }
}

///|
async test "serve_websocket_raw completes the handshake with a subprotocol echo and echoes a message" {
  @async.with_task_group(g => {
    // Inbound: a masked client text "hi", then a masked close.
    let mask = b"\x01\x02\x03\x04"
    let text = ws_encode_frame(true, Text, b"hi", mask~)
    let close = ws_encode_frame(true, Close, ws_close_payload(1000, ""), mask~)
    let reader : &@io.Reader = @io.MemoryReader(async fn(w) {
      w.write(text)
      w.write(close)
    })
    let (pr, pw) = @pipe.pipe()
    let writer : &@io.Writer = pw
    let _ = g.spawn(() => {
      serve_websocket_raw(ws_raw_echo_app, ws_upgrade_request(), reader, writer)
    })
    // The 101 response carries the RFC 6455 §1.3 accept key and the negotiated subprotocol.
    let resp = pr.read_until("\r\n\r\n").unwrap_or("")
    assert_eq(resp.contains("101 Switching Protocols"), true)
    assert_eq(
      resp.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
      true,
    )
    assert_eq(resp.contains("Sec-WebSocket-Protocol: chat"), true)
    // The server echoed "hi" back as an unmasked text frame.
    let echoed = ws_read_frame(pr)
    assert_eq(echoed.opcode, Text)
    assert_eq(echoed.payload, b"hi")
  })
}
