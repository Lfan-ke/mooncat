// The WebSocket opening handshake (RFC 6455 §4.2).

///|
test "websocket: the Sec-WebSocket-Accept matches the RFC 6455 §1.3 example" {
  assert_eq(
    websocket_accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
    "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
  )
}

///|
test "websocket: subprotocol selection honours the client's preference order" {
  assert_eq(
    websocket_select_subprotocol(["chat", "superchat"], ["superchat", "chat"]),
    Some("chat"),
  )
  assert_eq(
    websocket_select_subprotocol(["superchat"], ["chat", "superchat"]),
    Some("superchat"),
  )
  assert_eq(websocket_select_subprotocol(["mqtt"], ["chat"]), None)
}

///|
test "websocket: the 101 response carries the accept key and the negotiated subprotocol" {
  let resp = websocket_handshake_response(
    "dGhlIHNhbXBsZSBub25jZQ==",
    Some("chat"),
    [],
  )
  assert_eq(
    resp,
    @utf8.encode(
      "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\n" +
      "Connection: Upgrade\r\n" +
      "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" +
      "Sec-WebSocket-Protocol: chat\r\n" +
      "\r\n",
    ),
  )
  // Without a negotiated subprotocol, the Sec-WebSocket-Protocol line is omitted.
  let plain = websocket_handshake_response("dGhlIHNhbXBsZSBub25jZQ==", None, [])
  assert_eq(
    plain,
    @utf8.encode(
      "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\n" +
      "Connection: Upgrade\r\n" +
      "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" +
      "\r\n",
    ),
  )
}
