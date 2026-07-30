// The HTTP/3 connection setup and unidirectional-stream demultiplexer (RFC 9114 §6.2).

///|
test "http3 conn: the peer control stream establishes its SETTINGS" {
  let conn = Http3Conn::new(
    ServerSide,
    Http3Settings::new(4096UL, 16384UL, 100UL),
  )
  assert_eq(conn.settings_established(), false)
  let peer = Http3Settings::new(8192UL, 65536UL, 32UL)
  let event = conn.accept_uni_stream(
    http3_encode_control_stream(peer.to_pairs()),
  )
  assert_eq(event, ControlEstablished(peer))
  assert_eq(conn.settings_established(), true)
  assert_eq(conn.peer_settings(), Some(peer))
}

///|
test "http3 conn: our own control stream round-trips our settings" {
  let mine = Http3Settings::new(4096UL, 16384UL, 100UL)
  let conn = Http3Conn::new(ClientSide, mine)
  let peer = Http3Conn::new(ServerSide, Http3Settings::new(0UL, 0UL, 0UL))
  assert_eq(
    peer.accept_uni_stream(conn.open_control_stream()),
    ControlEstablished(mine),
  )
}

///|
test "http3 conn: a second control stream is a connection error" {
  let conn = Http3Conn::new(
    ServerSide,
    Http3Settings::new(4096UL, 16384UL, 100UL),
  )
  let ctrl = http3_encode_control_stream(
    Http3Settings::new(1UL, 2UL, 3UL).to_pairs(),
  )
  conn.accept_uni_stream(ctrl) |> ignore
  let failed = try {
    conn.accept_uni_stream(ctrl) |> ignore
    false
  } catch {
    _ => true
  }
  assert_eq(failed, true)
}

///|
test "http3 conn: QPACK streams classify, and a server rejects a push stream" {
  let conn = Http3Conn::new(
    ServerSide,
    Http3Settings::new(4096UL, 16384UL, 100UL),
  )
  assert_eq(
    conn.accept_uni_stream(http3_encode_stream_type(QpackEncoderStream)),
    QpackEncoder,
  )
  assert_eq(
    conn.accept_uni_stream(http3_encode_stream_type(QpackDecoderStream)),
    QpackDecoder,
  )
  let pushed_to_server = try {
    conn.accept_uni_stream(http3_encode_stream_type(PushStream(7UL))) |> ignore
    false
  } catch {
    _ => true
  }
  assert_eq(pushed_to_server, true)
  // A client, by contrast, accepts a push stream and reads its id.
  let client = Http3Conn::new(ClientSide, Http3Settings::new(0UL, 0UL, 0UL))
  assert_eq(
    client.accept_uni_stream(http3_encode_stream_type(PushStream(7UL))),
    Push(7UL),
  )
}
