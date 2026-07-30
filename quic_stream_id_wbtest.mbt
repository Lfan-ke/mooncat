// QUIC stream-id classification and generation (RFC 9000 §2.1, Table 1).

///|
test "stream id: RFC 9000 Table 1 classifies the four low-bit patterns" {
  assert_eq(stream_initiator(0), Client)
  assert_eq(stream_direction(0), Bidirectional)
  assert_eq(stream_initiator(1), Server)
  assert_eq(stream_direction(1), Bidirectional)
  assert_eq(stream_initiator(2), Client)
  assert_eq(stream_direction(2), Unidirectional)
  assert_eq(stream_initiator(3), Server)
  assert_eq(stream_direction(3), Unidirectional)
}

///|
test "stream id: generation places the type bits and sequence" {
  assert_eq(stream_id_of(Client, Bidirectional, 0), 0)
  assert_eq(stream_id_of(Server, Bidirectional, 0), 1)
  assert_eq(stream_id_of(Client, Unidirectional, 0), 2)
  assert_eq(stream_id_of(Server, Unidirectional, 0), 3)
  // Streams of one type are four apart.
  assert_eq(stream_id_of(Client, Bidirectional, 1), 4)
  assert_eq(stream_id_of(Server, Unidirectional, 5), 23)
}

///|
test "stream id: sequence recovers the index within the type" {
  assert_eq(stream_sequence(0), 0)
  assert_eq(stream_sequence(4), 1)
  assert_eq(stream_sequence(23), 5)
  assert_eq(stream_is_bidi(4), true)
  assert_eq(stream_is_bidi(3), false)
  assert_eq(stream_is_client_initiated(2), true)
  assert_eq(stream_is_client_initiated(1), false)
}

///|
test "stream id: generation and classification round-trip" {
  let inits = [Client, Server]
  let dirs = [Bidirectional, Unidirectional]
  for initiator in inits {
    for direction in dirs {
      for seq = 0UL; seq < 4; seq = seq + 1 {
        let id = stream_id_of(initiator, direction, seq)
        assert_eq(stream_initiator(id), initiator)
        assert_eq(stream_direction(id), direction)
        assert_eq(stream_sequence(id), seq)
      }
    }
  }
}

///|
test "stream id: locally-initiated depends on role" {
  // Even ids are client-initiated.
  assert_eq(stream_is_locally_initiated(0, false), true) // client, client stream
  assert_eq(stream_is_locally_initiated(0, true), false) // server, client stream
  assert_eq(stream_is_locally_initiated(1, true), true) // server, server stream
  assert_eq(stream_is_locally_initiated(1, false), false)
}

///|
test "stream id: writability follows ownership and directionality" {
  // A client may write its own bidi and uni streams, and peer-opened bidi streams,
  // but not a server-opened unidirectional (receive-only) stream.
  assert_eq(stream_is_writable(0, false), true) // client bidi (own)
  assert_eq(stream_is_writable(2, false), true) // client uni (own)
  assert_eq(stream_is_writable(1, false), true) // server bidi (peer, bidi)
  assert_eq(stream_is_writable(3, false), false) // server uni (peer, recv-only)
  // Symmetrically for the server on a client-opened unidirectional stream.
  assert_eq(stream_is_writable(2, true), false) // client uni (peer, recv-only)
  assert_eq(stream_is_writable(0, true), true) // client bidi (peer, bidi)
}
