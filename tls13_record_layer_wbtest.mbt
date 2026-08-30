// The record-layer driver (RFC 8446 §5). The wire vectors are RFC 8448 §3, the same trace
// `tls13_record_wbtest.mbt` uses, replayed here through the pump rather than a record at a
// time — which is what proves the reassembly and the sequence bookkeeping, not just the
// codec underneath them.

///|
/// A handshake message of `n` body octets under `msg_type` — a stand-in for whatever the
/// handshake layer would really send, since the record layer never looks inside one.
fn hs_msg(msg_type : Int, n : Int) -> Bytes {
  tls_encode_handshake(msg_type, Bytes::make(n, b'\x2a'))
}

///|
test "layer: a handshake message split across two records reassembles" {
  // §5.1: "Handshake messages MAY be ... fragmented across several records". Nothing comes
  // out until the last fragment lands, and then the whole message does.
  let layer = TlsRecordLayer::new()
  let message = rfc_server_hello()
  let head = message[0:40].to_owned()
  let tail = message[40:message.length()].to_owned()
  let first = layer.feed(tls_record_encode(tls_record_handshake, head))
  assert_eq(first, [])
  assert_eq(layer.has_partial(), true)
  let second = layer.feed(tls_record_encode(tls_record_handshake, tail))
  assert_eq(second, [
    HandshakeMsg(msg_type=tls_server_hello, message=rfc_server_hello()),
  ])
  assert_eq(layer.has_partial(), false)
}

///|
test "layer: a message split one octet at a time still reassembles" {
  // The fragmentation the sender chose is invisible: a record per octet reads the same as
  // one record, and a message is only ever delivered whole.
  let layer = TlsRecordLayer::new()
  let message = rfc_server_hello()
  let events : Array[TlsRecordEvent] = []
  for i = 0; i < message.length(); i = i + 1 {
    let one = message[i:i + 1].to_owned()
    for e in layer.feed(tls_record_encode(tls_record_handshake, one)) {
      events.push(e)
    }
  }
  assert_eq(events, [
    HandshakeMsg(msg_type=tls_server_hello, message=rfc_server_hello()),
  ])
}

///|
test "layer: several messages in one record all come out" {
  // §5.1: "Handshake messages MAY be coalesced into a single TLSPlaintext record."
  let layer = TlsRecordLayer::new()
  let flight = bytes_concat(
    hs_msg(8, 3),
    bytes_concat(hs_msg(11, 5), hs_msg(20, 32)),
  )
  let events = layer.feed(tls_record_encode(tls_record_handshake, flight))
  assert_eq(events.length(), 3)
  assert_eq(events[0], HandshakeMsg(msg_type=8, message=hs_msg(8, 3)))
  assert_eq(events[1], HandshakeMsg(msg_type=11, message=hs_msg(11, 5)))
  assert_eq(events[2], HandshakeMsg(msg_type=20, message=hs_msg(20, 32)))
  assert_eq(layer.has_partial(), false)
}

///|
test "layer: a message may both share a record and span the next" {
  // The two §5.1 rules at once: one record holds a whole message and the head of another,
  // and the rest of that one arrives in the record after.
  let layer = TlsRecordLayer::new()
  let whole = hs_msg(8, 4)
  let split = hs_msg(20, 32)
  let first = bytes_concat(whole, split[0:10].to_owned())
  let events = layer.feed(tls_record_encode(tls_record_handshake, first))
  assert_eq(events, [HandshakeMsg(msg_type=8, message=whole)])
  assert_eq(layer.has_partial(), true)
  let rest = split[10:split.length()].to_owned()
  assert_eq(layer.feed(tls_record_encode(tls_record_handshake, rest)), [
    HandshakeMsg(msg_type=20, message=split),
  ])
}

///|
test "layer: bytes short of a whole record are held for the next feed" {
  // A transport hands over whatever the socket gave it, which is rarely a record boundary.
  let layer = TlsRecordLayer::new()
  let record = tls_record_encode(tls_record_handshake, hs_msg(20, 32))
  assert_eq(layer.feed(record[0:3].to_owned()), [])
  assert_eq(layer.feed(record[3:9].to_owned()), [])
  let rest = record[9:record.length()].to_owned()
  assert_eq(layer.feed(rest), [
    HandshakeMsg(msg_type=20, message=hs_msg(20, 32)),
  ])
}

///|
test "layer: a record over 2^14 is refused with a record_overflow" {
  // §5.1 caps a TLSPlaintext fragment at 2^14, and §5.2 a TLSCiphertext at 2^14 + 256. The
  // header settles it either way, so the reader never waits on the oversized body.
  let plain = TlsRecordLayer::new()
  assert_eq(
    rec_refusal(() => plain.feed(b"\x16\x03\x03\x40\x01") |> ignore),
    Some(tls_fatal(tls_alert_record_overflow)),
  )
  let keyed = TlsRecordLayer::new()
  keyed.set_read_secret(rfc_s_ap_secret())
  // Under the ciphertext ceiling this is merely an incomplete record, not a refusal.
  assert_eq(keyed.feed(b"\x17\x03\x03\x40\x01"), [])
  let over = TlsRecordLayer::new()
  over.set_read_secret(rfc_s_ap_secret())
  assert_eq(
    rec_refusal(() => over.feed(b"\x17\x03\x03\x41\x01") |> ignore),
    Some(tls_fatal(tls_alert_record_overflow)),
  )
}

///|
test "layer: an undefined content type ends the connection" {
  // §5 — the record layer does not skip what it does not know.
  let layer = TlsRecordLayer::new()
  assert_eq(
    rec_refusal(() => layer.feed(b"\x19\x03\x03\x00\x01\x00") |> ignore),
    Some(tls_fatal(tls_alert_unexpected_message)),
  )
}

///|
test "layer: the RFC 8448 handshake replays through the pump" {
  // The client's view of RFC 8448 §3: a plaintext ServerHello, then the server's flight
  // under the handshake traffic keys, then NewSessionTicket, application data and
  // close_notify under the application keys — each key change restarting the sequence.
  let layer = TlsRecordLayer::new()
  assert_eq(layer.feed(rfc_server_hello_record()), [
    HandshakeMsg(msg_type=tls_server_hello, message=rfc_server_hello()),
  ])
  layer.set_read_secret(rfc_s_hs_secret())
  assert_eq(layer.read_seq(), 0UL)
  let flight = layer.feed(rfc_server_flight_record())
  assert_eq(layer.read_seq(), 1UL)
  // EncryptedExtensions, Certificate, CertificateVerify, Finished — four messages the
  // server coalesced into one record.
  assert_eq(flight.length(), 4)
  assert_eq(
    flight[0],
    HandshakeMsg(msg_type=8, message=rfc_server_flight()[0:40].to_owned()),
  )
  assert_eq(
    flight[1],
    HandshakeMsg(msg_type=11, message=rfc_server_flight()[40:485].to_owned()),
  )
  assert_eq(
    flight[2],
    HandshakeMsg(msg_type=15, message=rfc_server_flight()[485:621].to_owned()),
  )
  assert_eq(
    flight[3],
    HandshakeMsg(msg_type=20, message=rfc_server_flight()[621:657].to_owned()),
  )
  layer.set_read_secret(rfc_s_ap_secret())
  layer.handshake_done()
  assert_eq(layer.read_seq(), 0UL)
  assert_eq(layer.feed(rfc_new_session_ticket_record()), [
    HandshakeMsg(msg_type=4, message=rfc_new_session_ticket()),
  ])
  assert_eq(layer.feed(rfc_server_app_record()), [AppData(rfc_app_payload())])
  assert_eq(layer.feed(rfc_server_alert_record()), [
    PeerAlert(tls_warning(tls_alert_close_notify)),
  ])
  assert_eq(layer.read_seq(), 3UL)
}

///|
test "layer: the whole server flight arrives as one buffer of bytes" {
  // The same trace, fed as the transport would deliver it — two records in one read, with
  // no boundary marked — to show the pump finds them itself.
  let layer = TlsRecordLayer::new()
  let events = layer.feed(
    bytes_concat(rfc_server_hello_record(), rfc_server_hello_record()),
  )
  assert_eq(events.length(), 2)
  assert_eq(events[0], events[1])
}

///|
test "layer: a round trip carries application data with the sequence advancing" {
  // Two ends of one connection: what the writer seals under its traffic secret, the reader
  // opens under the same one, and both sequence numbers walk together (§5.3).
  let writer = TlsRecordLayer::new()
  let reader = TlsRecordLayer::new()
  writer.set_write_secret(rfc_c_ap_secret())
  reader.set_read_secret(rfc_c_ap_secret())
  assert_eq(writer.write_seq(), 0UL)
  let first = writer.write_app(b"hhh")
  assert_eq(writer.write_seq(), 1UL)
  assert_eq(reader.feed(first), [AppData(b"hhh")])
  assert_eq(reader.read_seq(), 1UL)
  let second = writer.write_app(b"qwq")
  let third = writer.write_app(rfc_app_payload())
  assert_eq(writer.write_seq(), 3UL)
  // Both records in one buffer, still in order.
  assert_eq(reader.feed(bytes_concat(second, third)), [
    AppData(b"qwq"),
    AppData(rfc_app_payload()),
  ])
  assert_eq(reader.read_seq(), 3UL)
  // Each record used a different nonce, so no two are alike.
  assert_eq(first == second, false)
}

///|
test "layer: a round trip carries a handshake flight and an alert" {
  let writer = TlsRecordLayer::new()
  let reader = TlsRecordLayer::new()
  writer.set_write_secret(rfc_s_hs_secret())
  reader.set_read_secret(rfc_s_hs_secret())
  let flight = bytes_concat(hs_msg(8, 3), hs_msg(20, 32))
  assert_eq(reader.feed(writer.write_handshake(flight)), [
    HandshakeMsg(msg_type=8, message=hs_msg(8, 3)),
    HandshakeMsg(msg_type=20, message=hs_msg(20, 32)),
  ])
  let alert = tls_fatal(tls_alert_bad_certificate)
  assert_eq(reader.feed(writer.write_alert(alert)), [PeerAlert(alert)])
}

///|
test "layer: writes are plaintext until the write secret is installed" {
  // The ClientHello and ServerHello travel as TLSPlaintext; everything after the keys is a
  // TLSCiphertext whose outer type claims application_data (§5.2).
  let layer = TlsRecordLayer::new()
  let clear = layer.write_handshake(rfc_server_hello())
  assert_eq(qv_hex(clear), qv_hex(rfc_server_hello_record()))
  assert_eq(layer.write_seq(), 0UL)
  layer.set_write_secret(rfc_s_hs_secret())
  let armoured = layer.write_handshake(rfc_server_flight())
  assert_eq(armoured[0].to_int(), tls_record_application_data)
  assert_eq(qv_hex(armoured), qv_hex(rfc_server_flight_record()))
  assert_eq(layer.write_seq(), 1UL)
}

///|
test "layer: content past the fragment limit is split across records" {
  // §5.1 — the writer fragments rather than refusing, which is what lets a handshake
  // message longer than a record exist at all.
  let layer = TlsRecordLayer::new()
  let big = Bytes::make(tls_record_max_fragment + 100, b'\x2a')
  let out = layer.write_app(big)
  let (first, used) = tls_record_parse(out[:]).unwrap()
  assert_eq(first.fragment.length(), tls_record_max_fragment)
  let (second, used2) = tls_record_parse(out[used:]).unwrap()
  assert_eq(second.fragment.length(), 100)
  assert_eq(used + used2, out.length())
  // Sealed, it is two records too, and each one advances the sequence.
  let keyed = TlsRecordLayer::new()
  keyed.set_write_secret(rfc_c_ap_secret())
  let reader = TlsRecordLayer::new()
  reader.set_read_secret(rfc_c_ap_secret())
  let closed = keyed.write_app(big)
  assert_eq(keyed.write_seq(), 2UL)
  assert_eq(reader.feed(closed), [
    AppData(Bytes::make(tls_record_max_fragment, b'\x2a')),
    AppData(Bytes::make(100, b'\x2a')),
  ])
}

///|
test "layer: a change_cipher_spec is dropped inside its window and refused outside it" {
  // §5: an unencrypted change_cipher_spec is tolerated for middlebox compatibility between
  // the first ClientHello and the peer's Finished, carries no meaning, and is dropped. It
  // must be the single octet 0x01, and once the handshake is over it is not tolerated.
  assert_eq(
    qv_hex(tls_record_ccs),
    qv_hex(tls_record_encode(tls_record_change_cipher_spec, b"\x01")),
  )
  let layer = TlsRecordLayer::new()
  assert_eq(layer.feed(tls_record_ccs), [])
  // It is still tolerated after the read keys are in — that is the whole point of it.
  layer.set_read_secret(rfc_s_hs_secret())
  assert_eq(layer.feed(tls_record_ccs), [])
  assert_eq(layer.read_seq(), 0UL)
  assert_eq(layer.feed(rfc_server_flight_record()).length(), 4)
  layer.handshake_done()
  assert_eq(
    rec_refusal(() => layer.feed(tls_record_ccs) |> ignore),
    Some(tls_fatal(tls_alert_unexpected_message)),
  )
}

///|
test "layer: a change_cipher_spec carrying anything else ends the connection" {
  // §5: "An implementation which receives any other change_cipher_spec value ... MUST abort
  // the handshake with an unexpected_message alert."
  let wrong = TlsRecordLayer::new()
  assert_eq(
    rec_refusal(() => {
      wrong.feed(tls_record_encode(tls_record_change_cipher_spec, b"\x02"))
      |> ignore
    }),
    Some(tls_fatal(tls_alert_unexpected_message)),
  )
  let long = TlsRecordLayer::new()
  assert_eq(
    rec_refusal(() => {
      long.feed(tls_record_encode(tls_record_change_cipher_spec, b"\x01\x01"))
      |> ignore
    }),
    Some(tls_fatal(tls_alert_unexpected_message)),
  )
}

///|
test "layer: a protected change_cipher_spec ends the connection" {
  // §5: a change_cipher_spec that arrives inside a TLSCiphertext is not the middlebox
  // record — it is an unexpected_message however well it decrypts.
  let writer = TlsRecordKeys::new(rfc_s_hs_secret())
  let layer = TlsRecordLayer::new()
  layer.set_read_secret(rfc_s_hs_secret())
  let record = writer.seal(tls_record_change_cipher_spec, b"\x01")
  assert_eq(
    rec_refusal(() => layer.feed(record) |> ignore),
    Some(tls_fatal(tls_alert_unexpected_message)),
  )
}

///|
test "layer: once the read keys are in, a cleartext handshake record is refused" {
  // Everything after the ServerHello is protected; a handshake or alert record still in the
  // clear is an unexpected_message rather than something to read.
  let layer = TlsRecordLayer::new()
  layer.set_read_secret(rfc_s_hs_secret())
  assert_eq(
    rec_refusal(() => layer.feed(rfc_server_hello_record()) |> ignore),
    Some(tls_fatal(tls_alert_unexpected_message)),
  )
  let alerting = TlsRecordLayer::new()
  alerting.set_read_secret(rfc_s_hs_secret())
  assert_eq(
    rec_refusal(() => {
      alerting.feed(tls_record_encode(tls_record_alert, b"\x01\x00")) |> ignore
    }),
    Some(tls_fatal(tls_alert_unexpected_message)),
  )
}

///|
test "layer: cleartext application data is refused before any keys" {
  // There is no point in the handshake at which application data travels unprotected.
  let layer = TlsRecordLayer::new()
  assert_eq(
    rec_refusal(() => {
      layer.feed(tls_record_encode(tls_record_application_data, b"hhh"))
      |> ignore
    }),
    Some(tls_fatal(tls_alert_unexpected_message)),
  )
}

///|
test "layer: another record type may not interrupt a handshake message" {
  // §5.1: "Handshake messages MUST NOT be interleaved with other record types."
  let layer = TlsRecordLayer::new()
  let split = hs_msg(20, 32)
  assert_eq(
    layer.feed(tls_record_encode(tls_record_handshake, split[0:10].to_owned())),
    [],
  )
  assert_eq(layer.has_partial(), true)
  assert_eq(
    rec_refusal(() => {
      layer.feed(tls_record_encode(tls_record_alert, b"\x01\x00")) |> ignore
    }),
    Some(tls_fatal(tls_alert_unexpected_message)),
  )
  // The same, with application data over the protected path.
  let keyed = TlsRecordLayer::new()
  let writer = TlsRecordKeys::new(rfc_c_ap_secret())
  keyed.set_read_secret(rfc_c_ap_secret())
  assert_eq(
    keyed.feed(writer.seal(tls_record_handshake, split[0:10].to_owned())),
    [],
  )
  assert_eq(
    rec_refusal(() => {
      keyed.feed(writer.seal(tls_record_application_data, b"hhh")) |> ignore
    }),
    Some(tls_fatal(tls_alert_unexpected_message)),
  )
}

///|
test "layer: an alert is two octets and never shares or spans a record" {
  // §6 — anything else under the alert content type is a message that cannot be parsed.
  let layer = TlsRecordLayer::new()
  assert_eq(
    rec_refusal(() => {
      layer.feed(tls_record_encode(tls_record_alert, b"\x01")) |> ignore
    }),
    Some(tls_fatal(tls_alert_decode_error)),
  )
  let coalesced = TlsRecordLayer::new()
  assert_eq(
    rec_refusal(() => {
      coalesced.feed(tls_record_encode(tls_record_alert, b"\x01\x00\x02\x28"))
      |> ignore
    }),
    Some(tls_fatal(tls_alert_decode_error)),
  )
  // A well-formed one comes out as the alert it is, level and description intact.
  let ok = TlsRecordLayer::new()
  assert_eq(ok.feed(tls_record_encode(tls_record_alert, b"\x02\x28")), [
    PeerAlert(tls_fatal(tls_alert_handshake_failure)),
  ])
}

///|
test "layer: a tampered protected record is a bad_record_mac" {
  // §5.2 — the pump reports the AEAD's verdict as the alert the connection dies of.
  let layer = TlsRecordLayer::new()
  layer.set_read_secret(rfc_s_hs_secret())
  let flipped = rfc_server_flight_record().to_array()
  flipped[100] = (flipped[100].to_int() ^ 0x01).to_byte()
  assert_eq(
    rec_refusal(() => layer.feed(Bytes::from_array(flipped)) |> ignore),
    Some(tls_fatal(tls_alert_bad_record_mac)),
  )
}
