// QUIC 1-RTT (Application) packet protection (RFC 9000 §17.3, RFC 9001 §5.3–§5.4): a short
// header with no length field and no wire connection-id lengths, protected with the
// application traffic keys derived over the RFC 8448 §3 key schedule.

///|
/// The server application-space keys from the RFC 8448 §3 master secret and 1-RTT
/// transcript (the traffic secret and its packet keys are checked in quic_hs_keys_wbtest).
fn rfc8448_server_app_keys() -> QuicPacketKeys {
  let master = qv_hexb(
    "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919",
  )
  let ap_th = qv_hexb(
    "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13",
  )
  quic_application_keys(master, ap_th, false)
}

///|
test "1-RTT packet: application frames round-trip under the app keys" {
  let keys = rfc8448_server_app_keys()
  let dcid = qv_hexb("0001020304050607") // 8 bytes
  let frames : Array[QuicFrame] = [
    Stream(id=0, offset=0, fin=false, data=b"hello over 1-RTT application data"),
    Ack(largest=4, delay=0, first_range=4, ranges=[]),
  ]
  let packet = quic_send_short(false, false, dcid, 42, 2, frames, keys)
  match quic_recv_short(packet, dcid.length(), keys) {
    Some((got, pn)) => {
      assert_eq(pn, 42)
      assert_eq(got, frames)
    }
    None => abort("1-RTT packet failed to authenticate")
  }
}

///|
test "1-RTT packet: the short header carries the spin and key-phase bits" {
  let keys = rfc8448_server_app_keys()
  let dcid = qv_hexb("0001020304050607")
  let frames : Array[QuicFrame] = [
    Stream(id=4, offset=0, fin=true, data=b"key phase one, spin set"),
  ]
  let packet = quic_send_short(true, true, dcid, 7, 4, frames, keys)
  // After removing header protection the recovered first byte shows the fixed bit, spin,
  // and key phase; parse_short_header reads them back.
  let (unprotected, _) = quic_header_unprotect(
    packet,
    1 + dcid.length(),
    keys.hp,
  )
  match parse_short_header(unprotected[:], dcid.length()) {
    Some((h, _)) => {
      assert_eq(h.spin, true)
      assert_eq(h.key_phase, true)
      assert_eq(h.dcid, dcid)
    }
    None => abort("expected a short header")
  }
  // And the frames still round-trip.
  match quic_recv_short(packet, dcid.length(), keys) {
    Some((got, pn)) => {
      assert_eq(pn, 7)
      assert_eq(got, frames)
    }
    None => abort("1-RTT packet failed to authenticate")
  }
}

///|
test "1-RTT packet: a tampered packet is rejected" {
  let keys = rfc8448_server_app_keys()
  let dcid = qv_hexb("0001020304050607")
  let packet = quic_send_short(
    false,
    false,
    dcid,
    1,
    2,
    [Stream(id=0, offset=0, fin=false, data=b"application payload")],
    keys,
  )
  let buf = Buffer()
  for i = 0; i < packet.length(); i = i + 1 {
    if i == packet.length() - 1 {
      buf.write_byte((packet[i].to_int() ^ 0xff).to_byte())
    } else {
      buf.write_byte(packet[i])
    }
  }
  match quic_recv_short(buf.to_bytes(), dcid.length(), keys) {
    Some(_) => abort("a tampered 1-RTT packet must not authenticate")
    None => ()
  }
}
