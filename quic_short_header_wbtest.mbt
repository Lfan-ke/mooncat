///|
test "short header encodes its first byte per RFC 9000 §17.3" {
  // spin set, key phase clear, packet-number length 2 -> 0x40 | 0x20 | 0x01 = 0x61.
  let h : QuicShortHeader = {
    spin: true,
    key_phase: false,
    pn_length: 2,
    dcid: qv_hexb("01020304"),
  }
  assert_eq(qv_hex(encode_short_header(h)), "6101020304")
}

///|
test "short header round-trips across spin, key-phase, and pn length" {
  let dcid = qv_hexb("8394c8f0")
  for spin in [false, true] {
    for kp in [false, true] {
      for pnl in [1, 2, 3, 4] {
        let h : QuicShortHeader = { spin, key_phase: kp, pn_length: pnl, dcid, }
        let encoded = encode_short_header(h)
        match parse_short_header(encoded[:], dcid.length()) {
          Some((decoded, consumed)) => {
            assert_eq(decoded, h)
            assert_eq(consumed, encoded.length())
          }
          None => fail("short header round-trip failed")
        }
      }
    }
  }
}

///|
test "a long-header first byte and a truncated buffer are rejected" {
  // A long-header first byte (high bit set) is not a short header.
  assert_eq(parse_short_header(qv_hexb("c001020304")[:], 4) is None, true)
  // Fewer bytes than the declared DCID length decodes to None.
  assert_eq(parse_short_header(qv_hexb("610102")[:], 4) is None, true)
}
