///|
/// The RFC 8448 section 3 ClientHello handshake message (196 bytes).
let rfc8448_client_hello : String = "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001"

///|
/// The RFC 8448 section 3 ServerHello handshake message (90 bytes).
let rfc8448_server_hello : String = "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304"

///|
test "the RFC 8448 ClientHello parses and re-encodes byte for byte" {
  let msg = qv_hexb(rfc8448_client_hello)
  guard tls_parse_handshake(msg[:]) is Some((mt, body)) else {
    fail("ClientHello should frame")
  }
  assert_eq(mt, tls_client_hello)
  guard decode_client_hello(body[:]) is Some(ch) else {
    fail("ClientHello body should decode")
  }
  assert_eq(ch.cipher_suites, [0x1301, 0x1303, 0x1302])
  assert_eq(tls_find_extension(ch.extensions, 0x002b) is Some(_), true)
  assert_eq(tls_find_extension(ch.extensions, 0x0033) is Some(_), true)
  assert_eq(qv_hex(encode_client_hello(ch)), rfc8448_client_hello)
}

///|
test "the RFC 8448 ServerHello parses and re-encodes byte for byte" {
  let msg = qv_hexb(rfc8448_server_hello)
  guard tls_parse_handshake(msg[:]) is Some((mt, body)) else {
    fail("ServerHello should frame")
  }
  assert_eq(mt, tls_server_hello)
  guard decode_server_hello(body[:]) is Some(sh) else {
    fail("ServerHello body should decode")
  }
  assert_eq(sh.cipher_suite, 0x1301)
  guard tls_find_extension(sh.extensions, 0x0033) is Some(ks) else {
    fail("ServerHello should carry a key_share")
  }
  assert_eq(ks.data.length() > 0, true)
  assert_eq(qv_hex(encode_server_hello(sh)), rfc8448_server_hello)
}
