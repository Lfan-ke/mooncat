// The TLS 1.3 record layer (RFC 8446 §5). RFC 8446 prints no numeric record examples, so
// the wire vectors here come from RFC 8448 "Example Handshake Traces for TLS 1.3" §3, the
// simple 1-RTT handshake, whose cipher suite is the TLS_AES_128_GCM_SHA256 this build
// implements. Each `rfc_*` helper is one value lifted out of that trace.

///|
/// Which §5 alert a record was refused with, or `None` if it was accepted — so a negative
/// case asserts on the reason the layer gave and not merely on the fact that it said no.
fn rec_refusal(f : () -> Unit raise TlsAlert) -> TlsAlert? {
  try f() catch {
    a => Some(a)
  } noraise {
    _ => None
  }
}

///|
/// RFC 8448 §3: the server's handshake-data write traffic secret.
fn rfc_s_hs_secret() -> Bytes {
  qv_hexb("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
}

///|
/// RFC 8448 §3: the client's handshake-data write traffic secret.
fn rfc_c_hs_secret() -> Bytes {
  qv_hexb("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
}

///|
/// RFC 8448 §3: the server's application-data write traffic secret.
fn rfc_s_ap_secret() -> Bytes {
  qv_hexb("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
}

///|
/// RFC 8448 §3: the client's application-data write traffic secret.
fn rfc_c_ap_secret() -> Bytes {
  qv_hexb("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
}

///|
/// RFC 8448 §3: the ServerHello, as the unencrypted record that carried it.
fn rfc_server_hello_record() -> Bytes {
  qv_hexb(
    "160303005a020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304",
  )
}

///|
/// RFC 8448 §3: the ServerHello handshake message alone.
fn rfc_server_hello() -> Bytes {
  qv_hexb(
    "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304",
  )
}

///|
/// RFC 8448 §3: the ClientHello record, whose legacy_record_version is 0x0301.
fn rfc_client_hello_record() -> Bytes {
  qv_hexb(
    "16030100c4010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001",
  )
}

///|
/// RFC 8448 §3: the ClientHello handshake message alone.
fn rfc_client_hello() -> Bytes {
  qv_hexb(
    "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001",
  )
}

///|
/// RFC 8448 §3: EncryptedExtensions, Certificate, CertificateVerify and Finished, coalesced
/// into the one protected record the server sent them in.
fn rfc_server_flight_record() -> Bytes {
  qv_hexb(
    "17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35edf7869fcf40aa40aa2b8ea73f848a7ca07612ef9f945cb960b4068905123ea78b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13bd9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9d7477609aee6e122a4cf51427325250c7d0e509289444c9b3a648f1d71035d2ed65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd610928d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead686945ba246ab66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b3684596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26f59ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b659622245317b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da8c87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7cca71e4599426f7d461e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb992f2b992f67f8afe67f76913fa388cb5630c8ca01e0c65d11c66a1e2ac4c85977b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b845e275592c12335ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e750edc53370d2b",
  )
}

///|
/// RFC 8448 §3: those four handshake messages, back to back.
fn rfc_server_flight() -> Bytes {
  qv_hexb(
    "080000240022000a00140012001d00170018001901000101010201030104001c00024001000000000b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de100000f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718",
  )
}

///|
/// RFC 8448 §3: the client's Finished, as the protected record that carried it.
fn rfc_client_finished_record() -> Bytes {
  qv_hexb(
    "170303003575ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc44d87f38f80338ac98fc46deb384bd1caeacab6867d726c40546",
  )
}

///|
/// RFC 8448 §3: the client's Finished handshake message.
fn rfc_client_finished() -> Bytes {
  qv_hexb(
    "14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61",
  )
}

///|
/// RFC 8448 §3: the NewSessionTicket record — the server's first under its application
/// traffic keys, so sequence number zero.
fn rfc_new_session_ticket_record() -> Bytes {
  qv_hexb(
    "17030300de3a6b8f90414a97d6959c3487680de5134a2b240e6cffac116e95d41d6af8f6b580dcf3d11d63c758db289a015940252f55713e061dc13e078891a38efbcf5753ad8ef170ad3c7353d16d9da773b9ca7f2b9fa1b6c0d4a3d03f75e09c30ba1e62972ac46f75f7b981be63439b2999ce13064615139891d5e4c5b406f16e3fc181a77ca475840025db2f0a77f81b5ab05b94c01346755f69232c86519d86cbeeac87aac347d143f9605d64f650db4d023e70e952ca49fe5137121c74bc2697687e248746d6df353005f3bce18696129c8153556b3b6c6779b37bf15985684f",
  )
}

///|
/// RFC 8448 §3: the NewSessionTicket handshake message.
fn rfc_new_session_ticket() -> Bytes {
  qv_hexb(
    "040000c90000001efad6aac502000000b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093934ae4d3570008002a000400000400",
  )
}

///|
/// RFC 8448 §3: the server's application-data record, its second under those keys.
fn rfc_server_app_record() -> Bytes {
  qv_hexb(
    "17030300432e937e11ef4ac740e538ad36005fc4a46932fc3225d05f82aa1b36e30efaf97d90e6dffc602dcb501a59a8fcc49c4bf2e5f0a21c0047c2abf332540dd032e167c2955d",
  )
}

///|
/// RFC 8448 §3: the client's application-data record, its first under its application keys.
fn rfc_client_app_record() -> Bytes {
  qv_hexb(
    "1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f2b9819a8a5b46b395bd54a9a20441e2b62974e1f5a6292a2977014bd1e3deae63aeebb21694915e4",
  )
}

///|
/// RFC 8448 §3: the 0x00..0x31 payload both sides send as application data.
fn rfc_app_payload() -> Bytes {
  qv_hexb(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031",
  )
}

///|
/// RFC 8448 §3: the server's close_notify record, its third under those keys.
fn rfc_server_alert_record() -> Bytes {
  qv_hexb("1703030013b58fd67166ebf599d24720cfbe7efa7a8864a9")
}

///|
/// RFC 8448 §3: the client's close_notify record, its second under its application keys.
fn rfc_client_alert_record() -> Bytes {
  qv_hexb("1703030013c9872760655666b74d7ff1153efd6db6d0b0e3")
}

///|
test "record: a TLSPlaintext is the content type, the frozen version, and the length" {
  // §5.1, against the ServerHello record of RFC 8448 §3: type 22, version 0x0303, length
  // 90, then the 90-octet message.
  let framed = tls_record_encode(tls_record_handshake, rfc_server_hello())
  assert_eq(qv_hex(framed), qv_hex(rfc_server_hello_record()))
  assert_eq(qv_hex(framed[0:5].to_owned()), "160303005a")
  let (rec, used) = tls_record_parse(rfc_server_hello_record()[:]).unwrap()
  assert_eq(rec.content_type, tls_record_handshake)
  assert_eq(qv_hex(rec.fragment), qv_hex(rfc_server_hello()))
  assert_eq(used, rfc_server_hello_record().length())
}

///|
test "record: legacy_record_version is ignored on the way in" {
  // §5.1 freezes the field for middleboxes and tells the receiver to ignore it. RFC 8448's
  // initial ClientHello record carries 0x0301 rather than 0x0303.
  let record = rfc_client_hello_record()
  assert_eq(qv_hex(record[0:5].to_owned()), "16030100c4")
  let (rec, _) = tls_record_parse(record[:]).unwrap()
  assert_eq(rec.content_type, tls_record_handshake)
  assert_eq(qv_hex(rec.fragment), qv_hex(rfc_client_hello()))
}

///|
test "record: a fragment past 2^14 is a record_overflow" {
  // §5.1: "The length MUST NOT exceed 2^14 octets."
  assert_eq(tls_record_max_fragment, 16384)
  let over = Bytes::make(tls_record_max_fragment + 1, b'\x00')
  assert_eq(
    rec_refusal(() => {
      tls_record_encode(tls_record_application_data, over) |> ignore
    }),
    Some(tls_fatal(tls_alert_record_overflow)),
  )
  // The header alone settles it. Waiting for the rest of an oversized record would leave a
  // reader parked on bytes that must never be accepted anyway.
  assert_eq(
    rec_refusal(() => tls_record_parse(b"\x17\x03\x03\x40\x01"[:]) |> ignore),
    Some(tls_fatal(tls_alert_record_overflow)),
  )
  // §5.2 gives TLSCiphertext 2^14 + 256, the room the inner type, the padding and the tag
  // need — so the same header is merely an incomplete record to the encrypted reader.
  assert_eq(tls_record_max_encrypted, 16640)
  assert_eq(tls_record_parse_encrypted(b"\x17\x03\x03\x40\x01"[:]), None)
  assert_eq(
    rec_refusal(() => {
      tls_record_parse_encrypted(b"\x17\x03\x03\x41\x01"[:]) |> ignore
    }),
    Some(tls_fatal(tls_alert_record_overflow)),
  )
}

///|
test "record: an undefined content type is an unexpected_message" {
  // §5: a record carrying a type the receiver does not recognise ends the connection.
  assert_eq(
    rec_refusal(() => tls_record_parse(b"\x19\x03\x03\x00\x01\x00"[:]) |> ignore),
    Some(tls_fatal(tls_alert_unexpected_message)),
  )
  assert_eq(
    rec_refusal(() => tls_record_parse(b"\x00\x03\x03\x00\x01\x00"[:]) |> ignore),
    Some(tls_fatal(tls_alert_unexpected_message)),
  )
  for
    t in [
      tls_record_change_cipher_spec, tls_record_alert, tls_record_handshake, tls_record_application_data,
    ] {
    let (rec, _) = tls_record_parse(tls_record_encode(t, b"\x01\x02")[:]).unwrap()
    assert_eq(rec.content_type, t)
  }
}

///|
test "record: only application_data may be sent zero-length" {
  // §5.1 forbids zero-length handshake, alert and change_cipher_spec fragments, and allows
  // them for application data as a traffic-analysis countermeasure.
  let (rec, used) = tls_record_parse(b"\x17\x03\x03\x00\x00"[:]).unwrap()
  assert_eq(rec.fragment.length(), 0)
  assert_eq(used, 5)
  for
    t in [tls_record_handshake, tls_record_alert, tls_record_change_cipher_spec] {
    let empty = b"\x00\x03\x03\x00\x00".to_array()
    empty[0] = t.to_byte()
    assert_eq(
      rec_refusal(() => tls_record_parse(Bytes::from_array(empty)[:]) |> ignore),
      Some(tls_fatal(tls_alert_unexpected_message)),
    )
  }
}

///|
test "record: a view short of a whole record is not yet a record" {
  let record = rfc_server_hello_record()
  for n = 0; n < record.length(); n = n + 1 {
    assert_eq(tls_record_parse(record[0:n]), None)
  }
  let (whole, used) = tls_record_parse(record[:]).unwrap()
  assert_eq(used, record.length())
  assert_eq(whole.fragment.length(), record.length() - tls_record_header_len)
}

///|
test "record: parse says what it consumed, so several records share one buffer" {
  // §5.1 lets a sender put several records in one flight of bytes; the consumed count is
  // what lets a reader walk from one to the next.
  let two = bytes_concat(
    tls_record_encode(tls_record_handshake, b"abc"),
    tls_record_encode(tls_record_application_data, b"defg"),
  )
  let (first, used) = tls_record_parse(two[:]).unwrap()
  assert_eq(first.content_type, tls_record_handshake)
  assert_eq(first.fragment, b"abc")
  assert_eq(used, 8)
  let (second, used2) = tls_record_parse(two[used:]).unwrap()
  assert_eq(second.content_type, tls_record_application_data)
  assert_eq(second.fragment, b"defg")
  assert_eq(used + used2, two.length())
}

///|
test "record: TLSInnerPlaintext is content, then the real type, then zeros" {
  // §5.2 — the outer header says application_data; the type inside is the truth.
  assert_eq(
    qv_hex(tls_record_inner(tls_record_handshake, b"\xaa\xbb", 0)),
    "aabb16",
  )
  assert_eq(
    qv_hex(tls_record_inner(tls_record_alert, b"\x01\x00", 3)),
    "010015000000",
  )
  let (t, content) = tls_record_unpad(qv_hexb("010015000000")[:])
  assert_eq(t, tls_record_alert)
  assert_eq(qv_hex(content), "0100")
  // Padding is invisible: the same content comes back whatever was appended.
  for pad in [0, 1, 7, 64] {
    let inner = tls_record_inner(tls_record_application_data, b"heke1228", pad)
    assert_eq(inner.length(), 8 + 1 + pad)
    let (rt, rc) = tls_record_unpad(inner[:])
    assert_eq(rt, tls_record_application_data)
    assert_eq(rc, b"heke1228")
  }
}

///|
test "record: an inner plaintext of only zeros names no type" {
  // §5.2: "If a receiving implementation does not find a non-zero octet in the cleartext,
  // it MUST terminate the connection with an unexpected_message alert."
  for n in [0, 1, 16] {
    assert_eq(
      rec_refusal(() => tls_record_unpad(Bytes::make(n, b'\x00')[:]) |> ignore),
      Some(tls_fatal(tls_alert_unexpected_message)),
    )
  }
  // A lone type octet is a zero-length content, not a failure.
  let (t, content) = tls_record_unpad(b"\x17"[:])
  assert_eq(t, tls_record_application_data)
  assert_eq(content.length(), 0)
}

///|
test "record: traffic keys are the §7.3 expansion of the traffic secret" {
  // §7.3 expands the secret under "key" and "iv"; RFC 8448 §3 prints both for every
  // direction of the handshake it traces.
  let s_hs = tls13_traffic_keys(rfc_s_hs_secret())
  assert_eq(qv_hex(s_hs.key), "3fce516009c21727d0f2e4e86ee403bc")
  assert_eq(qv_hex(s_hs.iv), "5d313eb2671276ee13000b30")
  let c_hs = tls13_traffic_keys(rfc_c_hs_secret())
  assert_eq(qv_hex(c_hs.key), "dbfaa693d1762c5b666af5d950258d01")
  assert_eq(qv_hex(c_hs.iv), "5bd3c71b836e0b76bb73265f")
  let s_ap = tls13_traffic_keys(rfc_s_ap_secret())
  assert_eq(qv_hex(s_ap.key), "9f02283b6c9c07efc26bb9f2ac92e356")
  assert_eq(qv_hex(s_ap.iv), "cf782b88dd83549aadf1e984")
  let c_ap = tls13_traffic_keys(rfc_c_ap_secret())
  assert_eq(qv_hex(c_ap.key), "17422dda596ed5d9acd890e3c63f5051")
  assert_eq(qv_hex(c_ap.iv), "5b78923dee08579033e523d9")
}

///|
test "record: the nonce is the sequence number XORed into the write IV" {
  // §5.3: the 64-bit sequence number, big-endian, left-padded with zeros to the IV's
  // length, XORed with the static IV. RFC 8448's server application IV ends 0x84, so its
  // record at sequence 2 ends 0x86 and nothing else moves.
  let iv = tls13_traffic_keys(rfc_s_ap_secret()).iv
  assert_eq(qv_hex(tls_record_nonce(iv, 0UL)), "cf782b88dd83549aadf1e984")
  assert_eq(qv_hex(tls_record_nonce(iv, 2UL)), "cf782b88dd83549aadf1e986")
  // The number is right-aligned: the leading four octets of a 12-byte IV are out of its
  // reach, and it climbs one place further left for every 256 records.
  assert_eq(
    qv_hex(tls_record_nonce(Bytes::make(12, b'\x00'), 1UL)),
    "000000000000000000000001",
  )
  assert_eq(
    qv_hex(tls_record_nonce(Bytes::make(12, b'\x00'), 256UL)),
    "000000000000000000000100",
  )
  assert_eq(
    qv_hex(tls_record_nonce(Bytes::make(12, b'\x00'), 0xffffffffffffffffUL)),
    "00000000ffffffffffffffff",
  )
  // XOR, not addition: a bit the sequence and the IV share cancels.
  assert_eq(
    qv_hex(tls_record_nonce(qv_hexb("000000000000000000000003"), 1UL)),
    "000000000000000000000002",
  )
}

///|
test "record: the RFC 8448 server flight opens under the handshake traffic keys" {
  // §5.2 — four handshake messages coalesced into one protected record, whose outer type
  // says application_data while the type sealed inside says handshake.
  let keys = TlsRecordKeys::new(rfc_s_hs_secret())
  assert_eq(keys.seq(), 0UL)
  assert_eq(qv_hex(keys.nonce()), "5d313eb2671276ee13000b30")
  let record = rfc_server_flight_record()
  assert_eq(qv_hex(record[0:5].to_owned()), "17030302a2")
  let (content_type, content) = keys.open(record[:])
  assert_eq(content_type, tls_record_handshake)
  assert_eq(qv_hex(content), qv_hex(rfc_server_flight()))
  assert_eq(keys.seq(), 1UL)
}

///|
test "record: sealing reproduces the RFC 8448 records byte for byte" {
  // The header is the AEAD's additional data (§5.2) and the nonce is the sequence number
  // XORed into the IV (§5.3); get either wrong and none of these match.
  let server = TlsRecordKeys::new(rfc_s_hs_secret())
  assert_eq(
    qv_hex(server.seal(tls_record_handshake, rfc_server_flight())),
    qv_hex(rfc_server_flight_record()),
  )
  let client = TlsRecordKeys::new(rfc_c_hs_secret())
  assert_eq(
    qv_hex(client.seal(tls_record_handshake, rfc_client_finished())),
    qv_hex(rfc_client_finished_record()),
  )
  // The client's application keys carry data at sequence 0, then close_notify at 1.
  let c_ap = TlsRecordKeys::new(rfc_c_ap_secret())
  assert_eq(
    qv_hex(c_ap.seal(tls_record_application_data, rfc_app_payload())),
    qv_hex(rfc_client_app_record()),
  )
  assert_eq(
    qv_hex(
      c_ap.seal(
        tls_record_alert,
        tls_encode_alert(tls_warning(tls_alert_close_notify)),
      ),
    ),
    qv_hex(rfc_client_alert_record()),
  )
  assert_eq(c_ap.seq(), 2UL)
}

///|
test "record: the sequence number advances one record at a time" {
  // RFC 8448 §3's server sends three records under its application traffic keys —
  // NewSessionTicket, application data, then close_notify — each numbered from where the
  // last left off, and each a different type inside the same application_data envelope.
  let keys = TlsRecordKeys::new(rfc_s_ap_secret())
  let (t0, c0) = keys.open(rfc_new_session_ticket_record()[:])
  assert_eq(t0, tls_record_handshake)
  assert_eq(qv_hex(c0), qv_hex(rfc_new_session_ticket()))
  assert_eq(keys.seq(), 1UL)
  let (t1, c1) = keys.open(rfc_server_app_record()[:])
  assert_eq(t1, tls_record_application_data)
  assert_eq(qv_hex(c1), qv_hex(rfc_app_payload()))
  assert_eq(keys.seq(), 2UL)
  let (t2, c2) = keys.open(rfc_server_alert_record()[:])
  assert_eq(t2, tls_record_alert)
  assert_eq(tls_decode_alert(c2[:]), Some(tls_warning(tls_alert_close_notify)))
  assert_eq(keys.seq(), 3UL)
}

///|
test "record: a record opened at the wrong sequence number fails the tag" {
  // The nonce carries the number, so a reader one record out of step cannot decrypt — which
  // is how the record layer notices a dropped, reordered or replayed record.
  let keys = TlsRecordKeys::new(rfc_s_ap_secret())
  // The application-data record belongs at sequence 1; offered at 0 it will not open.
  assert_eq(
    rec_refusal(() => keys.open(rfc_server_app_record()[:]) |> ignore),
    Some(tls_fatal(tls_alert_bad_record_mac)),
  )
  // In order it does, and the same record offered again at 2 does not.
  let _ = keys.open(rfc_new_session_ticket_record()[:])
  let _ = keys.open(rfc_server_app_record()[:])
  assert_eq(
    rec_refusal(() => keys.open(rfc_server_app_record()[:]) |> ignore),
    Some(tls_fatal(tls_alert_bad_record_mac)),
  )
}

///|
test "record: a key change restarts the sequence at zero" {
  // §5.3 — the IV survives a rekey, so a sequence number that carried over would repeat a
  // nonce under the new key.
  let keys = TlsRecordKeys::new(rfc_s_ap_secret())
  let _ = keys.seal(tls_record_application_data, b"qwq")
  let _ = keys.seal(tls_record_application_data, b"qwq")
  assert_eq(keys.seq(), 2UL)
  keys.rekey(rfc_c_ap_secret())
  assert_eq(keys.seq(), 0UL)
  assert_eq(qv_hex(keys.keys().key), "17422dda596ed5d9acd890e3c63f5051")
  assert_eq(qv_hex(keys.keys().iv), "5b78923dee08579033e523d9")
  // Back at zero under the client's keys, it produces the client's first record exactly.
  assert_eq(
    qv_hex(keys.seal(tls_record_application_data, rfc_app_payload())),
    qv_hex(rfc_client_app_record()),
  )
}

///|
test "record: a tampered record is a bad_record_mac" {
  // §5.2 makes an authentication failure fatal, and the sequence number does not move —
  // there is no next record for it to number.
  let keys = TlsRecordKeys::new(rfc_c_hs_secret())
  let flipped = rfc_client_finished_record().to_array()
  flipped[20] = (flipped[20].to_int() ^ 0x01).to_byte()
  assert_eq(
    rec_refusal(() => keys.open(Bytes::from_array(flipped)[:]) |> ignore),
    Some(tls_fatal(tls_alert_bad_record_mac)),
  )
  assert_eq(keys.seq(), 0UL)
  // The header is the additional data, so editing that fails the tag as surely.
  let header = rfc_client_finished_record().to_array()
  header[1] = b'\x02'
  assert_eq(
    rec_refusal(() => keys.open(Bytes::from_array(header)[:]) |> ignore),
    Some(tls_fatal(tls_alert_bad_record_mac)),
  )
  // Untouched, it opens.
  let (t, _) = keys.open(rfc_client_finished_record()[:])
  assert_eq(t, tls_record_handshake)
}

///|
test "record: padding hides the length without changing what arrives" {
  // §5.4 — the padding sits inside the AEAD, so it costs record length and nothing else.
  let write = TlsRecordKeys::new(rfc_c_ap_secret())
  let read = TlsRecordKeys::new(rfc_c_ap_secret())
  let plain = write.seal_padded(tls_record_application_data, b"hhh", 0)
  write.rekey(rfc_c_ap_secret())
  let padded = write.seal_padded(tls_record_application_data, b"hhh", 233)
  assert_eq(padded.length(), plain.length() + 233)
  let (t, content) = read.open(padded[:])
  assert_eq(t, tls_record_application_data)
  assert_eq(content, b"hhh")
}

///|
test "record: sealing refuses content past the fragment limit" {
  // §5.2 caps the content at the §5.1 fragment limit and the whole encrypted_record at
  // 2^14 + 256, so padding cannot be used to sail past it either.
  let keys = TlsRecordKeys::new(rfc_c_ap_secret())
  assert_eq(
    rec_refusal(() => {
      keys.seal(
        tls_record_application_data,
        Bytes::make(tls_record_max_fragment + 1, b'\x00'),
      )
      |> ignore
    }),
    Some(tls_fatal(tls_alert_record_overflow)),
  )
  assert_eq(
    rec_refusal(() => {
      keys.seal_padded(
        tls_record_application_data,
        Bytes::make(tls_record_max_fragment, b'\x00'),
        256,
      )
      |> ignore
    }),
    Some(tls_fatal(tls_alert_record_overflow)),
  )
  // Nothing went out, so nothing was numbered.
  assert_eq(keys.seq(), 0UL)
  // The largest record that does fit: 2^14 of content, the type octet, and the 16-byte tag.
  let ok = keys.seal(
    tls_record_application_data,
    Bytes::make(tls_record_max_fragment, b'\x00'),
  )
  assert_eq(ok.length(), tls_record_header_len + tls_record_max_fragment + 17)
  assert_eq(keys.seq(), 1UL)
}
