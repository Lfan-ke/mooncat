///|
test "AES-128-GCM matches NIST SP 800-38D Test Case 1 (empty, tag only)" {
  let key = Bytes::make(16, b'\x00')
  let nonce = Bytes::make(12, b'\x00')
  let packet = aes128_gcm_seal(key, nonce, b"", b"")
  assert_eq(qv_hex(packet), "58e2fccefa7e3061367f1d57a4e7455a")
  // Round-trips: open verifies the tag and yields the empty plaintext.
  match aes128_gcm_open(key, nonce, packet, b"") {
    Some(pt) => assert_eq(pt.length(), 0)
    None => fail("open should verify")
  }
}

///|
test "AES-128-GCM matches NIST Test Case 3 (one block, no AAD)" {
  let key = Bytes::make(16, b'\x00')
  let nonce = Bytes::make(12, b'\x00')
  let pt = Bytes::make(16, b'\x00')
  let packet = aes128_gcm_seal(key, nonce, pt, b"")
  assert_eq(
    qv_hex(packet),
    "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf",
  )
}

///|
test "AES-128-GCM matches NIST Test Case 4 (AAD, unaligned length)" {
  let key = qv_hexb("feffe9928665731c6d6a8f9467308308")
  let nonce = qv_hexb("cafebabefacedbaddecaf888")
  // 60-byte plaintext (3.75 blocks) forces the CTR and GHASH pad paths.
  let pt = qv_hexb(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
  )
  let aad = qv_hexb("feedfacedeadbeeffeedfacedeadbeefabaddad2")
  let packet = aes128_gcm_seal(key, nonce, pt, aad)
  assert_eq(
    qv_hex(packet),
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e0915bc94fbc3221a5db94fae95ae7121a47",
  )
  // Open with the correct AAD recovers the plaintext.
  match aes128_gcm_open(key, nonce, packet, aad) {
    Some(got) => assert_eq(qv_hex(got), qv_hex(pt))
    None => fail("open should verify")
  }
}

///|
test "AES-128-GCM open rejects a tampered tag" {
  let key = qv_hexb("feffe9928665731c6d6a8f9467308308")
  let nonce = qv_hexb("cafebabefacedbaddecaf888")
  let packet = aes128_gcm_seal(key, nonce, b"hello", qv_hexb("00"))
  // Flip the last byte of the tag; authentication must fail.
  let bad = Buffer()
  bad.write_bytes(packet[0:packet.length() - 1])
  bad.write_byte((packet[packet.length() - 1].to_int() ^ 0x01).to_byte())
  assert_eq(
    aes128_gcm_open(key, nonce, bad.to_bytes(), qv_hexb("00")) is None,
    true,
  )
  // Wrong AAD also fails.
  assert_eq(aes128_gcm_open(key, nonce, packet, qv_hexb("ff")) is None, true)
}
