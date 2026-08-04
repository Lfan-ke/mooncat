///|
/// AES-128 (FIPS-197) and AES-128-GCM (NIST SP 800-38D) — the AEAD under TLS 1.3
/// records and QUIC packet protection. The block cipher matches the FIPS-197
/// known answer; GCM seals a message then opens it (authenticating the tag and
/// AAD), and tampering with the AAD is refused.
///
///     moon run examples/06-aes-gcm --target native
#coverage.skip
fn main {
  let key = hexb("000102030405060708090a0b0c0d0e0f")
  let pt = hexb("00112233445566778899aabbccddeeff")
  let sched = @mooncat.aes128_key_schedule(key)
  println("aes128 block = \{hex(@mooncat.aes128_encrypt_block(sched, pt))}")

  let gkey = hexb("feffe9928665731c6d6a8f9467308308")
  let nonce = hexb("cafebabefacedbaddecaf888")
  let msg = b"hello heke1228"
  let aad = hexb("feedfacedeadbeef")
  let packet = @mooncat.aes128_gcm_seal(gkey, nonce, msg, aad)
  println("gcm sealed   = \{hex(packet)}")
  match @mooncat.aes128_gcm_open(gkey, nonce, packet, aad) {
    Some(got) =>
      println("gcm opened   = \{ascii(got)}  authentic=\{got == msg}")
    None => println("gcm open failed")
  }
  let forged = @mooncat.aes128_gcm_open(gkey, nonce, packet, hexb("00"))
  println("tampered aad rejected = \{forged is None}")
}

///|
fn hex(b : Bytes) -> String {
  let digits = "0123456789abcdef"
  let sb = StringBuilder::new()
  for i = 0; i < b.length(); i = i + 1 {
    let x = b[i].to_int()
    sb.write_char(digits[x >> 4].unsafe_to_char())
    sb.write_char(digits[x & 0xf].unsafe_to_char())
  }
  sb.to_string()
}

///|
fn ascii(b : Bytes) -> String {
  let sb = StringBuilder::new()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(b[i].to_int().unsafe_to_char())
  }
  sb.to_string()
}

///|
fn hexb(h : String) -> Bytes {
  let buf = Buffer()
  for i = 0; i < h.length(); i = i + 2 {
    buf.write_byte(
      ((nib(h[i].to_int()) << 4) | nib(h[i + 1].to_int())).to_byte(),
    )
  }
  buf.to_bytes()
}

///|
fn nib(c : Int) -> Int {
  if c >= 0x30 && c <= 0x39 {
    c - 0x30
  } else if c >= 0x61 && c <= 0x66 {
    c - 0x61 + 10
  } else {
    0
  }
}
