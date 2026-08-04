///|
/// HKDF (RFC 5869) — the extract-and-expand key derivation the TLS 1.3 and QUIC
/// key schedules are built on. The §A.1 vectors extract a PRK and expand 42
/// octets; `hkdf_expand_label` is the TLS 1.3 / QUIC labelled form (RFC 8446
/// §7.1) that wraps the label into an HkdfLabel structure.
///
///     moon run examples/04-hkdf --target native
#coverage.skip
fn main {
  let ikm = hexb("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
  let salt = hexb("000102030405060708090a0b0c")
  let info = hexb("f0f1f2f3f4f5f6f7f8f9")
  let prk = @mooncat.hkdf_extract(salt, ikm)
  println("prk (extract)          = \{hex(prk)}")
  let okm = @mooncat.hkdf_expand(prk, info, 42)
  println("okm (expand 42)        = \{hex(okm)}")
  let secret = @mooncat.sha256(b"heke1228")
  let k = @mooncat.hkdf_expand_label(secret, b"quic key", b"", 16)
  let iv = @mooncat.hkdf_expand_label(secret, b"quic iv", b"", 12)
  println("expand_label(quic key) = \{hex(k)}")
  println("expand_label(quic iv)  = \{hex(iv)}")
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
