///|
/// X25519 (RFC 7748) — the ECDHE curve TLS 1.3 and QUIC negotiate their
/// handshake keys over. Two parties scale the base point by their private
/// scalars, exchange the public points, and each scales the peer's point to
/// reach the same shared secret (§6.1).
///
///     moon run examples/07-x25519 --target native
#coverage.skip
fn main {
  let a_priv = hexb(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  let b_priv = hexb(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
  )
  let a_pub = @mooncat.x25519(a_priv, @mooncat.x25519_base())
  let b_pub = @mooncat.x25519(b_priv, @mooncat.x25519_base())
  println("a_pub  = \{hex(a_pub)}")
  println("b_pub  = \{hex(b_pub)}")
  let shared_a = @mooncat.x25519(a_priv, b_pub)
  let shared_b = @mooncat.x25519(b_priv, a_pub)
  println("shared = \{hex(shared_a)}")
  println("both sides agree = \{shared_a == shared_b}")
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
