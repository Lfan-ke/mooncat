///|
/// Base64 (RFC 4648) — the transfer coding the WebSocket accept key and PEM
/// certificates ride on. The §10 vectors encode across every input remainder,
/// and decode is shown to invert encode.
///
///     moon run examples/05-base64 --target native
#coverage.skip
fn main {
  for s in [b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
    let enc = @mooncat.base64_encode(s)
    let back = @mooncat.base64_decode(enc)
    println("\{pad(ascii(s))} -> \{pad(ascii(enc))}  round-trip=\{back == s}")
  }
}

///|
/// Interpret an ASCII byte string as text.
fn ascii(b : Bytes) -> String {
  let sb = StringBuilder::new()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(b[i].to_int().unsafe_to_char())
  }
  sb.to_string()
}

///|
/// Right-pad to a fixed width so the arrows line up.
fn pad(s : String) -> String {
  let sb = StringBuilder::new()
  sb.write_string(s)
  for _i = s.length(); _i < 8; _i = _i + 1 {
    sb.write_char(' ')
  }
  sb.to_string()
}
