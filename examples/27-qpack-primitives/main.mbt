///|
/// QPACK primitives (RFC 9204): the 99-entry static table with exact and
/// name-only lookups (Appendix A), the RFC 7541 prefixed-integer coding, and the
/// string literal coding raw and Huffman — the building blocks the field-section
/// encoder is assembled from.
///
///     moon run examples/27-qpack-primitives --target native
#coverage.skip
fn main {
  run() catch {
    e => println("qpack error: \{e}")
  }
}

///|
fn run() -> Unit raise {
  println("static table entries = \{@mooncat.qpack_static_len()}")
  println(
    "get(17)  = \{pair(@mooncat.qpack_static_get(17))} (expect :method GET)",
  )
  println(
    "find(:method, GET)   = \{opt_i(@mooncat.qpack_static_find(":method", "GET"))}",
  )
  println(
    "find_name(:status)   = \{opt_i(@mooncat.qpack_static_find_name(":status"))}",
  )
  println(
    "max_entries(4096)=\{@mooncat.qpack_max_entries(4096)} entry_size(:method,GET)=\{@mooncat.qpack_entry_size(b":method", b"GET")}",
  )
  let enc = @mooncat.qpack_int_encode(1337, 5, 0)
  println("int 1337 (5-bit prefix) = \{hex(enc)}")
  match @mooncat.qpack_int_decode(enc[:], 5) {
    Some((v, n)) => println("decoded = \{v} in \{n} bytes")
    None => println("truncated")
  }
  let raw = @mooncat.qpack_encode_string(b"hello", 7, 0, false)
  let huff = @mooncat.qpack_encode_string(b"hello", 7, 0, true)
  println(
    "string \"hello\": raw=\{raw.length()} huffman=\{huff.length()} bytes (huffman shorter=\{huff.length() < raw.length()})",
  )
  match @mooncat.qpack_decode_string(huff[:], 7) {
    Some((d, _)) => println("huffman decoded = \{ascii(d)}")
    None => println("bad string")
  }
}

///|
fn pair(o : (String, String)?) -> String {
  match o {
    Some((n, v)) => n + " " + v
    None => "(none)"
  }
}

///|
fn opt_i(o : Int?) -> String {
  match o {
    Some(n) => n.to_string()
    None => "(none)"
  }
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
