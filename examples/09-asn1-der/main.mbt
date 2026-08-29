///|
/// ASN.1 Distinguished Encoding Rules (X.690) — the tag-length-value byte layer
/// X.509 certificates are assembled on. Each builder emits the canonical minimal
/// encoding; the outputs are shown as hex against the standard's own examples.
///
///     moon run examples/09-asn1-der --target native
#coverage.skip
fn main {
  // Definite length: short form under 128, long form above (X.690 §8.1.3).
  println("length(127)      = \{hex(@mooncat.der_length(127))}")
  println("length(300)      = \{hex(@mooncat.der_length(300))}")
  // INTEGER strips leading zeros and keeps the sign bit clear (§8.3).
  println("integer(0x80)    = \{hex(@mooncat.der_integer(b"\x80"))}")
  // OBJECT IDENTIFIER packs the first two arcs (§8.19): ecdsa-with-SHA256.
  println(
    "oid ecdsa-sha256 = \{hex(@mooncat.der_oid([1, 2, 840, 10045, 4, 3, 2]))}",
  )
  println("null             = \{hex(@mooncat.der_null())}")
  println("octet_string     = \{hex(@mooncat.der_octet_string(b"\xca\xfe"))}")
  println("bit_string       = \{hex(@mooncat.der_bit_string(b"\xde\xad"))}")
  println("utf8_string      = \{hex(@mooncat.der_utf8_string("lfanke"))}")
  println("utc_time         = \{hex(@mooncat.der_utc_time("250101000000Z"))}")
  // SEQUENCE { INTEGER 1, NULL } composes its members.
  let seq = @mooncat.der_sequence([
    @mooncat.der_integer(b"\x01"),
    @mooncat.der_null(),
  ])
  println("sequence         = \{hex(seq)}")
  // A context [0] EXPLICIT wrapping INTEGER 2 (the X.509 version field).
  println(
    "explicit [0]     = \{hex(@mooncat.der_explicit(0, @mooncat.der_integer(b"\x02")))}",
  )
  println(
    "set              = \{hex(@mooncat.der_set([@mooncat.der_utf8_string("x")]))}",
  )
}

///|
fn hex(b : Bytes) -> String {
  let digits = "0123456789abcdef"
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let x = b[i].to_int()
    sb.write_char(digits[x >> 4].unsafe_to_char())
    sb.write_char(digits[x & 0xf].unsafe_to_char())
  }
  sb.to_string()
}
