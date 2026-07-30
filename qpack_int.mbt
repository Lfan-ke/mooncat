// QPACK's prefixed-integer codec (RFC 9204 §4.1.1, which adopts RFC 7541 §5.1): an
// integer is carried in the low N bits of the first byte, with the representation's
// pattern flags in the high bits; a value that does not fit in N bits sets those bits
// to all-ones and spills the remainder over continuation bytes, 7 bits each. This is
// the arithmetic every QPACK field-line representation is built from — an index, a
// string length, the field-section prefix's insert count and base.

///|
/// A malformed QPACK encoding.
pub suberror QpackError {
  QpackError(String)
}

///|
/// Encode `value` as an RFC 7541 §5.1 `prefix_bits`-prefix integer, OR-ing `flags` into
/// the high `8 - prefix_bits` bits of the first byte (the representation's pattern).
pub fn qpack_int_encode(value : Int, prefix_bits : Int, flags : Int) -> Bytes {
  let buf = Buffer()
  let max_prefix = (1 << prefix_bits) - 1
  if value < max_prefix {
    buf.write_byte((flags | value).to_byte())
  } else {
    buf.write_byte((flags | max_prefix).to_byte())
    let mut remainder = value - max_prefix
    while remainder >= 128 {
      buf.write_byte((remainder % 128 + 128).to_byte())
      remainder = remainder / 128
    }
    buf.write_byte(remainder.to_byte())
  }
  buf.to_bytes()
}

///|
/// Decode an RFC 7541 §5.1 `prefix_bits`-prefix integer from the front of `input` (its
/// first byte holds the value in its low `prefix_bits`, any flags in the high bits are
/// ignored). Returns `(value, bytes-consumed)`, or `None` when a continuation byte has
/// not yet arrived (a partial read).
pub fn qpack_int_decode(input : BytesView, prefix_bits : Int) -> (Int, Int)? {
  if input.length() == 0 {
    return None
  }
  let max_prefix = (1 << prefix_bits) - 1
  let mut value = input[0].to_int() & max_prefix
  if value < max_prefix {
    return Some((value, 1))
  }
  let mut shift = 0
  let mut off = 1
  for ;; {
    if off >= input.length() {
      return None
    }
    let b = input[off].to_int()
    value = value + ((b & 127) << shift)
    shift = shift + 7
    off = off + 1
    if (b & 128) == 0 {
      break
    }
  }
  Some((value, off))
}
