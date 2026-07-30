// QPACK prefixed-integer vectors, taken from RFC 7541 Appendix C.1 (the encoding QPACK
// adopts): the encoder's bytes are checked exactly, and each round-trips back.

///|
test "qpack int: RFC 7541 C.1 canonical vectors" {
  // C.1.1: 10 with a 5-bit prefix fits in the first byte.
  assert_eq(qpack_int_encode(10, 5, 0), b"\x0a")
  // C.1.2: 1337 with a 5-bit prefix spills over two continuation bytes.
  assert_eq(qpack_int_encode(1337, 5, 0), b"\x1f\x9a\x0a")
  // C.1.3: 42 with an 8-bit prefix fits in the first byte.
  assert_eq(qpack_int_encode(42, 8, 0), b"\x2a")
}

///|
test "qpack int: flags occupy the high bits, decode ignores them" {
  // A 6-bit prefix with the 0x80 pattern bit set (e.g. an indexed field line).
  let encoded = qpack_int_encode(2, 6, 0x80)
  assert_eq(encoded, b"\x82")
  // Decoding reads the low 6 bits and ignores the flags.
  assert_eq(qpack_int_decode(encoded[:], 6), Some((2, 1)))
}

///|
test "qpack int: decode C.1 vectors and boundary round-trips" {
  assert_eq(qpack_int_decode(b"\x0a"[:], 5), Some((10, 1)))
  assert_eq(qpack_int_decode(b"\x1f\x9a\x0a"[:], 5), Some((1337, 3)))
  assert_eq(qpack_int_decode(b"\x2a"[:], 8), Some((42, 1)))
  // The all-ones prefix value (31) needs one continuation byte holding 0.
  assert_eq(qpack_int_encode(31, 5, 0), b"\x1f\x00")
  assert_eq(qpack_int_decode(b"\x1f\x00"[:], 5), Some((31, 2)))
}

///|
test "qpack int: round-trips across prefix sizes and magnitudes" {
  let values = [0, 1, 30, 31, 32, 127, 128, 255, 256, 16383, 16384, 1000000]
  for bits = 1; bits <= 8; bits = bits + 1 {
    for v in values {
      let encoded = qpack_int_encode(v, bits, 0)
      match qpack_int_decode(encoded[:], bits) {
        Some((decoded, consumed)) => {
          assert_eq(decoded, v)
          assert_eq(consumed, encoded.length())
        }
        None => abort("expected a complete integer")
      }
    }
  }
}

///|
test "qpack int: a truncated continuation yields None" {
  // 0x1f says "prefix overflowed"; the continuation byte 0x9a has its high bit set,
  // so another byte is required but absent.
  assert_eq(qpack_int_decode(b"\x1f\x9a"[:], 5), None)
  assert_eq(qpack_int_decode(b""[:], 5), None)
}
