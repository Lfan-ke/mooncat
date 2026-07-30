// ASN.1 DER encoding (X.690), byte-exact against the standard's rules.

///|
test "der: length uses the short form under 128 and the long form above (X.690 §8.1.3)" {
  assert_eq(der_length(0), b"\x00")
  assert_eq(der_length(127), b"\x7f")
  assert_eq(der_length(128), b"\x81\x80")
  assert_eq(der_length(255), b"\x81\xff")
  assert_eq(der_length(256), b"\x82\x01\x00")
  assert_eq(der_length(300), b"\x82\x01\x2c")
}

///|
test "der: INTEGER strips leading zeros and keeps the sign bit clear (X.690 §8.3)" {
  assert_eq(der_integer(b""), b"\x02\x01\x00")
  assert_eq(der_integer(b"\x2a"), b"\x02\x01\x2a")
  assert_eq(der_integer(b"\x00\x00\x2a"), b"\x02\x01\x2a") // redundant zeros stripped
  assert_eq(der_integer(b"\x80"), b"\x02\x02\x00\x80") // sign bit → prepend 0x00
  assert_eq(der_integer(b"\x01\x00"), b"\x02\x02\x01\x00")
}

///|
test "der: OBJECT IDENTIFIER packs the first two arcs and base-128s the rest (X.690 §8.19)" {
  // 1.2.840.113549.1.1.1 (rsaEncryption): 2a 86 48 86 f7 0d 01 01 01.
  assert_eq(
    der_oid([1, 2, 840, 113549, 1, 1, 1]),
    b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01",
  )
  // 1.2.840.10045.4.3.2 (ecdsa-with-SHA256): 2a 86 48 ce 3d 04 03 02.
  assert_eq(
    der_oid([1, 2, 840, 10045, 4, 3, 2]),
    b"\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02",
  )
}

///|
test "der: BIT STRING, NULL, and SEQUENCE compose canonically" {
  assert_eq(der_bit_string(b"\xde\xad"), b"\x03\x03\x00\xde\xad")
  assert_eq(der_null(), b"\x05\x00")
  assert_eq(der_octet_string(b"\xca\xfe"), b"\x04\x02\xca\xfe")
  // SEQUENCE { INTEGER 1, NULL }.
  assert_eq(
    der_sequence([der_integer(b"\x01"), der_null()]),
    b"\x30\x05\x02\x01\x01\x05\x00",
  )
  // A context [0] EXPLICIT wrapping INTEGER 2 (the X.509 version field).
  assert_eq(der_explicit(0, der_integer(b"\x02")), b"\xa0\x03\x02\x01\x02")
}
