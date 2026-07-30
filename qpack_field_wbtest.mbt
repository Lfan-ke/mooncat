// QPACK field-section vectors (RFC 9204 §4.5): a byte-exact indexed encoding, and
// round-trips through every representation (indexed static, static name reference,
// fully literal) both raw and Huffman-coded. Dynamic-table references are rejected.

///|
test "qpack field: an exact static match encodes as an indexed field line" {
  // Prefix (insert count 0, base 0) = 00 00; :method GET is static index 17, so the
  // indexed field line is 0xC0 | 17 = 0xD1.
  assert_eq(
    qpack_encode_field_section([(":method", "GET")], huffman=false),
    b"\x00\x00\xd1",
  )
}

///|
test "qpack field: round-trip through all three representations (raw)" {
  let headers = [
    (":method", "GET"), // indexed static
    (":path", "/index.html"), // static name (:path), literal value
    (":scheme", "https"), // indexed static
    (":status", "200"), // indexed static
    ("x-custom-header", "custom-value"), // literal name and value
    ("content-type", "application/json"), // indexed static
  ]
  let encoded = qpack_encode_field_section(headers, huffman=false)
  assert_eq(qpack_decode_field_section(encoded), headers)
}

///|
test "qpack field: round-trip Huffman-coded" {
  let headers = [
    (":authority", "www.example.com"),
    ("user-agent", "Mozilla/5.0 (compatible)"),
    ("accept", "text/html,application/xhtml+xml"),
  ]
  let encoded = qpack_encode_field_section(headers, huffman=true)
  // A Huffman-coded body is strictly smaller than the raw one for these values.
  let raw = qpack_encode_field_section(headers, huffman=false)
  assert_eq(encoded.length() < raw.length(), true)
  assert_eq(qpack_decode_field_section(encoded), headers)
}

///|
test "qpack field: a static name reference with a novel value round-trips" {
  // :status is a static name (index 24) but 599 is not a static value.
  let headers = [(":status", "599")]
  assert_eq(
    qpack_decode_field_section(
      qpack_encode_field_section(headers, huffman=false),
    ),
    headers,
  )
  assert_eq(
    qpack_decode_field_section(
      qpack_encode_field_section(headers, huffman=true),
    ),
    headers,
  )
}

///|
test "qpack field: an empty field section is just the prefix" {
  let encoded = qpack_encode_field_section([], huffman=false)
  assert_eq(encoded, b"\x00\x00")
  assert_eq(qpack_decode_field_section(encoded), [])
}

///|
test "qpack field: string literal H bit selects Huffman on decode" {
  // Encode one value both ways; the raw one keeps its bytes, the Huffman one is decoded
  // back through the shared RFC 7541 table.
  let raw = qpack_encode_string(b"hello", 7, 0, false)
  let huff = qpack_encode_string(b"hello", 7, 0, true)
  match qpack_decode_string(raw[:], 7) {
    Some((data, _)) => assert_eq(data, b"hello")
    None => abort("expected a complete string")
  }
  match qpack_decode_string(huff[:], 7) {
    Some((data, _)) => assert_eq(data, b"hello")
    None => abort("expected a complete string")
  }
}

///|
test "qpack field: a dynamic-table reference is rejected" {
  // 0x80 with T=0 (bit 6 clear) is an indexed field line into the dynamic table.
  let rejected = try {
    let _ = qpack_decode_field_section(b"\x00\x00\x80")
    false
  } catch {
    _ => true
  }
  assert_eq(rejected, true)
}
