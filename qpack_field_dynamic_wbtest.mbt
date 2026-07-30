// Decoding QPACK field sections that reference the dynamic table (RFC 9204 §4.5.2–§4.5.5).

///|
/// A dynamic table holding two entries: absolute index 0 = (":authority",
/// "www.example.com"), absolute index 1 = ("custom-key", "custom-value").
fn dyn_table_two() -> QpackDynamicTable {
  let t = QpackDynamicTable::new(4096)
  let _ = t.insert(b":authority", b"www.example.com")
  let _ = t.insert(b"custom-key", b"custom-value")
  t
}

///|
/// Assemble a field section from a prefix and a run of field-line byte fragments.
fn field_section(prefix : Bytes, lines : Array[Bytes]) -> Bytes {
  let buf = Buffer()
  buf.write_bytes(prefix)
  for line in lines {
    buf.write_bytes(line)
  }
  buf.to_bytes()
}

///|
test "dynamic field: indexed lines by relative index (Base above the entries)" {
  let t = dyn_table_two()
  // Required Insert Count 2, Base 2: relative index 0 -> absolute 1, relative 1 -> 0.
  let prefix = qpack_encode_section_prefix(2, 2, 128)
  let wire = field_section(prefix, [
    qpack_int_encode(0, 6, 0x80), // Indexed, T=0 (dynamic), relative 0
    qpack_int_encode(1, 6, 0x80), // Indexed, T=0 (dynamic), relative 1
  ])
  assert_eq(qpack_decode_field_section_dyn(wire, t, 128), [
    ("custom-key", "custom-value"),
    (":authority", "www.example.com"),
  ])
}

///|
test "dynamic field: indexed lines by post-base index (Base below the entries)" {
  let t = dyn_table_two()
  // Base 0: post-base index 0 -> absolute 0, post-base index 1 -> absolute 1.
  let prefix = qpack_encode_section_prefix(2, 0, 128)
  let wire = field_section(prefix, [
    qpack_int_encode(0, 4, 0x10), // Indexed With Post-Base Index 0
    qpack_int_encode(1, 4, 0x10), // Indexed With Post-Base Index 1
  ])
  assert_eq(qpack_decode_field_section_dyn(wire, t, 128), [
    (":authority", "www.example.com"),
    ("custom-key", "custom-value"),
  ])
}

///|
test "dynamic field: literal with a dynamic name reference" {
  let t = dyn_table_two()
  let prefix = qpack_encode_section_prefix(2, 2, 128)
  // Literal With Name Reference, T=0, relative index 1 -> name at absolute 0 (":authority").
  let name_ref = qpack_int_encode(1, 4, 0x40)
  let value = qpack_encode_string(b"example.org", 7, 0, false)
  let wire = field_section(prefix, [name_ref, value])
  assert_eq(qpack_decode_field_section_dyn(wire, t, 128), [
    (":authority", "example.org"),
  ])
}

///|
test "dynamic field: literal with a post-base name reference" {
  let t = dyn_table_two()
  let prefix = qpack_encode_section_prefix(2, 0, 128)
  // Post-Base Name Reference, post-base index 0 -> name at absolute 0 (":authority").
  let name_ref = qpack_int_encode(0, 3, 0x00)
  let value = qpack_encode_string(b"v", 7, 0, false)
  let wire = field_section(prefix, [name_ref, value])
  assert_eq(qpack_decode_field_section_dyn(wire, t, 128), [(":authority", "v")])
}

///|
test "dynamic field: static and dynamic references mixed in one section" {
  let t = dyn_table_two()
  let prefix = qpack_encode_section_prefix(2, 2, 128)
  let wire = field_section(prefix, [
    qpack_int_encode(1, 6, 0xc0), // Indexed static, index 1 = (":path", "/")
    qpack_int_encode(0, 6, 0x80), // Indexed dynamic, relative 0 = ("custom-key", ...)
  ])
  assert_eq(qpack_decode_field_section_dyn(wire, t, 128), [
    (":path", "/"),
    ("custom-key", "custom-value"),
  ])
}
