// The dynamic QPACK encoder, round-tripped against the dynamic decoder: the instruction
// stream populates a peer's table and the field section decodes back to the original headers.

///|
/// Apply a whole encoder-stream instruction block to `table`.
fn apply_encoder_stream(
  table : QpackDynamicTable,
  instructions : Bytes,
) -> Unit raise QpackError {
  let view = instructions[:]
  let mut off = 0
  while off < instructions.length() {
    match qpack_decode_encoder_inst(view[off:]) {
      Some((inst, consumed)) => {
        let _ = table.apply(inst)
        off = off + consumed
      }
      None => abort("truncated encoder stream")
    }
  }
}

///|
test "dynamic encode: round-trips through the dynamic decoder (raw and Huffman)" {
  let headers = [
    (":authority", "www.example.com"),
    ("custom-key", "custom-value"),
    (":path", "/"),
    ("x-foo", "bar"),
  ]
  for huff in [false, true] {
    let enc_table = QpackDynamicTable::new(4096)
    let (instructions, section) = qpack_encode_dynamic(
      headers,
      enc_table,
      128,
      huffman=huff,
    )
    // The three non-static-exact headers were indexed into the dynamic table; ":path: /"
    // matched the static table and was not.
    assert_eq(enc_table.insert_count, 3)
    let dec_table = QpackDynamicTable::new(4096)
    apply_encoder_stream(dec_table, instructions)
    assert_eq(qpack_decode_field_section_dyn(section, dec_table, 128), headers)
  }
}

///|
test "dynamic encode: an entry too large for the table falls back to a literal line" {
  let headers = [("x-long-name", "a fairly long value here")]
  let enc = QpackDynamicTable::new(40) // 11 + 24 + 32 = 67 > 40, cannot index
  let (instructions, section) = qpack_encode_dynamic(
    headers,
    enc,
    1,
    huffman=false,
  )
  assert_eq(enc.insert_count, 0)
  assert_eq(instructions.length(), 0)
  let dec = QpackDynamicTable::new(40)
  assert_eq(qpack_decode_field_section_dyn(section, dec, 1), headers)
}
