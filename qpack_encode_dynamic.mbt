// A QPACK encoder that indexes into the dynamic table (RFC 9204 §2.1, §4.5). It pairs the
// two outputs a real encoder produces: the encoder-stream instructions that populate the
// decoder's dynamic table, and the field section that references those entries. The strategy
// here is the simple, always-index one the RFC permits: a header that matches the static
// table exactly is referenced there directly; otherwise the entry is inserted into the
// dynamic table (with a static name reference when the name is known, else a literal name)
// and the field line references it by relative index. An entry too large for the table falls
// back to a literal field line. Sections use Base = the post-insertion insert count, so every
// dynamic reference is a pre-Base relative index. This closes the loop with the dynamic
// decoder: apply the instructions to a peer table, then decode the section against it.

///|
/// How a single header is rendered in the field section.
priv enum QpackFieldRef {
  RefStatic(Int)
  RefDynamic(Int) // absolute index in the dynamic table
  RefLiteral(Bytes, Bytes)
}

///|
/// Encode `headers` with dynamic indexing over `table` (the encoder's view, mutated by the
/// inserts). Returns the encoder-stream instruction block and the field section. `max_entries`
/// comes from the negotiated maximum table capacity.
pub fn qpack_encode_dynamic(
  headers : Array[(String, String)],
  table : QpackDynamicTable,
  max_entries : Int,
  huffman? : Bool = true,
) -> (Bytes, Bytes) {
  let instr = Buffer()
  let refs : Array[QpackFieldRef] = []
  for header in headers {
    let (name, value) = header
    match qpack_static_find(name, value) {
      Some(index) => refs.push(RefStatic(index))
      None => {
        let name_bytes = @utf8.encode(name)
        let value_bytes = @utf8.encode(value)
        if qpack_entry_size(name_bytes, value_bytes) <= table.capacity {
          let inst = match qpack_static_find_name(name) {
            Some(name_index) =>
              InsertNameRef(is_static=true, index=name_index, value=value_bytes)
            None => InsertLiteralName(name=name_bytes, value=value_bytes)
          }
          instr.write_bytes(qpack_encode_encoder_inst(inst, huffman~))
          // apply cannot raise here: the name index (if any) is a valid static entry and
          // the value fits the capacity.
          let _ = table.apply(inst) catch { _ => false }
          refs.push(RefDynamic(table.insert_count - 1))
        } else {
          refs.push(RefLiteral(name_bytes, value_bytes))
        }
      }
    }
  }
  let base = table.insert_count
  let section = Buffer()
  section.write_bytes(qpack_encode_section_prefix(base, base, max_entries))
  for r in refs {
    match r {
      RefStatic(index) => section.write_bytes(qpack_int_encode(index, 6, 0xc0))
      RefDynamic(abs) =>
        section.write_bytes(qpack_int_encode(base - 1 - abs, 6, 0x80))
      RefLiteral(name, value) => {
        section.write_bytes(qpack_encode_string(name, 3, 0x20, huffman))
        section.write_bytes(qpack_encode_string(value, 7, 0, huffman))
      }
    }
  }
  (instr.to_bytes(), section.to_bytes())
}
