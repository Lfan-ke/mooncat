// Decoding a QPACK field section that references the dynamic table (RFC 9204 §4.5). The
// static-only decoder in qpack_field.mbt handles the representations that need no table
// state; this one reads the full section prefix (Required Insert Count and Base) and then
// resolves every representation, including the four that address the dynamic table: an
// indexed line by relative index (§4.5.2, T=0) or post-base index (§4.5.3), and a literal
// line whose name comes from a dynamic entry by relative (§4.5.4, T=0) or post-base
// (§4.5.5) index. A field-line relative index counts back from Base — index 0 is the entry
// at absolute index Base-1 (§3.2.6) — while a post-base index counts up from Base. This is
// the decode path a server uses to read a peer's dynamically indexed headers.

///|
/// The dynamic entry a field-line relative index selects: absolute index `base - 1 - rel`
/// (RFC 9204 §3.2.6), decoded to strings.
fn qpack_dyn_relative(
  table : QpackDynamicTable,
  base : Int,
  rel : Int,
) -> (String, String) raise QpackError {
  match table.get(base - 1 - rel) {
    Some((n, v)) => (@utf8.decode_lossy(n[:]), @utf8.decode_lossy(v[:]))
    None =>
      raise QpackError(
        "QPACK dynamic relative index out of range: " + rel.to_string(),
      )
  }
}

///|
/// The dynamic entry a post-base index selects: absolute index `base + post` (RFC 9204
/// §3.2.6), decoded to strings.
fn qpack_dyn_postbase(
  table : QpackDynamicTable,
  base : Int,
  post : Int,
) -> (String, String) raise QpackError {
  match table.get(base + post) {
    Some((n, v)) => (@utf8.decode_lossy(n[:]), @utf8.decode_lossy(v[:]))
    None =>
      raise QpackError(
        "QPACK post-base index out of range: " + post.to_string(),
      )
  }
}

///|
/// Decode a QPACK field section that may reference the dynamic `table`, given `max_entries`
/// (from the negotiated maximum table capacity). Reads the section prefix, then every field
/// line — static or dynamic, indexed or literal, pre- or post-base — into the header list.
/// Raises if a reference is out of range or the section is malformed.
pub fn qpack_decode_field_section_dyn(
  input : Bytes,
  table : QpackDynamicTable,
  max_entries : Int,
) -> Array[(String, String)] raise QpackError {
  let view = input[:]
  let (_ric, base, prefix_len) = match
    qpack_decode_section_prefix(view, max_entries, table.insert_count) {
    Some(v) => v
    None => raise QpackError("truncated field section prefix")
  }
  let headers : Array[(String, String)] = []
  let mut off = prefix_len
  while off < view.length() {
    let b0 = view[off].to_int()
    if (b0 & 0x80) != 0 {
      // Indexed Field Line (§4.5.2): T at bit 6 (1 = static).
      let is_static = (b0 & 0x40) != 0
      let (index, consumed) = qpack_decode_int_at(view, off, 6)
      headers.push(
        if is_static {
          qpack_static_entry(index)
        } else {
          qpack_dyn_relative(table, base, index)
        },
      )
      off += consumed
    } else if (b0 & 0x40) != 0 {
      // Literal Field Line With Name Reference (§4.5.4): T at bit 4.
      let is_static = (b0 & 0x10) != 0
      let (index, name_consumed) = qpack_decode_int_at(view, off, 4)
      let name = if is_static {
        qpack_static_entry(index).0
      } else {
        qpack_dyn_relative(table, base, index).0
      }
      off += name_consumed
      let (value, value_consumed) = qpack_decode_string_at(view, off, 7)
      headers.push((name, @utf8.decode_lossy(value[:])))
      off += value_consumed
    } else if (b0 & 0x20) != 0 {
      // Literal Field Line With Literal Name (§4.5.6).
      let (name, name_consumed) = qpack_decode_string_at(view, off, 3)
      off += name_consumed
      let (value, value_consumed) = qpack_decode_string_at(view, off, 7)
      headers.push((@utf8.decode_lossy(name[:]), @utf8.decode_lossy(value[:])))
      off += value_consumed
    } else if (b0 & 0x10) != 0 {
      // Indexed Field Line With Post-Base Index (§4.5.3): `0001` + index (4-bit prefix).
      let (index, consumed) = qpack_decode_int_at(view, off, 4)
      headers.push(qpack_dyn_postbase(table, base, index))
      off += consumed
    } else {
      // Literal Field Line With Post-Base Name Reference (§4.5.5): `0000 N` + name index
      // (3-bit prefix), then the value.
      let (index, name_consumed) = qpack_decode_int_at(view, off, 3)
      let name = qpack_dyn_postbase(table, base, index).0
      off += name_consumed
      let (value, value_consumed) = qpack_decode_string_at(view, off, 7)
      headers.push((name, @utf8.decode_lossy(value[:])))
      off += value_consumed
    }
  }
  headers
}
