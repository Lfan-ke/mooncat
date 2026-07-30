// QPACK field-line encoding (RFC 9204 §4.5): a field section is an encoded-field-
// section prefix followed by a run of field lines, each a header rendered as an indexed
// reference into the static table, a literal value with a static name reference, or a
// fully literal name and value. Strings carry an H bit selecting Huffman coding (RFC
// 7541 Appendix B, the same table HPACK uses — reused from moonrpc). This encoder never
// uses the dynamic table, so it emits a zero insert-count prefix and only static/literal
// representations, which is a complete and interoperable QPACK encoder (RFC 9204 §2.1
// permits an encoder to never index dynamically). The decoder reads those back; a field
// line that references the dynamic table is reported as unsupported (that layer is
// built separately).

///|
/// A malformed or unsupported QPACK field section.
pub suberror QpackError {
  QpackError(String)
}

///|
/// Encode a QPACK string literal: the `H` bit at position `prefix_bits` (set when the
/// data is Huffman-coded), `pattern` in the bits above it, the octet length as a
/// `prefix_bits`-prefix integer, then the (raw or Huffman) octets.
pub fn qpack_encode_string(
  data : Bytes,
  prefix_bits : Int,
  pattern : Int,
  huffman : Bool,
) -> Bytes {
  let payload = if huffman { @moonrpc.huffman_encode(data) } else { data }
  let h_bit = if huffman { 1 << prefix_bits } else { 0 }
  let buf = Buffer()
  buf.write_bytes(
    qpack_int_encode(payload.length(), prefix_bits, pattern | h_bit),
  )
  buf.write_bytes(payload)
  buf.to_bytes()
}

///|
/// Decode a QPACK string literal whose length uses a `prefix_bits`-prefix integer and
/// whose `H` bit sits at position `prefix_bits`. Returns `(octets, bytes-consumed)`, or
/// `None` when the string has not fully arrived.
pub fn qpack_decode_string(
  input : BytesView,
  prefix_bits : Int,
) -> (Bytes, Int)? raise QpackError {
  if input.length() == 0 {
    return None
  }
  let huffman = ((input[0].to_int() >> prefix_bits) & 1) == 1
  let (length, len_consumed) = match qpack_int_decode(input, prefix_bits) {
    Some(v) => v
    None => return None
  }
  if input.length() < len_consumed + length {
    return None
  }
  let raw = input[len_consumed:len_consumed + length].to_owned()
  let data = if huffman {
    @moonrpc.huffman_decode(raw) catch {
      e => raise QpackError("huffman decode: " + e.to_string())
    }
  } else {
    raw
  }
  Some((data, len_consumed + length))
}

///|
/// Encode a header list as a QPACK field section over the static table only: a
/// zero-insert-count / zero-base prefix, then one field line per header — an indexed
/// static entry for an exact match, a static name reference plus a literal value when
/// the name is known, or a fully literal name and value otherwise. `huffman` chooses
/// whether literal strings are Huffman-coded.
pub fn qpack_encode_field_section(
  headers : Array[(String, String)],
  huffman? : Bool = true,
) -> Bytes {
  let buf = Buffer()
  // Encoded Field Section Prefix (RFC 9204 §4.5.1): Required Insert Count = 0 (no
  // dynamic entries), then S = 0 with Delta Base = 0.
  buf.write_byte(0)
  buf.write_byte(0)
  for header in headers {
    let (name, value) = header
    match qpack_static_find(name, value) {
      // Indexed Field Line (§4.5.2), static table: `1 T=1 | Index(6-bit prefix)`.
      Some(index) => buf.write_bytes(qpack_int_encode(index, 6, 0xc0))
      None =>
        match qpack_static_find_name(name) {
          // Literal Field Line With Name Reference (§4.5.4), static: `0 1 N=0 T=1 |
          // Name Index(4-bit prefix)`, then the value string (7-bit prefix).
          Some(index) => {
            buf.write_bytes(qpack_int_encode(index, 4, 0x50))
            buf.write_bytes(
              qpack_encode_string(@utf8.encode(value), 7, 0, huffman),
            )
          }
          // Literal Field Line With Literal Name (§4.5.6): `0 0 1 N=0 H | Name
          // Length(3-bit prefix)`, the name, then the value string.
          None => {
            buf.write_bytes(
              qpack_encode_string(@utf8.encode(name), 3, 0x20, huffman),
            )
            buf.write_bytes(
              qpack_encode_string(@utf8.encode(value), 7, 0, huffman),
            )
          }
        }
    }
  }
  buf.to_bytes()
}

///|
/// Decode a QPACK field section (encoded over the static table) back into its header
/// list. The prefix's insert count and base are read and required to be zero (this
/// decoder resolves static references only); a field line that references the dynamic
/// table is reported as unsupported.
pub fn qpack_decode_field_section(
  input : Bytes,
) -> Array[(String, String)] raise QpackError {
  let view = input[:]
  // Encoded Field Section Prefix: Required Insert Count then S + Delta Base.
  let (insert_count, ric_len) = match qpack_int_decode(view, 8) {
    Some(v) => v
    None => raise QpackError("truncated field section prefix (insert count)")
  }
  if insert_count != 0 {
    raise QpackError("non-zero Required Insert Count needs the dynamic table")
  }
  let (_base, base_len) = match qpack_int_decode(view[ric_len:], 7) {
    Some(v) => v
    None => raise QpackError("truncated field section prefix (base)")
  }
  let mut off = ric_len + base_len
  let headers : Array[(String, String)] = []
  while off < view.length() {
    let b0 = view[off].to_int()
    if (b0 & 0x80) != 0 {
      // Indexed Field Line (§4.5.2): bit 6 is T (1 = static table).
      if (b0 & 0x40) == 0 {
        raise QpackError("dynamic-table indexed field line unsupported")
      }
      let (index, consumed) = qpack_decode_int_at(view, off, 6)
      headers.push(qpack_static_entry(index))
      off += consumed
    } else if (b0 & 0x40) != 0 {
      // Literal Field Line With Name Reference (§4.5.4): bit 4 is T.
      if (b0 & 0x10) == 0 {
        raise QpackError("dynamic-table name reference unsupported")
      }
      let (index, name_consumed) = qpack_decode_int_at(view, off, 4)
      let name = qpack_static_entry(index).0
      off += name_consumed
      let (value, value_consumed) = qpack_decode_string_at(view, off, 7)
      headers.push((name, @utf8.decode_lossy(value[:])))
      off += value_consumed
    } else if (b0 & 0x20) != 0 {
      // Literal Field Line With Literal Name (§4.5.6): name string uses a 3-bit prefix.
      let (name, name_consumed) = qpack_decode_string_at(view, off, 3)
      off += name_consumed
      let (value, value_consumed) = qpack_decode_string_at(view, off, 7)
      headers.push((@utf8.decode_lossy(name[:]), @utf8.decode_lossy(value[:])))
      off += value_consumed
    } else {
      // 0b0000_xxxx: Indexed / Literal With Post-Base Index — dynamic-table only.
      raise QpackError("post-base (dynamic-table) field line unsupported")
    }
  }
  headers
}

///|
/// The static-table entry at `index`, or raise if the index is out of range.
fn qpack_static_entry(index : Int) -> (String, String) raise QpackError {
  match qpack_static_get(index) {
    Some(entry) => entry
    None => raise QpackError("static index out of range: " + index.to_string())
  }
}

///|
/// Decode a prefix integer starting at `off` in `view`, raising on truncation.
fn qpack_decode_int_at(
  view : BytesView,
  off : Int,
  prefix_bits : Int,
) -> (Int, Int) raise QpackError {
  match qpack_int_decode(view[off:], prefix_bits) {
    Some(v) => v
    None => raise QpackError("truncated field-line integer")
  }
}

///|
/// Decode a string starting at `off` in `view`, raising on truncation.
fn qpack_decode_string_at(
  view : BytesView,
  off : Int,
  prefix_bits : Int,
) -> (Bytes, Int) raise QpackError {
  match qpack_decode_string(view[off:], prefix_bits) {
    Some(v) => v
    None => raise QpackError("truncated field-line string")
  }
}
