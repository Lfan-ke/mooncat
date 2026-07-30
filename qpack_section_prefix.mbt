// The QPACK Encoded Field Section Prefix (RFC 9204 §4.5.1): every field section opens with
// a Required Insert Count and a Base. The Required Insert Count states how many dynamic
// inserts the section depends on; it is transmitted modulo 2*MaxEntries (§4.5.1) and the
// decoder reconstructs the absolute value from the number of inserts it has already seen
// (§4.5.1.1), which lets a fixed-width field survive the dynamic table wrapping around. The
// Base anchors the section's relative indices and is carried as a sign bit plus a delta from
// the Required Insert Count. This prefix is what a field-line decoder reads before it can
// resolve any dynamic-table reference.

///|
/// The number of entries that fit in a table of `max_capacity` bytes at the 32-byte minimum
/// entry size — `MaxEntries` in RFC 9204 §4.5.1.1.
pub fn qpack_max_entries(max_capacity : Int) -> Int {
  max_capacity / 32
}

///|
/// Encode a field-section prefix (RFC 9204 §4.5.1): the Required Insert Count transmitted
/// modulo `2*max_entries`, then the Base as a sign bit (0 when `base >= req_insert_count`)
/// plus the delta.
pub fn qpack_encode_section_prefix(
  req_insert_count : Int,
  base : Int,
  max_entries : Int,
) -> Bytes {
  let enc_ric = if req_insert_count == 0 {
    0
  } else {
    req_insert_count % (2 * max_entries) + 1
  }
  let buf = Buffer()
  buf.write_bytes(qpack_int_encode(enc_ric, 8, 0))
  if base >= req_insert_count {
    buf.write_bytes(qpack_int_encode(base - req_insert_count, 7, 0))
  } else {
    buf.write_bytes(qpack_int_encode(req_insert_count - base - 1, 7, 0x80))
  }
  buf.to_bytes()
}

///|
/// Reconstruct the absolute Required Insert Count from its encoded form, `max_entries`, and
/// the number of inserts the decoder has processed (RFC 9204 §4.5.1.1).
pub fn qpack_decode_required_insert_count(
  encoded : Int,
  max_entries : Int,
  total_inserts : Int,
) -> Int raise QpackError {
  if encoded == 0 {
    return 0
  }
  let full_range = 2 * max_entries
  if encoded > full_range {
    raise QpackError("QPACK encoded Required Insert Count exceeds 2*MaxEntries")
  }
  let max_value = total_inserts + max_entries
  let max_wrapped = max_value / full_range * full_range
  let mut ric = max_wrapped + encoded - 1
  if ric > max_value {
    if ric <= full_range {
      raise QpackError("QPACK Required Insert Count decode underflow")
    }
    ric = ric - full_range
  }
  if ric == 0 {
    raise QpackError("QPACK Required Insert Count of 0 encoded as non-zero")
  }
  ric
}

///|
/// Decode a field-section prefix (RFC 9204 §4.5.1), given `max_entries` and the decoder's
/// total inserts so far. Returns `(req_insert_count, base, bytes-consumed)`, or `None` on a
/// partial read.
pub fn qpack_decode_section_prefix(
  input : BytesView,
  max_entries : Int,
  total_inserts : Int,
) -> (Int, Int, Int)? raise QpackError {
  let (enc_ric, ric_len) = match qpack_int_decode(input, 8) {
    Some(v) => v
    None => return None
  }
  let req_insert_count = qpack_decode_required_insert_count(
    enc_ric, max_entries, total_inserts,
  )
  if input.length() <= ric_len {
    return None
  }
  let sign = (input[ric_len].to_int() & 0x80) != 0
  let (delta_base, base_len) = match qpack_int_decode(input[ric_len:], 7) {
    Some(v) => v
    None => return None
  }
  let base = if sign {
    req_insert_count - delta_base - 1
  } else {
    req_insert_count + delta_base
  }
  Some((req_insert_count, base, ric_len + base_len))
}
