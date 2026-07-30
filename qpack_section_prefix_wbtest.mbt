// The QPACK Encoded Field Section Prefix (RFC 9204 §4.5.1, §4.5.1.1): Required Insert Count
// carried modulo 2*MaxEntries and reconstructed against the decoder's insert count, plus the
// signed Base delta.

///|
/// Encode a prefix and decode it back, given the decoder's total inserts (defaulting to the
/// Required Insert Count, the usual case).
fn roundtrip_prefix(
  req : Int,
  base : Int,
  max_entries : Int,
  total? : Int = -1,
) -> (Int, Int) raise {
  let total = if total == -1 { req } else { total }
  let wire = qpack_encode_section_prefix(req, base, max_entries)
  match qpack_decode_section_prefix(wire[:], max_entries, total) {
    Some((r, b, consumed)) => {
      assert_eq(consumed, wire.length())
      (r, b)
    }
    None => abort("truncated section prefix")
  }
}

///|
test "section prefix: the zero Required Insert Count encodes to two zero bytes" {
  let wire = qpack_encode_section_prefix(0, 0, 128)
  assert_eq(qv_hex(wire), "0000")
  assert_eq(roundtrip_prefix(0, 0, 128), (0, 0))
}

///|
test "section prefix: Base sign — S=0 when Base >= RIC, S=1 otherwise" {
  // Base above the Required Insert Count: S = 0, delta = Base - RIC.
  let above = qpack_encode_section_prefix(4, 6, 128)
  assert_eq((above[1].to_int() & 0x80) == 0, true) // sign bit clear
  assert_eq(roundtrip_prefix(4, 6, 128), (4, 6))
  // Base below the Required Insert Count: S = 1, delta = RIC - Base - 1.
  let below = qpack_encode_section_prefix(9, 6, 128)
  assert_eq((below[1].to_int() & 0x80) != 0, true) // sign bit set
  assert_eq(roundtrip_prefix(9, 6, 128), (9, 6))
}

///|
test "section prefix: round-trips across ranges, including dynamic-table wraparound" {
  let max_entries = 128 // a 4096-byte table
  // RIC below, at, and well past 2*MaxEntries (=256) so the reconstruction has to unwrap.
  for req in [1, 5, 128, 200, 256, 300, 511] {
    for base in [0, 1, req / 2, req] {
      assert_eq(roundtrip_prefix(req, base, max_entries), (req, base))
    }
  }
}

///|
test "section prefix: reconstructs when the decoder is ahead by up to MaxEntries" {
  // The decoder may have processed up to MaxEntries inserts beyond the section's Required
  // Insert Count; the modular value must still resolve to the exact count the encoder
  // meant. Past that window the reference would be to an evicted entry, so it is out of
  // scope here.
  let me = 128
  assert_eq(roundtrip_prefix(300, 290, me, total=300 + me - 1), (300, 290))
  assert_eq(roundtrip_prefix(9, 0, me, total=9 + me - 1), (9, 0))
}
