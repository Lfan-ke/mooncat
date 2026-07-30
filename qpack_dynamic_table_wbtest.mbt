// The QPACK dynamic table (RFC 9204 §3.2): entry sizing, eviction, absolute and relative
// indexing, and applying encoder-stream instructions.

///|
test "dynamic table: insert, size accounting, eviction, and indexing" {
  let t = QpackDynamicTable::new(100)
  assert_eq(t.insert(b"a", b"1"), true) // 1+1+32 = 34
  assert_eq(t.insert(b"bb", b"22"), true) // 2+2+32 = 36, total 70
  // The third entry (3+3+32 = 38) does not fit; the oldest is evicted first.
  assert_eq(t.insert(b"ccc", b"333"), true)
  assert_eq(t.used, 74) // 36 (bb) + 38 (ccc)
  assert_eq(t.insert_count, 3)
  assert_eq(t.dropped, 1)
  assert_eq(t.get(0), None) // evicted
  assert_eq(t.get(1), Some((b"bb", b"22")))
  assert_eq(t.get(2), Some((b"ccc", b"333")))
  // Relative index 0 is the most recently inserted entry (RFC 9204 §3.2.5).
  assert_eq(t.get_relative(0), Some((b"ccc", b"333")))
  assert_eq(t.get_relative(1), Some((b"bb", b"22")))
}

///|
test "dynamic table: shrinking the capacity evicts what no longer fits" {
  let t = QpackDynamicTable::new(200)
  let _ = t.insert(b"a", b"1") // 34
  let _ = t.insert(b"b", b"2") // 34, total 68
  let _ = t.insert(b"c", b"3") // 34, total 102
  assert_eq(t.used, 102)
  t.set_capacity(40) // room for one 34-byte entry
  assert_eq(t.used, 34)
  assert_eq(t.dropped, 2)
  assert_eq(t.get(2), Some((b"c", b"3")))
}

///|
test "dynamic table: an entry larger than the capacity is not inserted" {
  let t = QpackDynamicTable::new(40)
  assert_eq(t.insert(b"x", b"y"), true) // 34
  // 10+10+32 = 52 > 40: evicts everything, still cannot fit, inserts nothing.
  assert_eq(t.insert(b"aaaaaaaaaa", b"bbbbbbbbbb"), false)
  assert_eq(t.used, 0)
  assert_eq(t.entries.length(), 0)
  assert_eq(t.insert_count, 1) // only the successful insert counted
}

///|
test "dynamic table: apply encoder instructions (static/dynamic/duplicate names)" {
  let t = QpackDynamicTable::new(4096)
  let _ = t.apply(SetCapacity(220))
  assert_eq(t.capacity, 220)
  // Insert With Name Reference into the static table (index 0 = ":authority").
  let _ = t.apply(
    InsertNameRef(is_static=true, index=0, value=b"www.example.com"),
  )
  assert_eq(t.get(0), Some((b":authority", b"www.example.com")))
  let _ = t.apply(InsertLiteralName(name=b"custom-key", value=b"custom-value"))
  // Duplicate the most recent entry (relative index 0).
  let _ = t.apply(Duplicate(index=0))
  assert_eq(t.get(2), Some((b"custom-key", b"custom-value")))
  // Insert With Name Reference into the dynamic table (relative index 0 = the duplicate).
  let _ = t.apply(InsertNameRef(is_static=false, index=0, value=b"v2"))
  assert_eq(t.get(3), Some((b"custom-key", b"v2")))
  assert_eq(t.insert_count, 4)
}

///|
test "dynamic table: encode -> decode -> apply reproduces the table" {
  let insts : Array[QpackEncoderInst] = [
    SetCapacity(500),
    InsertNameRef(is_static=true, index=0, value=b"a.example"),
    InsertLiteralName(name=b"k", value=b"v"),
    Duplicate(index=0),
  ]
  // Serialize the whole encoder-stream and parse it back instruction by instruction.
  let wire = Buffer()
  for inst in insts {
    wire.write_bytes(qpack_encode_encoder_inst(inst, huffman=false))
  }
  let bytes = wire.to_bytes()
  let decoded : Array[QpackEncoderInst] = []
  let view = bytes[:]
  let mut off = 0
  while off < bytes.length() {
    match qpack_decode_encoder_inst(view[off:]) {
      Some((inst, consumed)) => {
        decoded.push(inst)
        off = off + consumed
      }
      None => abort("truncated encoder-stream")
    }
  }
  assert_eq(decoded, insts)
  let t = QpackDynamicTable::new(4096)
  for inst in decoded {
    let _ = t.apply(inst)
  }
  assert_eq(t.insert_count, 3) // SetCapacity is not an insert
  assert_eq(t.get(0), Some((b":authority", b"a.example")))
  assert_eq(t.get(1), Some((b"k", b"v")))
  assert_eq(t.get(2), Some((b"k", b"v"))) // the duplicate
}
