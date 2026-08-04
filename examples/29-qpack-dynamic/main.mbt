///|
/// The QPACK dynamic table (RFC 9204 §3.2): encoder-stream instructions (set
/// capacity, insert with a static/dynamic name reference, insert literal,
/// duplicate) build the table, absolute and relative indexing read it, an
/// instruction round-trips through the encoder-stream codec, and a dynamic
/// encode splits the encoder-stream inserts from the field section.
///
///     moon run examples/29-qpack-dynamic --target native
#coverage.skip
fn main {
  run() catch {
    e => println("qpack dyn error: \{e}")
  }
}

///|
fn run() -> Unit raise {
  let t = @mooncat.QpackDynamicTable::new(4096)
  let _ = t.apply(SetCapacity(220))
  let _ = t.apply(
    InsertNameRef(is_static=true, index=0, value=b"www.example.com"),
  )
  let _ = t.apply(InsertLiteralName(name=b"custom-key", value=b"custom-value"))
  let _ = t.apply(Duplicate(index=0))
  println(
    "table: entries=\{t.entries.length()} insert_count=\{t.insert_count} used=\{t.used}",
  )
  println(
    "get(0)=\{pairb(t.get(0))} get_relative(0)=\{pairb(t.get_relative(0))}",
  )
  let inst = @mooncat.qpack_encode_encoder_inst(
    InsertLiteralName(name=b"k", value=b"v"),
    huffman=false,
  )
  match @mooncat.qpack_decode_encoder_inst(inst[:]) {
    Some((_, n)) =>
      println("encoder inst round-trips, consumed \{n} of \{inst.length()}")
    None => println("bad instruction")
  }
  // Encode headers with dynamic indexing (max_entries = negotiated capacity),
  // then apply the encoder-stream to a peer table and decode the section back.
  let headers = [
    (":authority", "www.example.com"),
    ("custom-key", "custom-value"),
  ]
  let dt = @mooncat.QpackDynamicTable::new(4096)
  let (insts, section) = @mooncat.qpack_encode_dynamic(
    headers,
    dt,
    128,
    huffman=false,
  )
  println(
    "dynamic encode: \{insts.length()} encoder-stream bytes, \{section.length()} field-section bytes, inserts=\{dt.insert_count}",
  )
  let peer = @mooncat.QpackDynamicTable::new(4096)
  let view = insts[:]
  let mut off = 0
  while off < insts.length() {
    match @mooncat.qpack_decode_encoder_inst(view[off:]) {
      Some((got, consumed)) => {
        let _ = peer.apply(got)
        off = off + consumed
      }
      None => break
    }
  }
  println(
    "dynamic round-trip = \{@mooncat.qpack_decode_field_section_dyn(section, peer, 128) == headers}",
  )
  // The decoder-stream acknowledgement direction (RFC 9204 §4.4).
  let dinst = @mooncat.qpack_encode_decoder_inst(SectionAck(stream_id=4))
  match @mooncat.qpack_decode_decoder_inst(dinst[:]) {
    Some((got, _)) =>
      println(
        "decoder inst (SectionAck) round-trip = \{got == SectionAck(stream_id=4)}",
      )
    None => println("bad decoder inst")
  }
}

///|
fn pairb(o : (Bytes, Bytes)?) -> String {
  match o {
    Some((n, v)) => ascii(n) + " " + ascii(v)
    None => "(none)"
  }
}

///|
fn ascii(b : Bytes) -> String {
  let sb = StringBuilder::new()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(b[i].to_int().unsafe_to_char())
  }
  sb.to_string()
}
