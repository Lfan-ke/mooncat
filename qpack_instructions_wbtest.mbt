// QPACK encoder- and decoder-stream instructions (RFC 9204 §4.3, §4.4), checked against
// the Appendix B examples and round-tripped for every representation.

///|
test "QPACK encoder instructions: RFC 9204 Appendix B vectors" {
  // Set Dynamic Table Capacity = 220 (Appendix B.1).
  assert_eq(qv_hex(qpack_encode_encoder_inst(SetCapacity(220))), "3fbd01")
  // Insert With Name Reference, static index 0 (:authority), "www.example.com" (B.1).
  assert_eq(
    qv_hex(
      qpack_encode_encoder_inst(
        InsertNameRef(is_static=true, index=0, value=b"www.example.com"),
        huffman=false,
      ),
    ),
    "c00f7777772e6578616d706c652e636f6d",
  )
  // Insert With Literal Name "custom-key": "custom-value" (Appendix B.3).
  assert_eq(
    qv_hex(
      qpack_encode_encoder_inst(
        InsertLiteralName(name=b"custom-key", value=b"custom-value"),
        huffman=false,
      ),
    ),
    "4a637573746f6d2d6b65790c637573746f6d2d76616c7565",
  )
  // Duplicate index 0 (Appendix B.3).
  assert_eq(qv_hex(qpack_encode_encoder_inst(Duplicate(index=0))), "00")
}

///|
test "QPACK encoder instructions: round-trip, raw and Huffman" {
  let insts : Array[QpackEncoderInst] = [
    SetCapacity(4096),
    InsertNameRef(is_static=true, index=15, value=b"application/json"),
    InsertNameRef(is_static=false, index=2, value=b"dyn-value"),
    InsertLiteralName(name=b"x-custom-header", value=b"a somewhat longer value"),
    Duplicate(index=31),
  ]
  for huff in [false, true] {
    for inst in insts {
      let wire = qpack_encode_encoder_inst(inst, huffman=huff)
      match qpack_decode_encoder_inst(wire[:]) {
        Some((got, consumed)) => {
          assert_eq(got, inst)
          assert_eq(consumed, wire.length())
        }
        None => abort("encoder instruction did not fully decode")
      }
    }
  }
}

///|
test "QPACK decoder instructions: vectors and round-trip" {
  // Section Acknowledgement stream 4; Stream Cancellation stream 4; Insert Count
  // Increment 1 (RFC 9204 §4.4).
  assert_eq(qv_hex(qpack_encode_decoder_inst(SectionAck(stream_id=4))), "84")
  assert_eq(qv_hex(qpack_encode_decoder_inst(StreamCancel(stream_id=4))), "44")
  assert_eq(
    qv_hex(qpack_encode_decoder_inst(InsertCountIncrement(increment=1))),
    "01",
  )
  let dinsts : Array[QpackDecoderInst] = [
    SectionAck(stream_id=1000),
    StreamCancel(stream_id=42),
    InsertCountIncrement(increment=300),
  ]
  for d in dinsts {
    let wire = qpack_encode_decoder_inst(d)
    match qpack_decode_decoder_inst(wire[:]) {
      Some((got, consumed)) => {
        assert_eq(got, d)
        assert_eq(consumed, wire.length())
      }
      None => abort("decoder instruction did not fully decode")
    }
  }
}

///|
test "QPACK encoder instruction: a partial value string decodes as None" {
  // A valid Insert With Name Reference header byte and length, but the value octets have
  // not all arrived yet.
  let full = qpack_encode_encoder_inst(
    InsertNameRef(is_static=true, index=0, value=b"www.example.com"),
    huffman=false,
  )
  assert_eq(qpack_decode_encoder_inst(full[0:4]), None)
}
