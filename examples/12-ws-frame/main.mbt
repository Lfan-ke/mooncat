///|
/// The WebSocket frame codec (RFC 6455 §5.2): a server text frame (unmasked) and
/// a masked client binary frame both round-trip through the decoder, which
/// unmasks the payload; a close frame carries its 16-bit code then the reason;
/// the opcode wire values map both ways; and the receive rules reject what a
/// server must never accept from a client.
///
/// `from_client` picks which side's rules apply. It defaults to a server reading
/// a client, for whom masking is mandatory (§5.1), so decoding a frame the server
/// itself sent asks for the other direction.
///
///     moon run examples/12-ws-frame --target native
#coverage.skip
fn main {
  let text = @mooncat.ws_encode_frame(true, Text, b"hello heke1228")
  println("text frame     = \{hex(text)}")
  println("as server frame  = \{describe(text, false)}")
  // The very same bytes read as if a client had sent them: §5.1 requires a mask.
  println("as client frame  = \{describe(text, true)}")
  let masked = @mooncat.ws_encode_frame(
    true,
    Binary,
    b"\x00\x01\x02\xfe\xff",
    mask=b"\x37\xfa\x21\x3d",
  )
  println("masked frame   = \{hex(masked)}")
  println("as client frame  = \{describe(masked, true)}")
  // A reserved opcode (0x3) names the close code the connection must be failed with.
  println("reserved opcode  = \{describe(b"\x83\x80\x00\x00\x00\x00", true)}")
  println("close payload  = \{hex(@mooncat.ws_close_payload(1000, "bye"))}")
  println(
    "opcode Ping wire = \{@mooncat.WsOpcode::to_int(Ping)}, of_int(0xA) is Pong = \{@mooncat.ws_opcode_of_int(0xA) is Some(Pong)}",
  )
}

///|
/// Decode one frame and say what came back. The decoder answers three ways: a frame, `None` for a
/// buffer that does not hold a whole one yet, or a `WsError` naming the RFC 6455 §7.4.1 status the
/// connection must then be failed with.
fn describe(frame : Bytes, from_client : Bool) -> String {
  try {
    match @mooncat.ws_decode_frame(frame[:], from_client~) {
      Some((f, n)) =>
        "fin=\{f.fin} opcode=\{op(f.opcode)} payload=\{ascii(f.payload)} consumed=\{n}"
      None => "incomplete"
    }
  } catch {
    @mooncat.WsError(code, why) => "failed with \{code}: \{why}"
  }
}

///|
fn op(o : @mooncat.WsOpcode) -> String {
  match o {
    Continuation => "continuation"
    Text => "text"
    Binary => "binary"
    Close => "close"
    Ping => "ping"
    Pong => "pong"
  }
}

///|
fn hex(b : Bytes) -> String {
  let digits = "0123456789abcdef"
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let x = b[i].to_int()
    sb.write_char(digits[x >> 4].unsafe_to_char())
    sb.write_char(digits[x & 0xf].unsafe_to_char())
  }
  sb.to_string()
}

///|
fn ascii(b : Bytes) -> String {
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(b[i].to_int().unsafe_to_char())
  }
  sb.to_string()
}
