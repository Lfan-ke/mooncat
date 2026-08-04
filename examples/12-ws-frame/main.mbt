///|
/// The WebSocket frame codec (RFC 6455 §5.2): a server text frame (unmasked) and
/// a masked client binary frame both round-trip through the decoder, which
/// unmasks the payload; a close frame carries its 16-bit code then the reason;
/// and the opcode wire values map both ways.
///
///     moon run examples/12-ws-frame --target native
#coverage.skip
fn main {
  let text = @mooncat.ws_encode_frame(true, Text, b"hello heke1228")
  println("text frame     = \{hex(text)}")
  match @mooncat.ws_decode_frame(text[:]) {
    Some((f, n)) =>
      println(
        "decoded: fin=\{f.fin} opcode=\{op(f.opcode)} payload=\{ascii(f.payload)} consumed=\{n}",
      )
    None => println("incomplete")
  }
  let masked = @mooncat.ws_encode_frame(
    true,
    Binary,
    b"\x00\x01\x02\xfe\xff",
    mask=b"\x37\xfa\x21\x3d",
  )
  println("masked frame   = \{hex(masked)}")
  match @mooncat.ws_decode_frame(masked[:]) {
    Some((f, _)) => println("unmasked payload = \{hex(f.payload)}")
    None => println("incomplete")
  }
  println("close payload  = \{hex(@mooncat.ws_close_payload(1000, "bye"))}")
  println(
    "opcode Ping wire = \{@mooncat.WsOpcode::to_int(Ping)}, of_int(0xA) is Pong = \{@mooncat.ws_opcode_of_int(0xA) is Some(Pong)}",
  )
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
  let sb = StringBuilder::new()
  for i = 0; i < b.length(); i = i + 1 {
    let x = b[i].to_int()
    sb.write_char(digits[x >> 4].unsafe_to_char())
    sb.write_char(digits[x & 0xf].unsafe_to_char())
  }
  sb.to_string()
}

///|
fn ascii(b : Bytes) -> String {
  let sb = StringBuilder::new()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(b[i].to_int().unsafe_to_char())
  }
  sb.to_string()
}
