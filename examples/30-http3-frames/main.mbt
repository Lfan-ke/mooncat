///|
/// The HTTP/3 frame codec (RFC 9114 §7.2): a type varint, a length varint, then
/// the payload. Each typed frame encodes to its exact bytes and decodes back;
/// `decode_all` consumes whole frames off a stream and leaves a partial tail;
/// `frame_allowed` gates a frame against the stream it arrived on.
///
///     moon run examples/30-http3-frames --target native
#coverage.skip
fn main {
  run() catch {
    e => println("http3 error: \{e}")
  }
}

///|
fn run() -> Unit raise {
  let frames : Array[@mooncat.Http3Frame] = [
    Data(b"hi"),
    Headers(b"\xab\xcd"),
    Settings([(0x06, 0x00), (0x01, 0x00)]),
    GoAway(0),
    CancelPush(5),
    MaxPushId(5),
  ]
  for f in frames {
    let enc = @mooncat.http3_frame_encode(f)
    let ok = match @mooncat.http3_frame_decode(enc[:]) {
      Some((g, n)) => g == f && n == enc.length()
      None => false
    }
    println("encode \{pad(hex(enc))} round-trip=\{ok}")
  }

  // Two whole frames then the start of a third: decode_all stops at the partial.
  let stream = b"\x00\x02\x68\x69\x07\x01\x00\x00\x04\x68"
  let (got, consumed) = @mooncat.http3_frame_decode_all(stream)
  println(
    "decode_all: \{got.length()} whole frames, consumed \{consumed} of \{stream.length()} bytes",
  )

  // A DATA frame is allowed on a request stream but not on the control stream.
  println(
    "DATA on request stream allowed = \{@mooncat.http3_frame_allowed(Data(b"x"), RequestCtx)}",
  )
  println(
    "DATA on control stream allowed = \{@mooncat.http3_frame_allowed(Data(b"x"), ControlCtx)}",
  )
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
fn pad(s : String) -> String {
  let sb = StringBuilder::new()
  sb.write_string(s)
  for _i = s.length(); _i < 14; _i = _i + 1 {
    sb.write_char(' ')
  }
  sb.to_string()
}
