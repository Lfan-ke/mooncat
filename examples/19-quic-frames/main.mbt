///|
/// The QUIC frame codec (RFC 9000 §19) and packet headers (§17). A range of
/// frame types encode to their bytes and parse back, reporting whether each is
/// ack-eliciting; a payload of several frames parses as a unit; and the long and
/// short packet headers round-trip.
///
///     moon run examples/19-quic-frames --target native
#coverage.skip
fn main {
  run() catch {
    e => println("quic frame error: \{e}")
  }
}

///|
fn run() -> Unit raise {
  let frames : Array[@mooncat.QuicFrame] = [
    Ping,
    Crypto(offset=1UL, data=b"\xaa\xbb"),
    Stream(id=4UL, offset=0UL, fin=true, data=b"hello"),
    Ack(largest=10UL, delay=0UL, first_range=3UL, ranges=[]),
    MaxData(15293UL),
    ResetStream(id=4UL, error_code=0UL, final_size=100UL),
    ConnectionClose(error_code=7UL, frame_type=Some(8UL), reason=b"by"),
    HandshakeDone,
  ]
  for f in frames {
    let enc = @mooncat.encode_frame(f)
    let ok = match @mooncat.parse_frame(enc[:]) {
      Some((g, _)) => g == f
      None => false
    }
    println(
      "\{pad(hex(enc))} round-trip=\{ok} ack-eliciting=\{@mooncat.quic_frame_is_ack_eliciting(f)}",
    )
  }
  let payload = @mooncat.quic_encode_payload([
    Ping,
    Crypto(offset=0UL, data=b"\x01\x02"),
  ])
  let parsed = @mooncat.quic_parse_payload(payload)
  println(
    "payload frames = \{parsed.length()} ack-eliciting=\{@mooncat.quic_payload_is_ack_eliciting(parsed)}",
  )
  let lh = @mooncat.QuicLongHeader::{
    packet_type: @mooncat.QuicLongPacketType::Initial,
    type_specific: 0,
    version: 1U,
    dcid: b"\x01\x02\x03",
    scid: b"",
  }
  let lh_wire = @mooncat.encode_long_header(lh)
  let lh_ok = match @mooncat.parse_long_header(lh_wire[:]) {
    Some((h, _)) => h == lh
    None => false
  }
  println("long header  = \{hex(lh_wire)}  round-trip=\{lh_ok}")
  let sh = @mooncat.QuicShortHeader::{
    spin: false,
    key_phase: true,
    pn_length: 2,
    dcid: b"\xaa\xbb\xcc\xdd",
  }
  let sh_wire = @mooncat.encode_short_header(sh)
  let sh_ok = match @mooncat.parse_short_header(sh_wire[:], 4) {
    Some((h, _)) => h == sh
    None => false
  }
  println("short header = \{hex(sh_wire)}  round-trip=\{sh_ok}")
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
  for _i = s.length(); _i < 22; _i = _i + 1 {
    sb.write_char(' ')
  }
  sb.to_string()
}
