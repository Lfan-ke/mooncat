///|
/// HTTP/3 connection setup (RFC 9114 §6.2, §7.2.4): the named SETTINGS map to
/// their identifiers and round-trip on the control stream, an `Http3Conn`
/// demultiplexes the peer's unidirectional streams (establishing its SETTINGS
/// from the peer control stream, classifying the QPACK encoder stream), and the
/// SETTINGS identifier constants are the RFC assignments.
///
///     moon run examples/32-http3-conn --target native
#coverage.skip
fn main {
  run() catch {
    e => println("http3 conn error: \{e}")
  }
}

///|
fn run() -> Unit raise {
  let s = @mooncat.Http3Settings::new(4096UL, 16384UL, 100UL)
  let ctrl = @mooncat.http3_encode_control_stream(s.to_pairs())
  println("control stream type byte = \{ctrl[0].to_int()} (0 = control)")
  match @mooncat.http3_decode_control_stream(ctrl[:]) {
    Some(back) =>
      println(
        "settings: table=\{back.qpack_max_table_capacity.to_string()} max_field=\{back.max_field_section_size.to_string()} blocked=\{back.qpack_blocked_streams.to_string()}",
      )
    None => println("no settings")
  }
  let conn = @mooncat.Http3Conn::new(
    ServerSide,
    @mooncat.Http3Settings::new(4096UL, 16384UL, 100UL),
  )
  println("settings established (before peer) = \{conn.settings_established()}")
  let peer = @mooncat.Http3Settings::new(8192UL, 65536UL, 32UL)
  let ev = conn.accept_uni_stream(
    @mooncat.http3_encode_control_stream(peer.to_pairs()),
  )
  println(
    "peer control stream event = \{uev(ev)}, established now = \{conn.settings_established()}",
  )
  let ev2 = conn.accept_uni_stream(
    @mooncat.http3_encode_stream_type(QpackEncoderStream),
  )
  println("qpack encoder stream event = \{uev(ev2)}")
  println(
    "settings ids: table=\{@mooncat.h3_settings_qpack_max_table_capacity.to_string()} maxfield=\{@mooncat.h3_settings_max_field_section_size.to_string()} blocked=\{@mooncat.h3_settings_qpack_blocked_streams.to_string()}",
  )
}

///|
fn uev(e : @mooncat.Http3UniEvent) -> String {
  match e {
    ControlEstablished(_) => "control-established"
    QpackEncoder => "qpack-encoder"
    QpackDecoder => "qpack-decoder"
    Push(_) => "push"
    Reserved(_) => "reserved"
  }
}
