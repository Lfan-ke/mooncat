///|
/// QUIC transport parameters (RFC 9000 §18) — the (id, length, value) block a
/// peer carries in its TLS handshake. Named integer parameters encode, decode
/// back, and their varint values read out; the identifier constants are the RFC
/// 9000 §18.2 assignments.
///
///     moon run examples/20-quic-transport-params --target native
#coverage.skip
fn main {
  let params = [
    @mooncat.transport_param_int(@mooncat.tp_initial_max_data, 1048576UL),
    @mooncat.transport_param_int(@mooncat.tp_initial_max_streams_bidi, 100UL),
    @mooncat.transport_param_int(@mooncat.tp_max_idle_timeout, 30000UL),
    @mooncat.transport_param_int(@mooncat.tp_max_udp_payload_size, 1472UL),
  ]
  let enc = @mooncat.encode_transport_params(params)
  println("encoded = \{hex(enc)}")
  match @mooncat.decode_transport_params(enc[:]) {
    Some(got) => {
      println("decoded \{got.length()} parameters:")
      for p in got {
        println(
          "  id=\{p.id.to_string()} value=\{opt_u(@mooncat.transport_param_as_int(p))}",
        )
      }
    }
    None => println("decode failed")
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
fn opt_u(o : UInt64?) -> String {
  match o {
    Some(n) => n.to_string()
    None => "(none)"
  }
}
