// QUIC transport parameters (RFC 9000 §18). Each endpoint declares its limits — flow
// control, connection IDs, idle timeout — in a block carried by the TLS handshake.
// The wire form is a sequence of (id, length, value), all lengths and integer values
// varint-encoded (§18.1).

///|
/// The transport-parameter identifiers this build recognizes by name (RFC 9000 §18.2).
/// The block is still encoded and decoded generically, so unknown ids pass through.
pub let tp_max_idle_timeout : UInt64 = 0x01

///|
pub let tp_max_udp_payload_size : UInt64 = 0x03

///|
pub let tp_initial_max_data : UInt64 = 0x04

///|
pub let tp_initial_max_stream_data_bidi_local : UInt64 = 0x05

///|
pub let tp_initial_max_stream_data_bidi_remote : UInt64 = 0x06

///|
pub let tp_initial_max_stream_data_uni : UInt64 = 0x07

///|
pub let tp_initial_max_streams_bidi : UInt64 = 0x08

///|
pub let tp_initial_max_streams_uni : UInt64 = 0x09

///|
pub let tp_ack_delay_exponent : UInt64 = 0x0a

///|
pub let tp_max_ack_delay : UInt64 = 0x0b

///|
pub let tp_active_connection_id_limit : UInt64 = 0x0e

///|
pub let tp_initial_source_connection_id : UInt64 = 0x0f

///|
/// A transport parameter: an identifier and its raw value bytes. Integer parameters
/// carry a varint-encoded value; use `transport_param_int` / `transport_param_as_int`
/// to build and read those.
pub(all) struct TransportParam {
  id : UInt64
  value : Bytes
} derive(Eq, Debug)

///|
/// A transport parameter whose value is a single varint integer (RFC 9000 §18.2).
pub fn transport_param_int(id : UInt64, value : UInt64) -> TransportParam {
  { id, value: quic_varint_encode(value), }
}

///|
/// Read a varint-valued transport parameter's integer, or `None` if its value is not
/// a single well-formed varint.
pub fn transport_param_as_int(p : TransportParam) -> UInt64? {
  guard quic_varint_decode(p.value[:]) is Some((v, n)) else { return None }
  if n == p.value.length() {
    Some(v)
  } else {
    None
  }
}

///|
/// Encode a transport-parameter block: each parameter as its id varint, a length
/// varint, then the value bytes (RFC 9000 §18).
pub fn encode_transport_params(params : Array[TransportParam]) -> Bytes {
  let buf = Buffer()
  for p in params {
    buf.write_bytes(quic_varint_encode(p.id)[:])
    buf.write_bytes(quic_varint_encode(p.value.length().to_uint64())[:])
    buf.write_bytes(p.value[:])
  }
  buf.to_bytes()
}

///|
/// Decode a transport-parameter block, preserving order and duplicates so the caller
/// can apply RFC 9000 §7.4's rules. Returns `None` on a truncated parameter.
pub fn decode_transport_params(b : BytesView) -> Array[TransportParam]? {
  let out : Array[TransportParam] = []
  let mut off = 0
  while off < b.length() {
    guard quic_varint_decode(b[off:]) is Some((id, il)) else { return None }
    off = off + il
    guard quic_varint_decode(b[off:]) is Some((length, ll)) else { return None }
    off = off + ll
    let n = length.to_int()
    if b.length() < off + n {
      return None
    }
    out.push({ id, value: b[off:off + n].to_owned(), })
    off = off + n
  }
  Some(out)
}
