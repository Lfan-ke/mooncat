// Sending and receiving a whole QUIC Initial packet (RFC 9000 §17.2.2, RFC 9001 §5): the
// send side assembles the frames into a payload and protects it; the receive side finds
// the packet-number field, removes protection, and parses the payload back into frames.
// This ties the payload assembly, the Initial packet protection, and the frame codec
// into the packet a QUIC endpoint actually puts on and takes off the wire.

///|
/// The offset of the packet-number field in a received Initial packet, walking its long
/// header: first byte, version, the two connection ids, the token, and the length field
/// (RFC 9000 §17.2.2).
pub fn quic_initial_pn_offset(packet : Bytes) -> Int raise QuicPayloadError {
  let view = packet[:]
  let mut off = 1 + 4 // first byte + version
  if off + 1 > view.length() {
    raise QuicPayloadError("Initial packet truncated before DCID")
  }
  let dcid_len = view[off].to_int()
  off = off + 1 + dcid_len
  if off + 1 > view.length() {
    raise QuicPayloadError("Initial packet truncated before SCID")
  }
  let scid_len = view[off].to_int()
  off = off + 1 + scid_len
  let (token_len, tl) = match quic_varint_decode(view[off:]) {
    Some(v) => v
    None => raise QuicPayloadError("Initial packet truncated in token length")
  }
  off = off + tl + token_len.to_int()
  let (_length, ll) = match quic_varint_decode(view[off:]) {
    Some(v) => v
    None => raise QuicPayloadError("Initial packet truncated in length field")
  }
  off + ll
}

///|
/// Build a protected Initial packet carrying `frames`: encode them into a payload and
/// protect it with `keys` (RFC 9001 §5.3, §5.4).
pub fn quic_send_initial(
  version : UInt,
  dcid : Bytes,
  scid : Bytes,
  token : Bytes,
  packet_number : Int64,
  pn_length : Int,
  frames : Array[QuicFrame],
  keys : QuicPacketKeys,
) -> Bytes {
  quic_protect_initial(
    version,
    dcid,
    scid,
    token,
    packet_number,
    pn_length,
    quic_encode_payload(frames),
    keys.key,
    keys.iv,
    keys.hp,
  )
}

///|
/// Receive a protected Initial `packet` with `keys`: remove protection, parse the
/// payload, and return its frames and packet number. `None` if authentication fails.
pub fn quic_recv_initial(
  packet : Bytes,
  keys : QuicPacketKeys,
) -> (Array[QuicFrame], Int64)? raise QuicPayloadError {
  let pn_offset = quic_initial_pn_offset(packet)
  match quic_unprotect_initial(packet, pn_offset, keys.key, keys.iv, keys.hp) {
    Some((payload, pn)) => Some((quic_parse_payload(payload), pn))
    None => None
  }
}
