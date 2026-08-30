// A QUIC packet payload (RFC 9000 §12.4) is a sequence of frames. This assembles a
// frame list into the payload that goes under AEAD protection, parses a decrypted
// payload back into its frames, pads a payload out to a minimum size with PADDING, and
// classifies whether a payload is ack-eliciting (RFC 9000 §13.2.1). It sits between the
// single-frame codec and the packet-protection layer; pure bytes in and out.

///|
/// A truncated or unparsable frame in a packet payload.
pub suberror QuicPayloadError {
  QuicPayloadError(String)
}

///|
/// Encode a list of frames into a packet payload — their wire encodings concatenated.
pub fn quic_encode_payload(frames : Array[QuicFrame]) -> Bytes {
  let buf = Buffer()
  for frame in frames {
    buf.write_bytes(encode_frame(frame))
  }
  buf.to_bytes()
}

///|
/// Parse a decrypted packet payload into its frames, consuming the whole payload. A
/// frame that does not parse, or that consumes no bytes, is a payload error.
pub fn quic_parse_payload(
  payload : Bytes,
) -> Array[QuicFrame] raise QuicPayloadError {
  let frames : Array[QuicFrame] = []
  let view = payload[:]
  let mut off = 0
  while off < view.length() {
    match parse_frame(view[off:]) {
      Some((frame, consumed)) => {
        if consumed <= 0 {
          raise QuicPayloadError("frame consumed no bytes")
        }
        frames.push(frame)
        off += consumed
      }
      None => raise QuicPayloadError("truncated or unknown frame in payload")
    }
  }
  frames
}

///|
/// Whether a single frame is ack-eliciting (RFC 9000 §13.2.1): every frame except
/// PADDING, ACK, ACK_ECN, and CONNECTION_CLOSE obliges the peer to acknowledge the packet.
pub fn quic_frame_is_ack_eliciting(frame : QuicFrame) -> Bool {
  match frame {
    Padding(_) | Ack(..) | AckEcn(..) | ConnectionClose(..) => false
    _ => true
  }
}

///|
/// Whether a payload's frames make the packet ack-eliciting — true if any frame is.
pub fn quic_payload_is_ack_eliciting(frames : Array[QuicFrame]) -> Bool {
  for frame in frames {
    if quic_frame_is_ack_eliciting(frame) {
      return true
    }
  }
  false
}

///|
/// Pad `payload` out to at least `min_size` bytes with PADDING frames (zero octets); a
/// payload already that long is returned unchanged (RFC 9000 §14.1 — an Initial packet's
/// payload is padded so the datagram reaches the 1200-byte minimum).
pub fn quic_pad_payload(payload : Bytes, min_size : Int) -> Bytes {
  if payload.length() >= min_size {
    return payload
  }
  let buf = Buffer()
  buf.write_bytes(payload)
  for _i = payload.length(); _i < min_size; _i = _i + 1 {
    buf.write_byte(0)
  }
  buf.to_bytes()
}
