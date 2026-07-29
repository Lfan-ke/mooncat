// QUIC frames (RFC 9000 §19) — the content carried inside a packet's payload.
// This brick covers the frames the handshake needs: PADDING (§19.1), PING (§19.2),
// and CRYPTO (§19.6), which carries the TLS handshake bytes. Each frame starts with
// a varint type; CRYPTO's offset and length are varints too. STREAM/ACK and the
// flow-control frames land in later bricks on the same varint machinery.

///|
/// A decoded QUIC frame. `Padding` collapses a run of zero bytes to its length.
pub(all) enum QuicFrame {
  Padding(Int)
  Ping
  Crypto(offset~ : UInt64, data~ : Bytes)
} derive(Eq, Debug)

///|
/// Encode a frame to its wire bytes.
pub fn encode_frame(f : QuicFrame) -> Bytes {
  let buf = Buffer()
  match f {
    Padding(n) =>
      for _i = 0; _i < n; _i = _i + 1 {
        buf.write_byte(b'\x00')
      }
    Ping => buf.write_bytes(quic_varint_encode(1UL)[:])
    Crypto(offset~, data~) => {
      buf.write_bytes(quic_varint_encode(6UL)[:])
      buf.write_bytes(quic_varint_encode(offset)[:])
      buf.write_bytes(quic_varint_encode(data.length().to_uint64())[:])
      buf.write_bytes(data[:])
    }
  }
  buf.to_bytes()
}

///|
/// Parse one frame at the start of `b`, returning it and the bytes it occupied, or
/// `None` on a truncated frame or a type this brick does not yet decode. A PADDING
/// frame absorbs the whole run of leading zero bytes.
pub fn parse_frame(b : BytesView) -> (QuicFrame, Int)? {
  guard quic_varint_decode(b) is Some((ftype, tlen)) else { return None }
  match ftype {
    0UL => {
      let mut n = 0
      while n < b.length() && b[n].to_int() == 0 {
        n = n + 1
      }
      Some((Padding(n), n))
    }
    1UL => Some((Ping, tlen))
    6UL => {
      let mut off = tlen
      guard quic_varint_decode(b[off:]) is Some((offset, olen)) else {
        return None
      }
      off = off + olen
      guard quic_varint_decode(b[off:]) is Some((length, llen)) else {
        return None
      }
      off = off + llen
      let dlen = length.to_int()
      if b.length() < off + dlen {
        return None
      }
      let data = b[off:off + dlen].to_owned()
      off = off + dlen
      Some((Crypto(offset~, data~), off))
    }
    _ => None
  }
}
