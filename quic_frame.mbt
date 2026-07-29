// QUIC frames (RFC 9000 §19) — the content carried inside a packet's payload.
// This brick covers the frames the handshake needs: PADDING (§19.1), PING (§19.2),
// and CRYPTO (§19.6), which carries the TLS handshake bytes. Each frame starts with
// a varint type; CRYPTO's offset and length are varints too. STREAM/ACK and the
// flow-control frames land in later bricks on the same varint machinery.

///|
/// A decoded QUIC frame. `Padding` collapses a run of zero bytes to its length;
/// `Stream` carries application data on a stream, with a byte `offset` and a `fin`
/// flag marking the end of the stream (RFC 9000 §19.8).
pub(all) enum QuicFrame {
  Padding(Int)
  Ping
  Crypto(offset~ : UInt64, data~ : Bytes)
  Stream(id~ : UInt64, offset~ : UInt64, fin~ : Bool, data~ : Bytes)
  Ack(
    largest~ : UInt64,
    delay~ : UInt64,
    first_range~ : UInt64,
    ranges~ : Array[(UInt64, UInt64)]
  )
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
    Stream(id~, offset~, fin~, data~) => {
      // Always emit with the OFF and LEN bits set (0x0e) so the frame is
      // self-delimiting; the FIN bit rides the low bit.
      let type_byte = 0x0e | (if fin { 1 } else { 0 })
      buf.write_bytes(quic_varint_encode(type_byte.to_uint64())[:])
      buf.write_bytes(quic_varint_encode(id)[:])
      buf.write_bytes(quic_varint_encode(offset)[:])
      buf.write_bytes(quic_varint_encode(data.length().to_uint64())[:])
      buf.write_bytes(data[:])
    }
    Ack(largest~, delay~, first_range~, ranges~) => {
      buf.write_bytes(quic_varint_encode(2UL)[:])
      buf.write_bytes(quic_varint_encode(largest)[:])
      buf.write_bytes(quic_varint_encode(delay)[:])
      buf.write_bytes(quic_varint_encode(ranges.length().to_uint64())[:])
      buf.write_bytes(quic_varint_encode(first_range)[:])
      for r in ranges {
        let (gap, len) = r
        buf.write_bytes(quic_varint_encode(gap)[:])
        buf.write_bytes(quic_varint_encode(len)[:])
      }
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
    2UL => {
      let mut off = tlen
      guard quic_varint_decode(b[off:]) is Some((largest, l1)) else {
        return None
      }
      off = off + l1
      guard quic_varint_decode(b[off:]) is Some((delay, l2)) else {
        return None
      }
      off = off + l2
      guard quic_varint_decode(b[off:]) is Some((count, l3)) else {
        return None
      }
      off = off + l3
      guard quic_varint_decode(b[off:]) is Some((first_range, l4)) else {
        return None
      }
      off = off + l4
      let ranges : Array[(UInt64, UInt64)] = []
      for _i = 0; _i < count.to_int(); _i = _i + 1 {
        guard quic_varint_decode(b[off:]) is Some((gap, lg)) else {
          return None
        }
        off = off + lg
        guard quic_varint_decode(b[off:]) is Some((rlen, lr)) else {
          return None
        }
        off = off + lr
        ranges.push((gap, rlen))
      }
      Some((Ack(largest~, delay~, first_range~, ranges~), off))
    }
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
    ty if ty >= 8UL && ty <= 15UL => {
      let ti = ty.to_int()
      let has_off = (ti & 0x04) != 0
      let has_len = (ti & 0x02) != 0
      let fin = (ti & 0x01) != 0
      let mut off = tlen
      guard quic_varint_decode(b[off:]) is Some((id, ilen)) else { return None }
      off = off + ilen
      let mut offset = 0UL
      if has_off {
        guard quic_varint_decode(b[off:]) is Some((o, olen)) else {
          return None
        }
        offset = o
        off = off + olen
      }
      let data = if has_len {
        guard quic_varint_decode(b[off:]) is Some((length, llen)) else {
          return None
        }
        off = off + llen
        let dlen = length.to_int()
        if b.length() < off + dlen {
          return None
        }
        let d = b[off:off + dlen].to_owned()
        off = off + dlen
        d
      } else {
        // No length field: the stream data runs to the end of the buffer.
        let d = b[off:].to_owned()
        off = b.length()
        d
      }
      Some((Stream(id~, offset~, fin~, data~), off))
    }
    _ => None
  }
}
