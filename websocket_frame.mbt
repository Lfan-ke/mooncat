// The WebSocket frame layer (RFC 6455 §5.2), self-built so mooncat owns the whole server-side WS
// path: the async transport's `Conn::from_http_server` writes a fixed 101 (no negotiated
// subprotocol) and its frame reader/writer (`Conn::new`) is package-private, so echoing a
// subprotocol means writing our own 101 (see `websocket_handshake`) and framing over the raw
// upgraded socket ourselves. This is the codec half; the runtime half feeds it the socket's bytes.

///|
/// A WebSocket protocol violation detected while framing (a reserved opcode), distinct from the
/// reader's end-of-stream.
pub suberror WsError {
  WsError(String)
}

///|
/// A WebSocket frame opcode (RFC 6455 §5.2): the data opcodes (continuation / text / binary) and
/// the control opcodes (close / ping / pong).
pub(all) enum WsOpcode {
  Continuation
  Text
  Binary
  Close
  Ping
  Pong
} derive(Eq, Debug)

///|
/// The 4-bit wire value of an opcode.
pub fn WsOpcode::to_int(self : WsOpcode) -> Int {
  match self {
    Continuation => 0x0
    Text => 0x1
    Binary => 0x2
    Close => 0x8
    Ping => 0x9
    Pong => 0xA
  }
}

///|
/// The opcode for a 4-bit wire value, or `None` for a reserved opcode.
pub fn ws_opcode_of_int(n : Int) -> WsOpcode? {
  match n {
    0x0 => Some(Continuation)
    0x1 => Some(Text)
    0x2 => Some(Binary)
    0x8 => Some(Close)
    0x9 => Some(Ping)
    0xA => Some(Pong)
    _ => None
  }
}

///|
/// A decoded WebSocket frame (RFC 6455 §5.2): its FIN bit, opcode, and already-unmasked payload.
pub(all) struct WsFrame {
  fin : Bool
  opcode : WsOpcode
  payload : Bytes
} derive(Eq, Debug)

///|
/// Encode a WebSocket frame (RFC 6455 §5.2). A 4-byte `mask` sets the MASK bit and masks the
/// payload (clients MUST mask, servers MUST NOT — pass `b""` for an unmasked server frame). The
/// payload length takes the shortest of the 7-bit (≤125), 16-bit (`126`), or 64-bit (`127`) forms.
pub fn ws_encode_frame(
  fin : Bool,
  opcode : WsOpcode,
  payload : Bytes,
  mask? : Bytes = b"",
) -> Bytes {
  let buf = Buffer()
  let b0 = (if fin { 0x80 } else { 0x00 }) | opcode.to_int()
  buf.write_byte(b0.to_byte())
  let masked = mask.length() == 4
  let mask_bit = if masked { 0x80 } else { 0x00 }
  let len = payload.length()
  if len <= 125 {
    buf.write_byte((mask_bit | len).to_byte())
  } else if len <= 0xFFFF {
    buf.write_byte((mask_bit | 126).to_byte())
    buf.write_byte((len >> 8).to_byte())
    buf.write_byte(len.to_byte())
  } else {
    buf.write_byte((mask_bit | 127).to_byte())
    let l = len.to_int64()
    for i = 7; i >= 0; i = i - 1 {
      buf.write_byte((l >> (i * 8)).to_byte())
    }
  }
  if masked {
    for i = 0; i < 4; i = i + 1 {
      buf.write_byte(mask[i])
    }
    for i = 0; i < len; i = i + 1 {
      buf.write_byte((payload[i].to_int() ^ mask[i % 4].to_int()).to_byte())
    }
  } else {
    for i = 0; i < len; i = i + 1 {
      buf.write_byte(payload[i])
    }
  }
  buf.to_bytes()
}

///|
/// Decode one WebSocket frame at the start of `b` (RFC 6455 §5.2), returning the frame (its payload
/// unmasked) and the byte count it consumed, or `None` when `b` does not yet hold a whole frame or
/// carries a reserved opcode.
pub fn ws_decode_frame(b : BytesView) -> (WsFrame, Int)? {
  if b.length() < 2 {
    return None
  }
  let b0 = b[0].to_int()
  let fin = (b0 & 0x80) != 0
  let opcode = match ws_opcode_of_int(b0 & 0x0F) {
    Some(op) => op
    None => return None
  }
  let b1 = b[1].to_int()
  let masked = (b1 & 0x80) != 0
  let mut off = 2
  let mut len = b1 & 0x7F
  if len == 126 {
    if b.length() < off + 2 {
      return None
    }
    len = (b[off].to_int() << 8) | b[off + 1].to_int()
    off = off + 2
  } else if len == 127 {
    if b.length() < off + 8 {
      return None
    }
    let mut l = 0L
    for i = 0; i < 8; i = i + 1 {
      l = (l << 8) | b[off + i].to_int().to_int64()
    }
    len = l.to_int()
    off = off + 8
  }
  let mut mask_off = 0
  if masked {
    if b.length() < off + 4 {
      return None
    }
    mask_off = off
    off = off + 4
  }
  if b.length() < off + len {
    return None
  }
  let payload = Buffer()
  for i = 0; i < len; i = i + 1 {
    if masked {
      payload.write_byte(
        (b[off + i].to_int() ^ b[mask_off + i % 4].to_int()).to_byte(),
      )
    } else {
      payload.write_byte(b[off + i])
    }
  }
  Some(({ fin, opcode, payload: payload.to_bytes() }, off + len))
}

///|
/// Read one WebSocket frame off a raw byte stream (RFC 6455 §5.2) — the runtime counterpart of
/// `ws_decode_frame`. Reads the 2-byte prefix, then the extended length (16- or 64-bit), the masking
/// key, and the payload as the prefix dictates, unmasking the payload. Raises `WsError` on a
/// reserved opcode and propagates the reader's end-of-stream.
pub async fn ws_read_frame(reader : &@io.Reader) -> WsFrame {
  let h = reader.read_exactly(2)
  let b0 = h[0].to_int()
  let fin = (b0 & 0x80) != 0
  let opcode = match ws_opcode_of_int(b0 & 0x0F) {
    Some(op) => op
    None => raise WsError("reserved WebSocket opcode")
  }
  let b1 = h[1].to_int()
  let masked = (b1 & 0x80) != 0
  let mut len = b1 & 0x7F
  if len == 126 {
    let e = reader.read_exactly(2)
    len = (e[0].to_int() << 8) | e[1].to_int()
  } else if len == 127 {
    let e = reader.read_exactly(8)
    let mut l = 0L
    for i = 0; i < 8; i = i + 1 {
      l = (l << 8) | e[i].to_int().to_int64()
    }
    len = l.to_int()
  }
  let mask = if masked { reader.read_exactly(4) } else { b"" }
  let raw = reader.read_exactly(len)
  let payload = if masked {
    let buf = Buffer()
    for i = 0; i < len; i = i + 1 {
      buf.write_byte((raw[i].to_int() ^ mask[i % 4].to_int()).to_byte())
    }
    buf.to_bytes()
  } else {
    raw
  }
  { fin, opcode, payload }
}

///|
/// A complete WebSocket application message read off a raw stream: a text or binary message with its
/// reassembled payload bytes, or a close with its code and reason bytes. Control frames never surface
/// here — `ws_read_message` handles them — matching what uvicorn hands the ASGI app. Text is carried
/// as bytes; the UTF-8 decode to a `String` happens at the ASGI boundary.
pub(all) enum WsMessage {
  WsText(Bytes)
  WsBinary(Bytes)
  WsClose(Int, Bytes)
} derive(Eq, Debug)

///|
/// The status code of a close frame's payload (RFC 6455 §5.5.1 / §7.1.5): the leading 16-bit value,
/// or `1005` ("no status received") when the payload carries none.
fn ws_close_code(payload : Bytes) -> Int {
  if payload.length() >= 2 {
    (payload[0].to_int() << 8) | payload[1].to_int()
  } else {
    1005
  }
}

///|
/// Build a close frame's payload (RFC 6455 §5.5.1): the 16-bit status code big-endian followed by
/// the UTF-8 reason.
pub fn ws_close_payload(code : Int, reason : String) -> Bytes {
  let buf = Buffer()
  buf.write_byte((code >> 8).to_byte())
  buf.write_byte(code.to_byte())
  buf.write_bytes(@utf8.encode(reason))
  buf.to_bytes()
}

///|
/// The reason bytes of a close frame's payload — everything after the 2-byte status code.
fn ws_close_reason(payload : Bytes) -> Bytes {
  if payload.length() > 2 {
    payload[2:].to_owned()
  } else {
    b""
  }
}

///|
/// Read one complete WebSocket message off `reader`, reassembling a fragmented message from its
/// continuation frames (RFC 6455 §5.4) and transparently handling interleaved control frames (§5.5):
/// a ping is answered on `writer` with a pong, a pong is dropped, and a close ends the message with
/// its code and reason. Raises `WsError` on a framing violation (a stray continuation frame, or a new
/// data frame arriving before the current message finished).
pub async fn ws_read_message(
  reader : &@io.Reader,
  writer : &@io.Writer,
) -> WsMessage {
  let payload = Buffer()
  let mut kind : WsOpcode? = None
  for ;; {
    let frame = ws_read_frame(reader)
    match frame.opcode {
      Ping => writer.write(ws_encode_frame(true, Pong, frame.payload))
      Pong => ()
      Close =>
        return WsClose(
          ws_close_code(frame.payload),
          ws_close_reason(frame.payload),
        )
      Text | Binary => {
        if kind is Some(_) {
          raise WsError("a new data frame arrived before the message finished")
        }
        kind = Some(frame.opcode)
        payload.write_bytes(frame.payload)
        if frame.fin {
          break
        }
      }
      Continuation => {
        if kind is None {
          raise WsError("continuation frame with no message in progress")
        }
        payload.write_bytes(frame.payload)
        if frame.fin {
          break
        }
      }
    }
  }
  let data = payload.to_bytes()
  if kind is Some(Binary) {
    WsBinary(data)
  } else {
    WsText(data)
  }
}
