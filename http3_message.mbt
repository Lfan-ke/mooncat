// Mapping an HTTP message onto an HTTP/3 request or response stream (RFC 9114 §4.1). A
// message is a HEADERS frame carrying a QPACK-encoded field section, followed by zero or
// more DATA frames carrying the body, and optionally a trailing HEADERS frame for trailers.
// Requests and responses differ only in their pseudo-headers — :method/:scheme/:authority/
// :path for a request, :status for a response — which are ordinary field lines that precede
// the regular headers (§4.3.1). This ties the QPACK field-section codec and the HTTP/3 frame
// codec into the messages a connection actually exchanges; only the QUIC stream carrying
// these bytes is left to the async transport.

///|
/// Encode a message body as an HTTP/3 request/response stream: a HEADERS frame with the
/// QPACK-encoded `headers` (static table only), then a DATA frame when `body` is non-empty.
pub fn http3_encode_message(
  headers : Array[(String, String)],
  body : Bytes,
) -> Bytes {
  let buf = Buffer()
  buf.write_bytes(
    http3_frame_encode(Headers(qpack_encode_field_section(headers))),
  )
  if body.length() > 0 {
    buf.write_bytes(http3_frame_encode(Data(body)))
  }
  buf.to_bytes()
}

///|
/// Decode an HTTP/3 request/response stream back into its header list and body: the first
/// HEADERS frame gives the headers, the DATA frames concatenate into the body, and a second
/// HEADERS frame (trailers) and unknown frames are ignored (RFC 9114 §4.1). Raises if there
/// is no HEADERS frame or a frame is malformed.
pub fn http3_decode_message(
  bytes : Bytes,
) -> (Array[(String, String)], Bytes) raise Http3FrameError {
  let (frames, _) = http3_frame_decode_all(bytes)
  let mut headers : Array[(String, String)]? = None
  let body = Buffer()
  for frame in frames {
    match frame {
      Headers(field_section) =>
        match headers {
          None =>
            headers = Some(
              qpack_decode_field_section(field_section) catch {
                _ => raise Http3FrameError("malformed QPACK field section")
              },
            )
          Some(_) => () // trailers
        }
      Data(chunk) => body.write_bytes(chunk)
      _ => () // reserved, greased, or control frames on a request stream
    }
  }
  match headers {
    Some(h) => (h, body.to_bytes())
    None => raise Http3FrameError("HTTP/3 message has no HEADERS frame")
  }
}

///|
/// Encode an HTTP/3 request: the `:method`, `:scheme`, `:authority`, and `:path` pseudo-
/// headers (RFC 9114 §4.3.1), then `headers`, then the body.
pub fn http3_request(
  meth : String,
  scheme : String,
  authority : String,
  path : String,
  headers : Array[(String, String)],
  body : Bytes,
) -> Bytes {
  let all : Array[(String, String)] = [
    (":method", meth),
    (":scheme", scheme),
    (":authority", authority),
    (":path", path),
  ]
  for h in headers {
    all.push(h)
  }
  http3_encode_message(all, body)
}

///|
/// Encode an HTTP/3 response: the `:status` pseudo-header (RFC 9114 §4.3.2), then `headers`,
/// then the body.
pub fn http3_response(
  status : String,
  headers : Array[(String, String)],
  body : Bytes,
) -> Bytes {
  let all : Array[(String, String)] = [(":status", status)]
  for h in headers {
    all.push(h)
  }
  http3_encode_message(all, body)
}
