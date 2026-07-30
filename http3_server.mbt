// Serving an HTTP/3 request on a request stream (RFC 9114 §4.1): a client opens a bidirectional
// stream carrying a HEADERS frame (the pseudo-headers :method/:scheme/:authority/:path and the
// regular headers) and DATA frames (the body); the server decodes that into a request, runs a
// handler, and writes the response — a HEADERS frame with :status and the DATA of the body —
// back on the same stream. This is the connection-level routing over the HTTP/3 message codec, a
// mooncat HTTP/3 server's request/response path.

///|
/// A decoded HTTP/3 request: the pseudo-headers pulled out, the remaining header fields, and the
/// body.
pub(all) struct Http3Request {
  meth : String
  scheme : String
  authority : String
  path : String
  headers : Array[(String, String)]
  body : Bytes
}

///|
/// Decode an HTTP/3 request stream into a request, separating the pseudo-headers from the
/// regular ones (RFC 9114 §4.3.1). `None` when the required `:method` and `:path` are absent.
/// Raises on a malformed stream.
pub fn http3_parse_request(
  bytes : Bytes,
) -> Http3Request? raise Http3FrameError {
  let (all_headers, body) = http3_decode_message(bytes)
  let mut meth = ""
  let mut scheme = ""
  let mut authority = ""
  let mut path = ""
  let regular : Array[(String, String)] = []
  for h in all_headers {
    match h.0 {
      ":method" => meth = h.1
      ":scheme" => scheme = h.1
      ":authority" => authority = h.1
      ":path" => path = h.1
      _ => regular.push(h)
    }
  }
  if meth == "" || path == "" {
    None
  } else {
    Some({ meth, scheme, authority, path, headers: regular, body })
  }
}

///|
/// Parse a request stream, rejecting any frame the protocol does not allow on a request stream
/// (RFC 9114 §7.2): a control-only frame such as SETTINGS is an H3_FRAME_UNEXPECTED connection error
/// here, not silently ignored. Otherwise as `http3_parse_request` — `None` when the required
/// `:method` / `:path` are absent. This is the request path with frame-placement validation applied.
pub fn http3_parse_request_strict(
  bytes : Bytes,
) -> Http3Request? raise Http3FrameError {
  let (frames, _) = http3_frame_decode_all(bytes)
  for frame in frames {
    http3_check_frame(frame, RequestCtx)
  }
  http3_parse_request(bytes)
}

///|
/// An HTTP/3 response: the status, the header fields, and the body.
pub(all) struct Http3Response {
  status : String
  headers : Array[(String, String)]
  body : Bytes
}

///|
/// Encode the response as an HTTP/3 response stream (a HEADERS frame with `:status`, then DATA).
pub fn Http3Response::encode(self : Http3Response) -> Bytes {
  http3_response(self.status, self.headers, self.body)
}

///|
/// Serve one HTTP/3 request stream: decode the request, apply `handler`, and encode its
/// response stream. A request missing its pseudo-headers is answered with a 400. Raises on a
/// malformed request stream.
pub fn http3_serve(
  request_bytes : Bytes,
  handler : (Http3Request) -> Http3Response,
) -> Bytes raise Http3FrameError {
  match http3_parse_request(request_bytes) {
    Some(req) => handler(req).encode()
    None => Http3Response::{ status: "400", headers: [], body: b"" }.encode()
  }
}
