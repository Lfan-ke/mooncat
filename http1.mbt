///|
/// A parsed HTTP/1.1 request line + header block, produced by
/// `parse_http1_request` from any `@io.Reader` transport (a plain socket, or —
/// the reason this codec exists — a `@tls.Tls` stream, over which the async
/// library's own `@http.ServerConnection` cannot be built because it is welded
/// to `@socket.Tcp`). This is the self-built HTTP/1.1 request parser mandated by
/// the roadmap (§6.2 "自建解析器"), kept transport-agnostic so it drives both the
/// TLS accept path and, in later batches, the full h11 knob surface.
priv struct Http1Request {
  http_method : String
  target : String
  version : String
  headers : Map[String, String]
  content_length : Int
}

///|
/// Index of the first `ch` in `s` at or after `from`, or `-1`. Operates on the
/// `UInt16` code units `String` indexing yields; HTTP request/header syntax is
/// ASCII so code-unit scanning is exact.
fn index_of(s : String, ch : UInt16, from : Int) -> Int {
  let n = s.length()
  for i = from; i < n; i = i + 1 {
    if s[i] == ch {
      return i
    }
  }
  -1
}

///|
/// Split an HTTP/1.1 request line `METHOD SP request-target SP HTTP-version`
/// into its three tokens, or `None` if it is malformed (fewer than two spaces).
fn split_request_line(line : String) -> (String, String, String)? {
  let sp1 = index_of(line, ' ', 0)
  guard sp1 >= 0 else { return None }
  let sp2 = index_of(line, ' ', sp1 + 1)
  guard sp2 >= 0 else { return None }
  let verb = line[0:sp1].to_owned()
  let target = line[sp1 + 1:sp2].to_owned()
  let version = line[sp2 + 1:line.length()].to_owned()
  Some((verb, target, version))
}

///|
/// Parse a `Content-Length` field value into a non-negative `Int`, stopping at
/// the first non-digit (lenient like a production parser's fast path).
fn parse_content_length(s : String) -> Int {
  let t = ascii_trim(s)
  let mut acc = 0
  for i = 0; i < t.length(); i = i + 1 {
    let c = t[i]
    if c >= '0' && c <= '9' {
      acc = acc * 10 + (c.to_int() - 48)
    } else {
      return acc
    }
  }
  acc
}

///|
/// Read one HTTP/1.1 request head (request line + header block, terminated by a
/// blank line) from `reader`. Returns `None` on a clean end-of-stream — the
/// signal the keep-alive accept loop uses to stop reading further requests from
/// a closed connection — or on a malformed request line. Header names are
/// lowercased per ASGI's latin1-lowercased convention; values are OWS-trimmed
/// per RFC 7230 §3.2.
async fn parse_http1_request(reader : &@io.Reader) -> Http1Request? {
  let line = reader.read_until("\r\n")
  guard line is Some(request_line) else { return None }
  guard split_request_line(request_line) is Some((verb, target, version)) else {
    return None
  }
  let headers : Map[String, String] = Map([])
  for ;; {
    let h = reader.read_until("\r\n")
    guard h is Some(header_line) else { break }
    if header_line.length() == 0 {
      break
    }
    let colon = index_of(header_line, ':', 0)
    if colon >= 0 {
      let key = ascii_trim(header_line[0:colon].to_owned()).to_lower()
      let value = ascii_trim(
        header_line[colon + 1:header_line.length()].to_owned(),
      )
      headers[key] = value
    }
  }
  let content_length = match headers.get("content-length") {
    Some(v) => parse_content_length(v)
    None => 0
  }
  Some({ http_method: verb, target, version, headers, content_length })
}

///|
/// Lowercase hexadecimal encoding of a non-negative `Int`, for HTTP/1.1 chunked
/// transfer-encoding chunk-size prefixes.
fn hex_of(n : Int) -> String {
  let table = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
  ]
  if n == 0 {
    return "0"
  }
  let digits : Array[Char] = []
  let mut v = n
  while v > 0 {
    digits.push(table[v % 16])
    v = v / 16
  }
  let out = StringBuilder::new()
  for i = digits.length() - 1; i >= 0; i = i - 1 {
    out.write_char(digits[i])
  }
  out.to_string()
}

///|
/// Should the connection be kept alive after this request? HTTP/1.1 defaults to
/// keep-alive unless `Connection: close`; HTTP/1.0 defaults to close unless
/// `Connection: keep-alive` (RFC 7230 §6.3).
fn should_keep_alive(req : Http1Request) -> Bool {
  let conn = match req.headers.get("connection") {
    Some(c) => c.to_lower()
    None => ""
  }
  if req.version == "HTTP/1.0" {
    conn.contains("keep-alive")
  } else {
    !conn.contains("close")
  }
}

///|
/// Write one HTTP/1.1 chunked-encoding chunk. A zero-length body is skipped so
/// it is never mistaken for the terminating chunk.
async fn write_chunk(writer : &@io.Writer, body : Bytes) -> Unit {
  if body.length() == 0 {
    return
  }
  writer.write("\{hex_of(body.length())}\r\n")
  writer.write(body)
  writer.write("\r\n")
}

///|
/// Drive a moonasgi application over a single already-established HTTP/1.1
/// transport (`reader`/`writer` are the same `@tls.Tls` stream on the TLS path).
/// Builds the `Http` `Scope`, a `Receive` that streams the `Content-Length`
/// request body, and a `Send` that serialises the response:
///
/// * a single-shot response (`http.response.body` with `more_body=false` first)
///   is framed with `Content-Length`;
/// * a streamed response (`more_body=true`) switches to `Transfer-Encoding:
///   chunked`, one chunk per body event, terminated by the final `0\r\n\r\n`.
///
/// Framing headers the app supplies (`content-length` / `transfer-encoding`) are
/// dropped in favour of the ones this codec computes. Returns whether the
/// connection should be kept alive for a further request.
async fn dispatch_http1(
  app : @moonasgi.AsgiApp,
  req : Http1Request,
  reader : &@io.Reader,
  writer : &@io.Writer,
) -> Bool {
  let (path, query) = split_query(req.target)
  let scope = @moonasgi.Scope::Http({
    http_version: if req.version == "HTTP/1.0" {
      "1.0"
    } else {
      "1.1"
    },
    http_method: req.http_method,
    scheme: "https",
    path,
    raw_path: @utf8.encode(path),
    query_string: @utf8.encode(query),
    root_path: "",
    headers: headers_to_pairs(req.headers),
    client: None,
    server: None,
    state: Map([]),
  })
  let body_sent = Ref(false)
  let receive : @moonasgi.Receive = () => {
    if body_sent.val {
      @moonasgi.Event::HttpDisconnect
    } else {
      body_sent.val = true
      if req.content_length == 0 {
        @moonasgi.Event::HttpRequest(body=b"", more_body=false)
      } else {
        let chunk = reader.read_exactly(req.content_length)
        @moonasgi.Event::HttpRequest(body=chunk, more_body=false)
      }
    }
  }
  let resp_status = Ref(200)
  let resp_headers : Ref[Array[(String, String)]] = Ref([])
  let started = Ref(false)
  let chunked = Ref(false)
  let ended = Ref(false)
  let head = fn(extra : String) -> String {
    let sb = StringBuilder::new()
    sb.write_string(
      "HTTP/1.1 \{resp_status.val} \{reason(resp_status.val)}\r\n",
    )
    for pair in resp_headers.val {
      let kl = pair.0.to_lower()
      if kl != "content-length" && kl != "transfer-encoding" {
        sb.write_string("\{pair.0}: \{pair.1}\r\n")
      }
    }
    sb.write_string(extra)
    sb.to_string()
  }
  let send : @moonasgi.Send = event => {
    match event {
      HttpResponseStart(status~, headers~) => {
        resp_status.val = status
        resp_headers.val = headers
      }
      HttpResponseBody(body~, more_body~) =>
        if !started.val {
          started.val = true
          if !more_body {
            writer.write(head("content-length: \{body.length()}\r\n\r\n"))
            writer.write(body)
            ended.val = true
          } else {
            chunked.val = true
            writer.write(head("transfer-encoding: chunked\r\n\r\n"))
            write_chunk(writer, body)
          }
        } else if chunked.val {
          write_chunk(writer, body)
          if !more_body {
            writer.write("0\r\n\r\n")
            ended.val = true
          }
        }
      _ => ()
    }
  }
  app(scope, receive, send)
  if !started.val {
    writer.write(head("content-length: 0\r\n\r\n"))
  } else if chunked.val && !ended.val {
    writer.write("0\r\n\r\n")
  }
  should_keep_alive(req)
}

///|
test "http1 codec: request-line split, content-length, hex, keep-alive" {
  assert_eq(
    split_request_line("GET /a?b=1 HTTP/1.1"),
    Some(("GET", "/a?b=1", "HTTP/1.1")),
  )
  assert_eq(split_request_line("garbage"), None)
  assert_eq(parse_content_length(" 42 "), 42)
  assert_eq(parse_content_length("0"), 0)
  assert_eq(hex_of(0), "0")
  assert_eq(hex_of(255), "ff")
  assert_eq(hex_of(4096), "1000")
  let ka_11 : Http1Request = {
    http_method: "GET",
    target: "/",
    version: "HTTP/1.1",
    headers: Map([]),
    content_length: 0,
  }
  assert_eq(should_keep_alive(ka_11), true)
  let close_11 : Http1Request = {
    ..ka_11,
    headers: Map([("connection", "close")]),
  }
  assert_eq(should_keep_alive(close_11), false)
  let ka_10 : Http1Request = {
    ..ka_11,
    version: "HTTP/1.0",
    headers: Map([("connection", "keep-alive")]),
  }
  assert_eq(should_keep_alive(ka_10), true)
  let close_10 : Http1Request = { ..ka_11, version: "HTTP/1.0" }
  assert_eq(should_keep_alive(close_10), false)
}
