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
  // `Transfer-Encoding: chunked` — the body is read as chunks, not by content-length.
  chunked : Bool
  // `Expect: 100-continue` — the server sends an interim `100 Continue` before it
  // reads the body, so the client waits for the go-ahead.
  expect_continue : Bool
}

///|
/// The cap on a request's head (request line + all header lines). A peer exceeding
/// it is rejected before its headers can pin unbounded memory — uvicorn's
/// `h11_max_incomplete_event_size` default of 16 KiB.
let max_head_size : Int = 16 * 1024

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
  // Bound the request head: a peer that never sends the terminating blank line (an
  // endless stream of header lines) must not grow the buffer without limit.
  let mut head_bytes = request_line.length() + 2
  for ;; {
    let h = reader.read_until("\r\n")
    guard h is Some(header_line) else { break }
    if header_line.length() == 0 {
      break
    }
    head_bytes = head_bytes + header_line.length() + 2
    if head_bytes > max_head_size {
      return None
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
  let chunked = match headers.get("transfer-encoding") {
    Some(v) => v.to_lower().contains("chunked")
    None => false
  }
  let expect_continue = match headers.get("expect") {
    Some(v) => v.to_lower().contains("100-continue")
    None => false
  }
  Some({
    http_method: verb,
    target,
    version,
    headers,
    content_length,
    chunked,
    expect_continue,
  })
}

///|
/// Parse a chunked-body chunk-size line (RFC 7230 §4.1): hexadecimal, up to an
/// optional `;chunk-ext` or the line end. A non-hex character stops the scan.
fn parse_chunk_size(s : String) -> Int {
  let t = ascii_trim(s)
  let mut acc = 0
  for i = 0; i < t.length(); i = i + 1 {
    let c = t[i]
    let d = if c >= '0' && c <= '9' {
      c.to_int() - '0'.to_int()
    } else if c >= 'a' && c <= 'f' {
      c.to_int() - 'a'.to_int() + 10
    } else if c >= 'A' && c <= 'F' {
      c.to_int() - 'A'.to_int() + 10
    } else {
      return acc
    }
    acc = acc * 16 + d
  }
  acc
}

///|
/// Read a `Transfer-Encoding: chunked` request body to its decoded bytes (RFC 7230
/// §4.1): each chunk is a hex size line, that many octets, then a CRLF; a zero-size
/// chunk ends the body, after which any trailer fields up to the blank line are
/// consumed.
async fn read_chunked_body(reader : &@io.Reader) -> Bytes {
  let buf = Buffer()
  for ;; {
    let size_line = reader.read_until("\r\n")
    guard size_line is Some(sl) else { break }
    let size = parse_chunk_size(sl)
    if size <= 0 {
      // A zero chunk ends the body; drain any trailer fields to the blank line.
      for ;; {
        let t = reader.read_until("\r\n")
        guard t is Some(tl) else { break }
        if tl.length() == 0 {
          break
        }
      }
      break
    }
    buf.write_bytes(reader.read_exactly(size))
    let _ = reader.read_exactly(2) // the CRLF terminating the chunk data
  }
  buf.to_bytes()
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
  scheme~ : String,
  server_headers? : Map[String, String] = Map([]),
) -> Bool {
  let (path, query) = split_query(req.target)
  let scope = @moonasgi.Scope::Http({
    http_version: if req.version == "HTTP/1.0" {
      "1.0"
    } else {
      "1.1"
    },
    http_method: req.http_method,
    scheme,
    path,
    raw_path: @utf8.encode(path),
    query_string: @utf8.encode(query),
    root_path: "",
    headers: headers_to_pairs(req.headers),
    client: None,
    server: None,
    asgi: @moonasgi.AsgiVersion::http(),
    extensions: @moonasgi.Extensions::none(),
    state: Map([]),
  })
  let body_sent = Ref(false)
  let receive : @moonasgi.Receive = () => {
    if body_sent.val {
      @moonasgi.Event::HttpDisconnect
    } else {
      body_sent.val = true
      // Expect: 100-continue — let the client know it may send the body now.
      if req.expect_continue {
        writer.write("HTTP/1.1 100 Continue\r\n\r\n")
      }
      let body = if req.chunked {
        read_chunked_body(reader)
      } else if req.content_length == 0 {
        b""
      } else {
        reader.read_exactly(req.content_length)
      }
      @moonasgi.Event::HttpRequest(body~, more_body=false)
    }
  }
  let resp_status = Ref(200)
  let resp_headers : Ref[Array[(String, String)]] = Ref([])
  let started = Ref(false)
  let chunked = Ref(false)
  let ended = Ref(false)
  // Answer with the request's HTTP version; HTTP/1.0 has no chunked transfer-encoding,
  // so a streamed 1.0 response is framed by connection close instead.
  let is_http10 = req.version == "HTTP/1.0"
  let resp_version = if is_http10 { "HTTP/1.0" } else { "HTTP/1.1" }
  // A HEAD response carries the same headers as GET but no body (RFC 7231 §4.3.2).
  let is_head = req.http_method == "HEAD"
  let close_delimited = Ref(false)
  let head = fn(extra : String) -> String {
    let sb = StringBuilder::new()
    sb.write_string(
      "\{resp_version} \{resp_status.val} \{reason(resp_status.val)}\r\n",
    )
    let app_keys : Map[String, Bool] = Map([])
    for pair in resp_headers.val {
      let kl = pair.0.to_lower()
      app_keys[kl] = true
      if kl != "content-length" && kl != "transfer-encoding" {
        sb.write_string("\{pair.0}: \{pair.1}\r\n")
      }
    }
    // Configured server headers (e.g. `Server`) as defaults, unless the app already
    // set the same key — matching what the async HTTP server injects on the plaintext
    // path, so HTTPS responses carry them too.
    for name, value in server_headers {
      let kl = name.to_lower()
      if !app_keys.contains(kl) &&
        kl != "content-length" &&
        kl != "transfer-encoding" {
        sb.write_string("\{name}: \{value}\r\n")
      }
    }
    // Signal the connection's fate unless the app already set `Connection`: a server
    // that will close SHOULD say so (RFC 7230 §6.1), and HTTP/1.0 needs an explicit
    // `keep-alive` since it defaults to close.
    if !app_keys.contains("connection") {
      let will_keep_alive = should_keep_alive(req) && !close_delimited.val
      if !will_keep_alive {
        sb.write_string("connection: close\r\n")
      } else if is_http10 {
        sb.write_string("connection: keep-alive\r\n")
      }
    }
    sb.write_string(extra)
    sb.to_string()
  }
  let send : @moonasgi.Send = event => {
    match event {
      HttpResponseStart(status~, headers~, ..) => {
        resp_status.val = status
        resp_headers.val = headers
      }
      HttpResponseBody(body~, more_body~) =>
        if !started.val {
          started.val = true
          if !more_body {
            writer.write(head("content-length: \{body.length()}\r\n\r\n"))
            if !is_head {
              writer.write(body)
            }
            ended.val = true
          } else if is_head {
            // A HEAD response carries the framing headers a GET would but no body,
            // and no chunk terminator; the head alone completes it.
            writer.write(head("transfer-encoding: chunked\r\n\r\n"))
            ended.val = true
          } else if is_http10 {
            // No chunked on HTTP/1.0: frame the stream by closing the connection.
            close_delimited.val = true
            writer.write(head("\r\n"))
            writer.write(body)
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
        } else if close_delimited.val {
          writer.write(body)
          if !more_body {
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
  // A close-delimited response has no length signal, so the connection must close.
  should_keep_alive(req) && !close_delimited.val
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
    chunked: false,
    expect_continue: false,
  }
  assert_eq(parse_chunk_size("1a"), 26)
  assert_eq(parse_chunk_size("ff;name=v"), 255)
  assert_eq(parse_chunk_size("0"), 0)
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

///|
/// Read a (closed) pipe to its bytes — a test helper for inspecting the response a
/// `dispatch_http1` run wrote.
async fn drain_pipe(r : @pipe.PipeRead) -> Bytes {
  let buf = Buffer()
  for ;; {
    match r.read_some() {
      Some(chunk) => buf.write_bytes(chunk)
      None => break
    }
  }
  buf.to_bytes()
}

///|
/// Whether `needle` occurs anywhere in `hay` (test helper for response inspection).
fn bytes_has(hay : Bytes, needle : Bytes) -> Bool {
  let n = needle.length()
  if n == 0 {
    return true
  }
  let mut i = 0
  while i + n <= hay.length() {
    let mut j = 0
    while j < n && hay[i + j] == needle[j] {
      j = j + 1
    }
    if j == n {
      return true
    }
    i = i + 1
  }
  false
}

///|
/// Drive `dispatch_http1` for `req` with a trivial 200 app over in-memory pipes and
/// return the raw response bytes (test helper).
async fn run_h1(req : Http1Request) -> Bytes {
  let (req_r, req_w) = @pipe.pipe()
  req_w.close()
  let (resp_r, resp_w) = @pipe.pipe()
  let app : @moonasgi.AsgiApp = (_scope, _receive, send) => {
    send(
      @moonasgi.Event::HttpResponseStart(status=200, headers=[], trailers=false),
    )
    send(@moonasgi.Event::HttpResponseBody(body=b"hi", more_body=false))
  }
  let _ = dispatch_http1(app, req, req_r, resp_w, scheme="http")
  resp_w.close()
  drain_pipe(resp_r)
}

///|
async test "http1: a HEAD request keeps content-length but suppresses the body" {
  let head_resp = run_h1({ ..h1_req("HTTP/1.1"), http_method: "HEAD" })
  // The framing header a GET would send is present...
  assert_eq(bytes_has(head_resp, b"content-length: 2"), true)
  // ...but the body ("hi") is not.
  assert_eq(bytes_has(head_resp, b"hi"), false)
  // A GET on the same app does include the body.
  assert_eq(bytes_has(run_h1(h1_req("HTTP/1.1")), b"hi"), true)
}

///|
async test "http1: the response signals connection close and HTTP/1.0 keep-alive" {
  // HTTP/1.1 with Connection: close -> the response echoes connection: close.
  let close_11 = run_h1({
    ..h1_req("HTTP/1.1"),
    headers: Map([("connection", "close")]),
  })
  assert_eq(bytes_has(close_11, b"connection: close"), true)
  // HTTP/1.0 defaults to close -> connection: close.
  assert_eq(bytes_has(run_h1(h1_req("HTTP/1.0")), b"connection: close"), true)
  // HTTP/1.0 with keep-alive requested -> connection: keep-alive.
  let ka_10 = run_h1({
    ..h1_req("HTTP/1.0"),
    headers: Map([("connection", "keep-alive")]),
  })
  assert_eq(bytes_has(ka_10, b"connection: keep-alive"), true)
  // HTTP/1.1 defaults to keep-alive -> no connection: close header.
  assert_eq(bytes_has(run_h1(h1_req("HTTP/1.1")), b"connection: close"), false)
}

///|
/// A fixed Http1Request head for driving `dispatch_http1` in tests.
fn h1_req(version : String) -> Http1Request {
  {
    http_method: "GET",
    target: "/",
    version,
    headers: Map([]),
    content_length: 0,
    chunked: false,
    expect_continue: false,
  }
}

///|
async test "http1: an HTTP/1.0 request is answered with an HTTP/1.0 status line" {
  let (req_r, req_w) = @pipe.pipe()
  req_w.close()
  let (resp_r, resp_w) = @pipe.pipe()
  let app : @moonasgi.AsgiApp = (_scope, _receive, send) => {
    send(
      @moonasgi.Event::HttpResponseStart(status=200, headers=[], trailers=false),
    )
    send(@moonasgi.Event::HttpResponseBody(body=b"hi", more_body=false))
  }
  let keep = dispatch_http1(
    app,
    h1_req("HTTP/1.0"),
    req_r,
    resp_w,
    scheme="http",
  )
  resp_w.close()
  let resp = drain_pipe(resp_r)
  assert_eq(resp[0:8].to_owned() == b"HTTP/1.0", true)
  // HTTP/1.0 defaults to closing the connection.
  assert_eq(keep, false)
}

///|
async test "http1: a streamed HTTP/1.0 response is close-delimited, not chunked" {
  let (req_r, req_w) = @pipe.pipe()
  req_w.close()
  let (resp_r, resp_w) = @pipe.pipe()
  let app : @moonasgi.AsgiApp = (_scope, _receive, send) => {
    send(
      @moonasgi.Event::HttpResponseStart(status=200, headers=[], trailers=false),
    )
    send(@moonasgi.Event::HttpResponseBody(body=b"part1", more_body=true))
    send(@moonasgi.Event::HttpResponseBody(body=b"part2", more_body=false))
  }
  let keep = dispatch_http1(
    app,
    h1_req("HTTP/1.0"),
    req_r,
    resp_w,
    scheme="http",
  )
  resp_w.close()
  let resp = drain_pipe(resp_r)
  let n = resp.length()
  // HTTP/1.0 has no chunked, so the body is written raw and the response ends with the
  // last body part, not a "0\r\n\r\n" chunk terminator.
  assert_eq(resp[n - 5:n].to_owned() == b"part2", true)
  // Close-delimited framing forces the connection closed.
  assert_eq(keep, false)
}

///|
async test "http1: configured server headers ride the response, unless the app sets them" {
  // Default: the configured `server` header is written.
  let (req_r, req_w) = @pipe.pipe()
  req_w.close()
  let (resp_r, resp_w) = @pipe.pipe()
  let plain : @moonasgi.AsgiApp = (_scope, _receive, send) => {
    send(
      @moonasgi.Event::HttpResponseStart(status=200, headers=[], trailers=false),
    )
    send(@moonasgi.Event::HttpResponseBody(body=b"hi", more_body=false))
  }
  let _ = dispatch_http1(
    plain,
    h1_req("HTTP/1.1"),
    req_r,
    resp_w,
    scheme="http",
    server_headers=Map([("server", "mooncat")]),
  )
  resp_w.close()
  assert_eq(bytes_has(drain_pipe(resp_r), b"server: mooncat"), true)

  // Override: an app that sets `server` itself wins over the configured default.
  let (req_r2, req_w2) = @pipe.pipe()
  req_w2.close()
  let (resp_r2, resp_w2) = @pipe.pipe()
  let overrides : @moonasgi.AsgiApp = (_scope, _receive, send) => {
    send(
      @moonasgi.Event::HttpResponseStart(
        status=200,
        headers=[("server", "myapp")],
        trailers=false,
      ),
    )
    send(@moonasgi.Event::HttpResponseBody(body=b"hi", more_body=false))
  }
  let _ = dispatch_http1(
    overrides,
    h1_req("HTTP/1.1"),
    req_r2,
    resp_w2,
    scheme="http",
    server_headers=Map([("server", "mooncat")]),
  )
  resp_w2.close()
  let resp2 = drain_pipe(resp_r2)
  assert_eq(bytes_has(resp2, b"server: myapp"), true)
  assert_eq(bytes_has(resp2, b"server: mooncat"), false)
}

///|
async test "http1: parse detects Transfer-Encoding chunked and Expect 100-continue" {
  let (r, w) = @pipe.pipe()
  w.write(
    b"POST /u HTTP/1.1\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n",
  )
  w.close()
  guard parse_http1_request(r) is Some(req) else {
    fail("expected a parsed request")
  }
  assert_eq(req.chunked, true)
  assert_eq(req.expect_continue, true)
  assert_eq(req.http_method, "POST")
}

///|
async test "http1: a request head past the size cap is rejected" {
  @async.with_task_group(g => {
    let (r, w) = @pipe.pipe()
    // A header block well past max_head_size (16 KiB) with no terminating blank line
    // before the cap; parsing must give up with None rather than buffer on. The write
    // is larger than a pipe buffer, so it runs concurrently with the read.
    let writer = g.spawn(() => {
      let head = StringBuilder::new()
      head.write_string("GET / HTTP/1.1\r\n")
      for _i = 0; _i < 400; _i = _i + 1 {
        head.write_string("x-pad: ")
        for _j = 0; _j < 60; _j = _j + 1 {
          head.write_string("a")
        }
        head.write_string("\r\n")
      }
      w.write(@utf8.encode(head.to_string())) catch {
        _ => ()
      }
      w.close()
    })
    assert_eq(parse_http1_request(r) is None, true)
    // The parser stops reading once the cap is hit, so the writer may still be blocked
    // on the unread tail; release it now that the assertion holds.
    writer.cancel()
  })
}

///|
async test "http1: a normal small request head parses under the cap" {
  let (r, w) = @pipe.pipe()
  w.write(b"GET /ok HTTP/1.1\r\nhost: x\r\n\r\n")
  w.close()
  guard parse_http1_request(r) is Some(req) else {
    fail("expected a parsed request")
  }
  assert_eq(req.target, "/ok")
}

///|
async test "http1: a chunked request body decodes to the joined chunk data" {
  let (r, w) = @pipe.pipe()
  // Two data chunks ("hello" + " world") then the terminating zero chunk.
  w.write(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
  w.close()
  assert_eq(read_chunked_body(r) == b"hello world", true)
}

///|
async test "http1: a chunked body with a chunk extension and a trailer decodes cleanly" {
  let (r, w) = @pipe.pipe()
  // A chunk-size line carries a `;ext`, and a trailer field follows the zero chunk.
  w.write(b"4;n=v\r\ndata\r\n0\r\nx-checksum: 1\r\n\r\n")
  w.close()
  assert_eq(read_chunked_body(r) == b"data", true)
}
