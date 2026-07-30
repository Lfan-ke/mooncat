// Mapping HTTP messages onto HTTP/3 request/response streams (RFC 9114 §4.1): HEADERS +
// DATA frames carrying a QPACK field section and the body.

///|
test "http3 message: a GET request round-trips" {
  let wire = http3_request(
    "GET",
    "https",
    "example.com",
    "/index.html",
    [("user-agent", "mooncat"), ("accept", "text/html")],
    b"",
  )
  let (headers, body) = http3_decode_message(wire)
  assert_eq(headers, [
    (":method", "GET"),
    (":scheme", "https"),
    (":authority", "example.com"),
    (":path", "/index.html"),
    ("user-agent", "mooncat"),
    ("accept", "text/html"),
  ])
  assert_eq(body, b"")
}

///|
test "http3 message: a POST request carries a body" {
  let payload = b"{\"name\":\"mooncat\"}"
  let wire = http3_request(
    "POST",
    "https",
    "api.example.com",
    "/submit",
    [("content-type", "application/json")],
    payload,
  )
  let (headers, body) = http3_decode_message(wire)
  assert_eq(headers, [
    (":method", "POST"),
    (":scheme", "https"),
    (":authority", "api.example.com"),
    (":path", "/submit"),
    ("content-type", "application/json"),
  ])
  assert_eq(body, payload)
}

///|
test "http3 message: a response round-trips with status and body" {
  let wire = http3_response(
    "200",
    [("content-type", "text/html"), ("server", "mooncat")],
    b"<h1>ok</h1>",
  )
  let (headers, body) = http3_decode_message(wire)
  assert_eq(headers, [
    (":status", "200"),
    ("content-type", "text/html"),
    ("server", "mooncat"),
  ])
  assert_eq(body, b"<h1>ok</h1>")
}

///|
test "http3 message: a body split across multiple DATA frames reassembles" {
  // Hand-build a stream: HEADERS, then two DATA frames.
  let buf = Buffer()
  buf.write_bytes(
    http3_frame_encode(
      Headers(qpack_encode_field_section([(":status", "200")])),
    ),
  )
  buf.write_bytes(http3_frame_encode(Data(b"hello ")))
  buf.write_bytes(http3_frame_encode(Data(b"world")))
  let (headers, body) = http3_decode_message(buf.to_bytes())
  assert_eq(headers, [(":status", "200")])
  assert_eq(body, b"hello world")
}
