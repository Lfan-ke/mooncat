// Serving HTTP/3 requests on request streams (RFC 9114 §4.1).

///|
fn h3_header(headers : Array[(String, String)], name : String) -> String {
  for h in headers {
    if h.0 == name {
      return h.1
    }
  }
  ""
}

///|
test "http3 server: parses a request stream into its pseudo-headers, headers, and body" {
  let stream = http3_request(
    "POST",
    "https",
    "lfanke.example",
    "/submit",
    [("content-type", "text/plain")],
    b"payload",
  )
  let req = match http3_parse_request(stream) {
    Some(r) => r
    None => abort("expected a valid request")
  }
  assert_eq(req.meth, "POST")
  assert_eq(req.scheme, "https")
  assert_eq(req.authority, "lfanke.example")
  assert_eq(req.path, "/submit")
  assert_eq(req.headers, [("content-type", "text/plain")]) // pseudo-headers stripped
  assert_eq(req.body, b"payload")
}

///|
test "http3 server: routes a request through a handler and encodes the response" {
  let stream = http3_request(
    "GET",
    "https",
    "lfanke.example",
    "/hello",
    [],
    b"",
  )
  let handler = fn(r : Http3Request) -> Http3Response {
    if r.path == "/hello" {
      Http3Response::{
        status: "200",
        headers: [("content-type", "text/plain")],
        body: b"hi from mooncat",
      }
    } else {
      Http3Response::{ status: "404", headers: [], body: b"", }
    }
  }
  let resp = http3_serve(stream, handler)
  let (headers, body) = http3_decode_message(resp)
  assert_eq(h3_header(headers, ":status"), "200")
  assert_eq(body, b"hi from mooncat")
}

///|
test "http3 server: a request stream without pseudo-headers is answered 400" {
  let stream = http3_encode_message([("x-custom", "y")], b"") // no :method / :path
  let resp = http3_serve(stream, fn(_r) {
    Http3Response::{ status: "200", headers: [], body: b"", }
  })
  let (headers, _) = http3_decode_message(resp)
  assert_eq(h3_header(headers, ":status"), "400")
}
