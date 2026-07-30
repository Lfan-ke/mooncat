// The request path with frame-placement validation (RFC 9114 §4.1 + §7.2).

///|
test "http3 request strict: a well-formed request parses, a control frame on it is rejected" {
  let req = http3_request("GET", "https", "example", "/x", [("k", "v")], b"hi")
  match http3_parse_request_strict(req) {
    Some(r) => {
      assert_eq(r.meth, "GET")
      assert_eq(r.scheme, "https")
      assert_eq(r.authority, "example")
      assert_eq(r.path, "/x")
      assert_eq(r.headers, [("k", "v")])
      assert_eq(r.body, b"hi")
    }
    None => abort("expected a parsed request")
  }
  // A SETTINGS frame belongs on the control stream; on a request stream it is H3_FRAME_UNEXPECTED.
  let tampered = bytes_concat(req, http3_frame_encode(Settings([])))
  let rejected = try {
    http3_parse_request_strict(tampered) |> ignore
    false
  } catch {
    _ => true
  }
  assert_eq(rejected, true)
}
