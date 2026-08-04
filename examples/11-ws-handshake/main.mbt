///|
/// The WebSocket opening handshake (RFC 6455 §4.2): the server proves it
/// understood the upgrade by returning `Sec-WebSocket-Accept` = base64(SHA-1(key
/// + GUID)), and echoes the one subprotocol it selected. The accept key matches
/// the RFC's own worked example, and the full 101 response is printed.
///
///     moon run examples/11-ws-handshake --target native
#coverage.skip
fn main {
  let key = "dGhlIHNhbXBsZSBub25jZQ=="
  let accept = @mooncat.websocket_accept_key(key)
  println("guid             = \{@mooncat.websocket_guid}")
  println("accept           = \{accept}")
  println("matches RFC 6455 = \{accept == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="}")
  let picked = @mooncat.websocket_select_subprotocol(["chat", "superchat"], [
    "superchat", "chat",
  ])
  println("selected sub     = \{opt_s(picked)}")
  println("--- 101 Switching Protocols ---")
  println(
    ascii(
      @mooncat.websocket_handshake_response(key, picked, [
        ("x-server", "mooncat"),
      ]),
    ),
  )
}

///|
fn ascii(b : Bytes) -> String {
  let sb = StringBuilder::new()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(b[i].to_int().unsafe_to_char())
  }
  sb.to_string()
}

///|
fn opt_s(o : String?) -> String {
  match o {
    Some(s) => s
    None => "(none)"
  }
}
