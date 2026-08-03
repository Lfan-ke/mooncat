// The WebSocket bridge over mooncat's own raw HTTP/1.1 transport (`&@io.Reader`/`&@io.Writer`), the
// self-built counterpart of `handle_websocket` (which rides the async transport's
// `Conn::from_http_server`). Because we own the 101 response here, the negotiated subprotocol is
// echoed in `Sec-WebSocket-Protocol` — the header the `from_http_server` path cannot set — and the
// frames go through mooncat's own `websocket_frame` codec.

///|
/// Bridge a WebSocket connection to a moonasgi application over the raw HTTP/1.1 stream `reader` /
/// `writer` (← uvicorn's `WSProtocol`), the raw-transport twin of `handle_websocket`:
///
/// * `receive()` yields `websocket.connect` first, then reads messages with `ws_read_message`
///   (which reassembles fragments and answers pings) — a text message becomes
///   `WebSocketReceive(text=..)`, a binary one `WebSocketReceive(bytes=..)`, and a peer close
///   `WebSocketDisconnect(code=..)`.
/// * `send(WebSocketAccept)` writes the self-built 101 (with the negotiated `Sec-WebSocket-Protocol`
///   echoed); `send(WebSocketSendText / WebSocketSendBytes)` writes a message frame;
///   `send(WebSocketClose)` writes a close frame; a close sent *before* accept declines the upgrade
///   with `403 Forbidden`, as uvicorn does.
async fn serve_websocket_raw(
  app : @moonasgi.AsgiApp,
  req : Http1Request,
  reader : &@io.Reader,
  writer : &@io.Writer,
) -> Unit {
  let (path, query) = split_query(req.target)
  let scope = @moonasgi.Scope::WebSocket({
    http_version: "1.1",
    scheme: "ws",
    path,
    raw_path: @utf8.encode(path),
    query_string: @utf8.encode(query),
    root_path: "",
    headers: headers_to_pairs(req.headers),
    client: None,
    server: None,
    subprotocols: parse_subprotocols(req.headers),
    asgi: @moonasgi.AsgiVersion::websocket(),
    extensions: @moonasgi.Extensions::none(),
    state: Map([]),
  })
  let connected = Ref(false)
  let accepted = Ref(false)
  let closed = Ref(false)
  let receive : @moonasgi.Receive = () => {
    if not_yet(connected) {
      @moonasgi.Event::WebSocketConnect
    } else if closed.val {
      @moonasgi.Event::WebSocketDisconnect(code=1006, reason=None)
    } else {
      let msg = Some(ws_read_message(reader, writer)) catch { _ => None }
      match msg {
        None => {
          closed.val = true
          @moonasgi.Event::WebSocketDisconnect(code=1006, reason=None)
        }
        Some(WsText(bytes)) =>
          @moonasgi.Event::WebSocketReceive(
            text=Some(@utf8.decode_lossy(bytes[:])),
            bytes=None,
          )
        Some(WsBinary(bytes)) =>
          @moonasgi.Event::WebSocketReceive(text=None, bytes=Some(bytes))
        Some(WsClose(code, _)) => {
          closed.val = true
          @moonasgi.Event::WebSocketDisconnect(code~, reason=None)
        }
      }
    }
  }
  let send : @moonasgi.Send = event => {
    match event {
      WebSocketAccept(subprotocol~, headers~) =>
        if !accepted.val {
          accepted.val = true
          let key = req.headers.get("sec-websocket-key").unwrap_or("")
          writer.write(websocket_handshake_response(key, subprotocol, headers))
        }
      WebSocketSendText(text) =>
        if accepted.val {
          writer.write(ws_encode_frame(true, Text, @utf8.encode(text)))
        }
      WebSocketSendBytes(data) =>
        if accepted.val {
          writer.write(ws_encode_frame(true, Binary, data))
        }
      WebSocketClose(code~, reason~) => {
        if accepted.val {
          writer.write(
            ws_encode_frame(true, Close, ws_close_payload(code, reason)),
          )
        } else {
          writer.write(@utf8.encode("HTTP/1.1 403 Forbidden\r\n\r\n"))
        }
        closed.val = true
      }
      _ => ()
    }
  }
  app(scope, receive, send)
}
