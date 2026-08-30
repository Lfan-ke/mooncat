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
///   (which reassembles fragments, answers pings, and echoes a close) — a text message becomes
///   `WebSocketReceive(text=..)`, a binary one `WebSocketReceive(bytes=..)`, and a peer close
///   `WebSocketDisconnect(code=..)`.
/// * `send(WebSocketAccept)` writes the self-built 101 (with the negotiated `Sec-WebSocket-Protocol`
///   echoed); `send(WebSocketSendText / WebSocketSendBytes)` writes a message frame;
///   `send(WebSocketClose)` writes a close frame; a close sent *before* accept declines the upgrade
///   with `403 Forbidden`, as uvicorn does.
///
/// A peer that breaks RFC 6455 fails the connection rather than being tolerated: the violation's
/// close code goes out as a close frame (§7.1.7) and the app sees a disconnect carrying that same
/// code, so an app can tell a protocol failure from a peer that simply went away (`1006`).
async fn serve_websocket_raw(
  app : @moonasgi.AsgiApp,
  req : Http1Request,
  reader : &@io.Reader,
  writer : &@io.Writer,
  config~ : Config,
  client_addr? : @socket.Addr,
) -> Unit {
  let (path, query) = split_query(req.target)
  let peer = match client_addr {
    Some(a) => Some(addr_pair(a))
    None => None
  }
  let (client, scheme) = if config.proxy_headers {
    proxy_rewrite(
      req.headers,
      peer,
      "ws",
      trusted=config.forwarded_allow_ips,
      websocket=true,
    )
  } else {
    (peer, "ws")
  }
  let scope = @moonasgi.Scope::WebSocket({
    http_version: "1.1",
    scheme,
    path,
    raw_path: @utf8.encode(path),
    query_string: @utf8.encode(query),
    root_path: config.root_path,
    headers: headers_to_pairs(req.headers),
    client,
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
      let msg : Result[WsMessage, Int] = Ok(
        ws_read_message(reader, writer, max_size=config.ws.max_size),
      ) catch {
        // A violation names the code the connection must be failed with; anything else is the
        // stream ending under us, which has no status to report.
        WsError(code, _) => Err(code)
        _ => Err(1006)
      }
      match msg {
        Err(code) => {
          closed.val = true
          if code != 1006 {
            // §7.1.7: fail the connection, but say why on the wire first.
            writer.write(
              ws_encode_frame(true, Close, ws_close_payload(code, "")),
            ) catch {
              _ => ()
            }
          }
          @moonasgi.Event::WebSocketDisconnect(code~, reason=None)
        }
        Ok(WsText(text)) =>
          @moonasgi.Event::WebSocketReceive(text=Some(text), bytes=None)
        Ok(WsBinary(bytes)) =>
          @moonasgi.Event::WebSocketReceive(text=None, bytes=Some(bytes))
        Ok(WsClose(code, _)) => {
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
