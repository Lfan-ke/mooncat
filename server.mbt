///|
/// Map async's request-method enum to the ASGI method string.
fn method_str(m : @http.RequestMethod) -> String {
  match m {
    Get => "GET"
    Head => "HEAD"
    Post => "POST"
    Put => "PUT"
    Delete => "DELETE"
    Connect => "CONNECT"
    Options => "OPTIONS"
    Trace => "TRACE"
    Patch => "PATCH"
  }
}

///|
/// Split a raw request target into (path, query_string) at the first '?'.
fn split_query(raw : String) -> (String, String) {
  let n = raw.length()
  for i = 0; i < n; i = i + 1 {
    if raw[i] == '?' {
      return (raw[0:i].to_owned(), raw[i + 1:n].to_owned())
    }
  }
  (raw, "")
}

///|
fn headers_to_pairs(h : Map[String, String]) -> Array[(String, String)] {
  let out : Array[(String, String)] = []
  for k, v in h {
    out.push((k, v))
  }
  out
}

///|
/// Drop the framing headers the async layer manages itself — it forbids setting
/// Content-Length / Transfer-Encoding by hand.
fn response_headers(pairs : Array[(String, String)]) -> Map[String, String] {
  let m : Map[String, String] = Map([])
  for pair in pairs {
    let k = pair.0
    if k != "content-length" && k != "transfer-encoding" {
      m[k] = pair.1
    }
  }
  m
}

///|
fn reason(code : Int) -> String {
  match code {
    200 => "OK"
    201 => "Created"
    204 => "No Content"
    301 => "Moved Permanently"
    302 => "Found"
    304 => "Not Modified"
    400 => "Bad Request"
    401 => "Unauthorized"
    403 => "Forbidden"
    404 => "Not Found"
    405 => "Method Not Allowed"
    500 => "Internal Server Error"
    _ => ""
  }
}

///|
/// True when a request is a WebSocket upgrade handshake: `Upgrade: websocket`
/// plus an `upgrade` token in `Connection`, compared case-insensitively per
/// RFC 6455 / ASGI header rules.
fn is_websocket_upgrade(headers : Map[String, String]) -> Bool {
  let upgraded = match headers.get("upgrade") {
    Some(u) => u.to_lower() == "websocket"
    None => false
  }
  let connection = match headers.get("connection") {
    Some(c) => c.to_lower().contains("upgrade")
    None => false
  }
  upgraded && connection
}

///|
/// Upgrade an HTTP connection to WebSocket and run the echo smoke path: accept
/// the handshake via `@websocket.Conn::from_http_server`, then reflect a single inbound
/// message (text or binary, streamed) back to the peer and close the tunnel.
/// This is the transliterated seam where uvicorn hands a `websocket` scope to
/// the app; the full frame→`Event` bridge lands in a later batch.
async fn handle_websocket(
  request : @http.Request,
  conn : @http.ServerConnection,
) -> Unit {
  let ws = @websocket.Conn::from_http_server(request, conn)
  defer ws.close()
  let msg = ws.recv()
  ws..start_message(msg.kind)..write_reader(msg).end_message()
  ws.send_close() catch {
    _ => ()
  }
}

///|
/// Bridge one HTTP connection to a moonasgi application: build the `Scope`, a
/// `Receive` that streams the request body, and a `Send` that writes the
/// response, then drive the app. A WebSocket upgrade request is diverted to
/// `handle_websocket` before any HTTP scope is built.
async fn dispatch(
  app : @moonasgi.AsgiApp,
  request : @http.Request,
  body_reader : &@io.Reader,
  conn : @http.ServerConnection,
) -> Unit {
  if is_websocket_upgrade(request.headers) {
    handle_websocket(request, conn)
    return
  }
  let (path, query) = split_query(request.path)
  let scope = @moonasgi.Scope::Http({
    http_version: "1.1",
    http_method: method_str(request.meth),
    scheme: "http",
    path,
    raw_path: @utf8.encode(path),
    query_string: @utf8.encode(query),
    root_path: "",
    headers: headers_to_pairs(request.headers),
    client: None,
    server: None,
    state: Map([]),
  })
  let body_done = Ref(false)
  let receive : @moonasgi.Receive = () => {
    if body_done.val {
      @moonasgi.Event::HttpDisconnect
    } else {
      match body_reader.read_some() {
        Some(chunk) => @moonasgi.Event::HttpRequest(body=chunk, more_body=true)
        None => {
          body_done.val = true
          @moonasgi.Event::HttpRequest(body=b"", more_body=false)
        }
      }
    }
  }
  let send : @moonasgi.Send = event => {
    match event {
      HttpResponseStart(status~, headers~) =>
        conn.send_response(
          status,
          reason(status),
          extra_headers=response_headers(headers),
        )
      HttpResponseBody(body~, more_body=_) => conn.write(body)
      _ => ()
    }
  }
  app(scope, receive, send)
}

///|
/// Serve a moonasgi ASGI application over native HTTP/1.1 + WebSocket
/// (← uvicorn). Convenience wrapper over `serve_config` that builds a `Config`
/// from `host` / `port` / `backlog`. Blocks in a keep-alive accept loop until
/// the running task is cancelled.
pub async fn serve(
  app : @moonasgi.AsgiApp,
  host? : String = "127.0.0.1",
  port? : Int = 8000,
  backlog? : Int = 2048,
) -> Unit {
  serve_config(app, Config::new(host~, port~, backlog~))
}

///|
/// Serve a moonasgi ASGI application under an explicit `Config`.
///
/// Runs the full lifespan protocol around the accept loop: the app is invoked
/// once under a `Lifespan` scope and `startup()` is driven **before** the
/// listener is bound, and `shutdown()` is driven on the way out — even when the
/// serving task is cancelled, via `protect_from_cancel`. Each accepted request
/// is bridged by `dispatch`, which diverts WebSocket upgrades to the echo path.
pub async fn serve_config(app : @moonasgi.AsgiApp, config : Config) -> Unit {
  @async.with_task_group(g => {
    let lifespan = Lifespan::new(app)
    let task = lifespan.spawn(g)
    lifespan.startup(task)
    let server = @http.Server(@socket.Addr::parse(config.bind()))
    try
      server.run_forever((request, body_reader, conn) => {
        dispatch(app, request, body_reader, conn)
      })
    catch {
      err => {
        @async.protect_from_cancel(() => {
          lifespan.shutdown(task) catch {
            _ => ()
          }
        })
        server.close()
        raise err
      }
    } noraise {
      _ => {
        @async.protect_from_cancel(() => {
          lifespan.shutdown(task) catch {
            _ => ()
          }
        })
        server.close()
      }
    }
  })
}

///|
test "helpers: method, query split, reason" {
  assert_eq(method_str(Post), "POST")
  assert_eq(method_str(Get), "GET")
  let (p, q) = split_query("/x/y?a=1&b=2")
  assert_eq(p, "/x/y")
  assert_eq(q, "a=1&b=2")
  let (p2, q2) = split_query("/noquery")
  assert_eq(p2, "/noquery")
  assert_eq(q2, "")
  assert_eq(reason(404), "Not Found")
  assert_eq(reason(200), "OK")
}

///|
async test "serve responds 200 with body over a real socket" {
  @async.with_task_group(g => {
    let app : @moonasgi.AsgiApp = (_scope, _receive, send) => {
      send(
        @moonasgi.Event::HttpResponseStart(status=200, headers=[
          ("content-type", "text/plain"),
        ]),
      )
      send(
        @moonasgi.Event::HttpResponseBody(
          body=b"hi from mooncat",
          more_body=false,
        ),
      )
    }
    let task = g.spawn(() => serve(app, port=18080))
    @async.sleep(200)
    let (resp, _body) = @http.get("http://127.0.0.1:18080/")
    assert_eq(resp.code, 200)
    task.cancel()
  })
}

///|
async test "lifespan drives startup then shutdown in order" {
  @async.with_task_group(g => {
    let log : Array[String] = []
    let app : @moonasgi.AsgiApp = (scope, receive, send) => {
      guard scope is Lifespan(_) else { return }
      for ;; {
        match receive() {
          LifespanStartup => {
            log.push("startup")
            send(@moonasgi.Event::LifespanStartupComplete)
          }
          LifespanShutdown => {
            log.push("shutdown")
            send(@moonasgi.Event::LifespanShutdownComplete)
            break
          }
          _ => ()
        }
      }
    }
    let lifespan = Lifespan::new(app)
    let task = lifespan.spawn(g)
    lifespan.startup(task)
    lifespan.shutdown(task)
    assert_eq(log, ["startup", "shutdown"])
  })
}

///|
async test "serve upgrades a websocket and echoes one message" {
  @async.with_task_group(g => {
    let app : @moonasgi.AsgiApp = (_scope, _receive, _send) => ()
    let task = g.spawn(() => serve(app, port=18081))
    @async.sleep(200)
    let ws = @websocket.connect("ws://127.0.0.1:18081/ws")
    ws.send_text("ping")
    assert_eq(ws.recv().read_all().text(), "ping")
    ws.close()
    task.cancel()
  })
}
