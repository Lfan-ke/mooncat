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
/// Bridge one HTTP connection to a moonasgi application: build the `Scope`, a
/// `Receive` that streams the request body, and a `Send` that writes the
/// response, then drive the app.
async fn dispatch(
  app : @moonasgi.AsgiApp,
  request : @http.Request,
  body_reader : &@io.Reader,
  conn : @http.ServerConnection,
) -> Unit {
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
/// Serve a moonasgi ASGI application over native HTTP/1.1 (← uvicorn). Blocks in
/// a keep-alive accept loop until the running task is cancelled.
pub async fn serve(
  app : @moonasgi.AsgiApp,
  host? : String = "127.0.0.1",
  port? : Int = 8000,
) -> Unit {
  let addr = @socket.Addr::parse("\{host}:\{port}")
  @http.Server(addr).run_forever((request, body_reader, conn) => {
    dispatch(app, request, body_reader, conn)
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
