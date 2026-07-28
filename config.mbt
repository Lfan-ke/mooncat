///|
/// Server configuration (← uvicorn `Config`): the bind address, the listen
/// backlog, and the HTTP/1.1 transport knobs the `moonbitlang/async` server
/// exposes. Constructed once and handed to `serve_config`.
///
/// `backlog` mirrors uvicorn's `listen(2)` backlog. The current
/// `moonbitlang/async` transport does not expose a backlog setter on its TCP
/// listener, so the value is recorded on the config for parity and future use
/// but is not yet applied to the socket — this is a transport-capability gap,
/// not a behavioural choice.
///
/// The remaining fields map one-to-one onto knobs the async server *does*
/// honour: `dual_stack` / `reuse_addr` on the listening socket, `server_headers`
/// stamped onto every response (uvicorn's `Server:` header lives here),
/// `max_connections` for the parallel-client ceiling (uvicorn's `limit_concurrency`),
/// and `allow_failure` for whether a handler error tears the whole server down.
/// Keep-alive and chunked request/response framing are handled automatically by
/// the async server (each connection loops over multiple requests, and
/// Content-Length / Transfer-Encoding are chosen by the sender), so they need no
/// explicit knob — mirroring uvicorn's default keep-alive behaviour.
pub(all) struct Config {
  host : String
  port : Int
  backlog : Int
  dual_stack : Bool
  reuse_addr : Bool
  server_headers : Map[String, String]
  max_connections : Int?
  allow_failure : Bool
}

///|
/// Build a `Config`, defaulting to uvicorn's own defaults: host `127.0.0.1`,
/// port `8000`, backlog `2048`. Transport knobs default to the async server's
/// own defaults: `reuse_addr` on (uvicorn sets `SO_REUSEADDR`), single-stack
/// binding, no extra response headers, an unbounded connection ceiling, and
/// `allow_failure` on so a single failing handler never crashes the listener.
pub fn Config::new(
  host? : String = "127.0.0.1",
  port? : Int = 8000,
  backlog? : Int = 2048,
  dual_stack? : Bool = false,
  reuse_addr? : Bool = true,
  server_headers? : Map[String, String] = Map([]),
  max_connections? : Int? = None,
  allow_failure? : Bool = true,
) -> Config {
  {
    host,
    port,
    backlog,
    dual_stack,
    reuse_addr,
    server_headers,
    max_connections,
    allow_failure,
  }
}

///|
/// The `host:port` string used to resolve the listen address.
pub fn Config::bind(self : Config) -> String {
  "\{self.host}:\{self.port}"
}
