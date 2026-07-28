///|
/// Server configuration (← uvicorn `Config`): the bind address and the listen
/// backlog. Constructed once and handed to `serve_config`.
///
/// `backlog` mirrors uvicorn's `listen(2)` backlog. The current
/// `moonbitlang/async` transport does not expose a backlog setter on its TCP
/// listener, so the value is recorded on the config for parity and future use
/// but is not yet applied to the socket — this is a transport-capability gap,
/// not a behavioural choice.
pub(all) struct Config {
  host : String
  port : Int
  backlog : Int
}

///|
/// Build a `Config`, defaulting to uvicorn's own defaults: host `127.0.0.1`,
/// port `8000`, backlog `2048`.
pub fn Config::new(
  host? : String = "127.0.0.1",
  port? : Int = 8000,
  backlog? : Int = 2048,
) -> Config {
  { host, port, backlog }
}

///|
/// The `host:port` string used to resolve the listen address.
pub fn Config::bind(self : Config) -> String {
  "\{self.host}:\{self.port}"
}
