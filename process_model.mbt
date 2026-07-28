///|
/// A handle for driving a graceful shutdown of `serve_graceful` from outside the
/// serving task (← uvicorn's `Server.should_exit` / `handle_exit`). Hand one to
/// `serve_graceful`, then call `shutdown()` from any other task to stop the
/// server: it stops accepting, waits for in-flight requests to drain, runs the
/// ASGI lifespan shutdown, and closes the listener, in that order.
///
/// Two async queues carry the handshake. `request` receives the shutdown trigger
/// (a signal delivered through the runtime's global cancellation reaches the
/// server the same way — see `serve_graceful`). `done` is posted once the
/// server has finished the whole shutdown sequence, so `shutdown()` can block
/// until the port is actually free.
pub struct ShutdownHandle {
  request : @aqueue.Queue[Unit]
  done : @aqueue.Queue[Unit]
}

///|
/// Create an idle shutdown handle with empty unbounded signal queues.
pub fn ShutdownHandle::new() -> ShutdownHandle {
  {
    request: @aqueue.Queue::Queue(kind=Unbounded),
    done: @aqueue.Queue::Queue(kind=Unbounded),
  }
}

///|
/// Request a graceful shutdown and block until the server has drained in-flight
/// requests, run lifespan shutdown, and closed the listener. Returns once the
/// listen port is free again.
pub async fn ShutdownHandle::shutdown(self : ShutdownHandle) -> Unit {
  self.request.put(())
  self.done.get()
}

///|
/// Request a graceful shutdown without waiting for it to finish.
pub async fn ShutdownHandle::request_stop(self : ShutdownHandle) -> Unit {
  self.request.put(())
}

///|
/// Serve one accepted connection through the same `dispatch` path `serve` uses,
/// looping under keep-alive until the peer closes. The graceful acceptor needs
/// its own accept loop over `@socket.TcpServer` — the async library's
/// `@http.Server::run_forever` gives no hook to stop accepting and drain — so
/// mooncat wraps each accepted socket in an `@http.ServerConnection` by hand and
/// reads requests off it directly. Building the `ServerConnection` (rather than
/// the self-built HTTP/1.1 codec the TLS path uses) is what lets the graceful
/// server handle WebSocket upgrades: `dispatch` diverts them to
/// `handle_websocket`, which needs exactly that `ServerConnection` to complete
/// the 101 handshake. `read_request` raises on a clean end-of-stream, which ends
/// the keep-alive loop; a WebSocket upgrade hijacks the connection, so the loop
/// stops after dispatching it. The connection is always closed on the way out.
async fn serve_conn(app : @moonasgi.AsgiApp, sock : @socket.Tcp) -> Unit {
  let conn = @http.ServerConnection::new(sock)
  defer conn.close()
  for ;; {
    let request = conn.read_request() catch { _ => break }
    dispatch(app, request, conn, conn)
    if is_websocket_upgrade(request.headers) {
      break
    }
  }
}

///|
/// The acceptor task: pull connections off the listener and spawn a handler for
/// each, tracking the in-flight count so the shutdown path can drain them. Runs
/// until cancelled by the shutdown coordinator.
async fn accept_loop(
  g : @async.TaskGroup[Unit],
  server : @socket.TcpServer,
  app : @moonasgi.AsgiApp,
  inflight : Ref[Int],
) -> Unit {
  for ;; {
    let (conn, _addr) = server.accept()
    g.spawn_bg(
      () => {
        inflight.val = inflight.val + 1
        serve_conn(app, conn) catch {
          _ => ()
        }
        inflight.val = inflight.val - 1
      },
      allow_failure=true,
    )
  }
}

///|
/// Wait for the in-flight request count to reach zero, giving up after
/// `timeout` milliseconds if one is set (`None` waits for the last request to
/// finish, as uvicorn does by default). Polls on a short tick because the count
/// is only mutated at handler task boundaries.
async fn drain(inflight : Ref[Int], timeout : Int?) -> Unit {
  let mut waited = 0
  for ;; {
    if inflight.val <= 0 {
      break
    }
    match timeout {
      Some(t) => if waited >= t { break }
      None => ()
    }
    @async.sleep(10)
    waited = waited + 10
  }
}

///|
/// Serve a moonasgi application with a uvicorn-style process model: a graceful
/// shutdown path over a single acceptor that spawns a concurrent handler per
/// connection.
///
/// The lifespan protocol runs as in `serve_config` — startup before the listener
/// binds, shutdown on the way out. A single acceptor task then drives accepted
/// connections through the same `dispatch` path `serve` uses (over a hand-built
/// `@http.ServerConnection`), spawning one handler task per connection so
/// requests are served concurrently — and, because it is the real
/// `ServerConnection`, WebSocket upgrades bridge here too.
///
/// Shutdown is triggered either by `handle.shutdown()` / `handle.request_stop()`
/// or by a signal the runtime turns into global cancellation (see the boundary
/// note below). Both converge on one sequence, run under `protect_from_cancel`
/// so a signal can't abort it midway: stop accepting (cancel the acceptor),
/// drain in-flight requests (bounded by `Config::graceful_timeout`), run the
/// ASGI lifespan shutdown, then close the listener.
///
/// ## Multi-worker boundary
///
/// uvicorn's `--workers` forks N OS processes that each bind the same port with
/// `SO_REUSEPORT` for multi-core parallelism. `moonbitlang/async` exposes neither
/// `SO_REUSEPORT` on `TcpServer` nor a fork primitive, and its event loop allows
/// only one outstanding `accept` per listener handle (`wait_read` guards on a
/// single waiter), so even N in-process acceptor tasks on one shared listener
/// aren't expressible — a second concurrent `accept` on the same listener aborts.
/// mooncat therefore serves from one acceptor that spawns a concurrent handler
/// per connection, which is exactly the concurrency a single uvicorn worker
/// provides on its single event loop. Multi-process fan-out is a transport limit,
/// not a behavioural choice; it lands when the async layer exposes `SO_REUSEPORT`
/// or a fork primitive.
///
/// ## Signal boundary
///
/// The only signal hook `moonbitlang/async` exposes is
/// `@signal.set_global_cancellation_signals`, which cancels the whole task tree
/// on SIGINT/SIGTERM. mooncat catches that cancellation and still runs lifespan
/// shutdown and closes the listener under `protect_from_cancel`; but a signal
/// also cancels the in-flight handler tasks, so drain-before-close is only fully
/// honoured on the programmatic `ShutdownHandle` path. That matches uvicorn's
/// own escalation: a first signal drains, a second forces exit.
pub async fn serve_graceful(
  app : @moonasgi.AsgiApp,
  config : Config,
  handle? : ShutdownHandle = ShutdownHandle::new(),
) -> Unit {
  @async.with_task_group(g => {
    let lifespan = Lifespan::new(app)
    let ltask = lifespan.spawn(g)
    lifespan.startup(ltask)
    let server = @socket.TcpServer(
      @socket.Addr::parse(config.bind()),
      dual_stack=config.dual_stack,
      reuse_addr=config.reuse_addr,
    )
    let inflight = Ref(0)
    let acceptor = g.spawn(
      () => accept_loop(g, server, app, inflight),
      allow_failure=true,
    )
    handle.request.get() catch {
      _ => ()
    }
    @async.protect_from_cancel(() => {
      acceptor.cancel()
      drain(inflight, config.graceful_timeout)
      lifespan.shutdown(ltask) catch {
        _ => ()
      }
      server.close()
      handle.done.put(())
    })
  })
}

///|
/// Watch `path` for source changes and fire `on_reload` on each batch of events
/// (← uvicorn's `--reload` file watcher). Backed by `@fs.Watcher`, which
/// debounces and reports child-file events, so a save to any file under `path`
/// triggers one reload. `on_reload` is where a supervisor re-execs the server;
/// wiring it to a `ShutdownHandle` turns a file save into a graceful restart.
/// Loops until its task is cancelled, always closing the watcher.
pub async fn reload_watch(path : String, on_reload : async () -> Unit) -> Unit {
  let watcher = @fs.Watcher::Watcher(path, report_child_event=true)
  defer watcher.close()
  for ;; {
    let events = watcher.wait()
    if events.length() > 0 {
      on_reload()
    }
  }
}

///|
/// Graceful shutdown, end to end over a real socket: a slow in-flight request is
/// still running when shutdown is triggered; the server must let it finish
/// (return `200`) before it runs lifespan shutdown, and the listener must be
/// closed afterwards. The `log` order pins the drain-then-shutdown sequence — it
/// is the assertion the mutation test flips.
async test "graceful shutdown drains in-flight, runs lifespan shutdown, then closes the listener" {
  @async.with_task_group(g => {
    let log : Array[String] = []
    let handle = ShutdownHandle::new()
    let app : @moonasgi.AsgiApp = (scope, receive, send) => {
      match scope {
        Lifespan(_) =>
          for ;; {
            match receive() {
              LifespanStartup => send(@moonasgi.Event::LifespanStartupComplete)
              LifespanShutdown => {
                log.push("lifespan-shutdown")
                send(@moonasgi.Event::LifespanShutdownComplete)
                break
              }
              _ => ()
            }
          }
        Http(_) => {
          @async.sleep(300)
          send(@moonasgi.Event::HttpResponseStart(status=200, headers=[]))
          send(
            @moonasgi.Event::HttpResponseBody(body=b"drained", more_body=false),
          )
          log.push("request-done")
        }
        _ => ()
      }
    }
    let srv = g.spawn(() => {
      serve_graceful(app, Config::new(port=18090), handle~)
    })
    @async.sleep(250)
    let client = g.spawn(() => {
      let (resp, _b) = @http.get("http://127.0.0.1:18090/")
      resp.code
    })
    @async.sleep(100)
    handle.shutdown()
    assert_eq(client.wait(), 200)
    assert_eq(log, ["request-done", "lifespan-shutdown"])
    let refused = try {
      @http.get("http://127.0.0.1:18090/") |> ignore
      false
    } catch {
      _ => true
    }
    assert_eq(refused, true)
    srv.wait()
  })
}

///|
/// A burst of concurrent requests is served while each handler holds for a beat:
/// the single acceptor spawns a handler per connection, so all eight overlap and
/// all answer `200`. Exercises the concurrent-handler fan-out under the accept
/// loop.
async test "concurrent request burst is served by per-connection handlers" {
  @async.with_task_group(g => {
    let handle = ShutdownHandle::new()
    let app : @moonasgi.AsgiApp = (scope, _receive, send) => {
      guard scope is Http(_) else { return }
      @async.sleep(80)
      send(@moonasgi.Event::HttpResponseStart(status=200, headers=[]))
      send(@moonasgi.Event::HttpResponseBody(body=b"ok", more_body=false))
    }
    let srv = g.spawn(() => {
      serve_graceful(app, Config::new(port=18091), handle~)
    })
    @async.sleep(250)
    let codes : Array[Int] = []
    let tasks : Array[@async.Task[Unit]] = []
    for _i in 0..<8 {
      tasks.push(
        g.spawn(() => {
          let (resp, _b) = @http.get("http://127.0.0.1:18091/")
          codes.push(resp.code)
        }),
      )
    }
    for t in tasks {
      t.wait()
    }
    assert_eq(codes.length(), 8)
    for c in codes {
      assert_eq(c, 200)
    }
    handle.shutdown()
    srv.wait()
  })
}

///|
/// A WebSocket round-trip under the graceful acceptor: the same `ws_echo_app` the
/// plain `serve` path uses, now hosted by `serve_graceful`. Before this batch the
/// graceful acceptor drove the self-built HTTP/1.1 codec, which can't build the
/// `@http.ServerConnection` the upgrade needs, so a `ws://` request under
/// `serve_graceful` had nowhere to go. It now runs the shared `dispatch`, so text
/// and binary frames round-trip and the client close is observed as a disconnect,
/// exactly as under `serve`.
async test "graceful serve bridges a websocket round-trip" {
  @async.with_task_group(g => {
    let handle = ShutdownHandle::new()
    let srv = g.spawn(() => {
      serve_graceful(ws_echo_app, Config::new(port=18092), handle~)
    })
    @async.sleep(250)
    let ws = @websocket.connect("ws://127.0.0.1:18092/chat")
    ws.send_text("via graceful")
    assert_eq(ws.recv().read_all().text(), "via graceful")
    ws.send_binary(b"\x01\x02\x03\xff"[:])
    assert_eq(ws.recv().read_all().binary(), b"\x01\x02\x03\xff")
    ws.send_close(code=Normal)
    ws.close()
    handle.shutdown()
    srv.wait()
  })
}

///|
/// The reload watcher fires on a genuine file change: write a file, start the
/// watcher over its directory, modify the file, and observe the callback run.
async test "reload watcher fires on a real file change" {
  @async.with_task_group(g => {
    let dir = @fs.tmpdir(prefix="mooncat-reload")
    let file = "\{dir}/app.mbt"
    @fs.write_file(file, b"one", create_mode=CreateOrTruncate)
    let hits = Ref(0)
    let task = g.spawn(() => reload_watch(dir, () => hits.val = hits.val + 1))
    @async.sleep(200)
    @fs.write_file(file, b"two", create_mode=CreateOrTruncate)
    @async.sleep(500)
    task.cancel()
    assert_eq(hits.val >= 1, true)
    @fs.rmdir(dir, recursive=true)
  })
}
