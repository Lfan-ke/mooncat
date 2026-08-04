# Examples

Runnable tours of the public `@mooncat` API. Each folder is a `main` package
that serves a real `@moonasgi` app over a live socket.

```bash
moon run examples/00-hello --target native
```

| # | Example | What it teaches | Key API |
| --- | --- | --- | --- |
| 00 | [`hello`](00-hello/) | Serve the smallest moonasgi app over native HTTP/1.1 | `@mooncat.serve`, `@moonasgi.AsgiApp`, `Event::HttpResponseStart`, `Event::HttpResponseBody` |

`serve` blocks in a keep-alive accept loop until its task is cancelled, so a
running example stays up — hit it from another shell:

```bash
curl http://127.0.0.1:23333
# hello from mooncat, heke1228
```

**Linux/macOS-native only.** The `moonbitlang/async` HTTP server has no JS
backend, so mooncat — and these examples — build and run on the `native`
target (`--target native`).
