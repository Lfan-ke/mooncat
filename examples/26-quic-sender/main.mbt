///|
/// The assembled QUIC data path: a receive-side `StreamManager` routes STREAM
/// frames to per-stream reassembly; a send-side `QuicStreamScheduler`
/// round-robins streams capped by the frame size; the `QuicSender` packetizes
/// queued data and an ACK clears it; and a `QuicConnection` numbers its three
/// packet-number spaces and reassembles CRYPTO per level.
///
///     moon run examples/26-quic-sender --target native
#coverage.skip
fn main {
  run() catch {
    e => println("sender error: \{e}")
  }
}

///|
fn run() -> Unit raise {
  let m = @mooncat.StreamManager::new(100UL, 100UL)
  let _ = m.on_stream_frame(0UL, 3UL, b"def", false)
  let delivered = m.on_stream_frame(0UL, 0UL, b"abc", false)
  println(
    "stream mgr delivered = \"\{ascii(delivered)}\" streams=\{m.stream_count()}",
  )
  let sch = @mooncat.QuicStreamScheduler::new(
    @mooncat.QuicSendFlow::new(1000UL, 1000UL),
    300UL,
  )
  sch.queue(0UL, 500UL)
  sch.queue(4UL, 500UL)
  let d0 = next(sch)
  let d1 = next(sch)
  println(
    "scheduler: d0 stream=\{d0.stream.to_string()} len=\{d0.length.to_string()}, d1 stream=\{d1.stream.to_string()} len=\{d1.length.to_string()}",
  )
  let s = @mooncat.QuicSender::new(
    100000UL, 100000UL, 1200L, 25000L, 1000L, 8UL,
  )
  s.queue_stream(0UL, b"abcdefghij")
  s.queue_fin(0UL)
  let (pn0, f0) = poll(s, 0L)
  let (pn1, _) = poll(s, 1L)
  println(
    "sender pn0=\{pn0.to_string()} pn1=\{pn1.to_string()} first packet carries \{f0.length()} frame(s)",
  )
  let ack : @mooncat.QuicFrame = Ack(largest=1UL, delay=0UL, first_range=1UL, ranges=[])
  s.on_ack(ack, 10L)
  println("outstanding after ack = \{s.outstanding().length()}")
  let c = @mooncat.QuicConnection::new(false)
  let _ = c.next_packet_number(@mooncat.QuicLevel::Initial)
  println(
    "next initial pn=\{c.next_packet_number(@mooncat.QuicLevel::Initial).to_string()} next handshake pn=\{c.next_packet_number(@mooncat.QuicLevel::Handshake).to_string()}",
  )
  let _ = c.on_crypto_frame(@mooncat.QuicLevel::Initial, 3UL, b"def")
  println(
    "crypto reassembled = \"\{ascii(c.on_crypto_frame(@mooncat.QuicLevel::Initial, 0UL, b"abc"))}\"",
  )
}

///|
fn next(sch : @mooncat.QuicStreamScheduler) -> @mooncat.StreamSend raise {
  match sch.next() {
    Some(d) => d
    None => abort("expected a scheduling decision")
  }
}

///|
fn poll(
  s : @mooncat.QuicSender,
  now : Int64,
) -> (Int64, Array[@mooncat.QuicFrame]) raise {
  match s.poll_send(now) {
    Some(p) => p
    None => abort("expected a packet")
  }
}

///|
fn ascii(b : Bytes) -> String {
  let sb = StringBuilder::new()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(b[i].to_int().unsafe_to_char())
  }
  sb.to_string()
}
