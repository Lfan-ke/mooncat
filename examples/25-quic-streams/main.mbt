///|
/// QUIC streams: id classification and generation (RFC 9000 §2.1, Table 1), the
/// send and receive stream state machines (§3.1, §3.2), and stream reassembly
/// (§2.2) reordering out-of-order fragments and tracking the final size from the
/// fin bit.
///
///     moon run examples/25-quic-streams --target native
#coverage.skip
fn main {
  run() catch {
    e => println("stream error: \{e}")
  }
}

///|
fn run() -> Unit raise {
  println(
    "id_of(Client,Bidi,1)=\{@mooncat.stream_id_of(Client, Bidirectional, 1UL).to_string()} (expect 4)",
  )
  println(
    "initiator(3)=\{sinit(@mooncat.stream_initiator(3UL))} direction(3)=\{sdir(@mooncat.stream_direction(3UL))}",
  )
  println(
    "is_bidi(4)=\{@mooncat.stream_is_bidi(4UL)} client_initiated(2)=\{@mooncat.stream_is_client_initiated(2UL)} sequence(23)=\{@mooncat.stream_sequence(23UL).to_string()}",
  )
  println(
    "server writable on client-uni(2)=\{@mooncat.stream_is_writable(2UL, true)} locally_initiated(1,server)=\{@mooncat.stream_is_locally_initiated(1UL, true)}",
  )
  let s1 = @mooncat.send_stream_next(Ready, Write(fin=false))
  let s2 = @mooncat.send_stream_next(s1, Write(fin=true))
  let s3 = @mooncat.send_stream_next(s2, AllAcked)
  println("send path: \{sendst(s1)} -> \{sendst(s2)} -> \{sendst(s3)}")
  let r1 = @mooncat.recv_stream_next(Recv, Receive(fin=true))
  let r2 = @mooncat.recv_stream_next(r1, AllReceived)
  let r3 = @mooncat.recv_stream_next(r2, AppRead)
  println("recv path: \{recvst(r1)} -> \{recvst(r2)} -> \{recvst(r3)}")
  let re = @mooncat.StreamReassembler::new()
  re.insert(3UL, b"def", false)
  println("read before gap filled = \"\{ascii(re.read())}\"")
  re.insert(0UL, b"abc", true)
  println(
    "read after gap filled = \"\{ascii(re.read())}\" final_size=\{opt_u(re.final_size())} complete=\{re.is_complete()}",
  )
}

///|
fn sinit(s : @mooncat.StreamInitiator) -> String {
  match s {
    Client => "Client"
    Server => "Server"
  }
}

///|
fn sdir(d : @mooncat.StreamDirection) -> String {
  match d {
    Bidirectional => "Bidirectional"
    Unidirectional => "Unidirectional"
  }
}

///|
fn sendst(s : @mooncat.SendStreamState) -> String {
  match s {
    Ready => "Ready"
    Send => "Send"
    DataSent => "DataSent"
    DataRecvd => "DataRecvd"
    ResetSent => "ResetSent"
    ResetRecvd => "ResetRecvd"
  }
}

///|
fn recvst(s : @mooncat.RecvStreamState) -> String {
  match s {
    Recv => "Recv"
    SizeKnown => "SizeKnown"
    DataReceived => "DataReceived"
    DataRead => "DataRead"
    ResetReceived => "ResetReceived"
    ResetRead => "ResetRead"
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

///|
fn opt_u(o : UInt64?) -> String {
  match o {
    Some(n) => n.to_string()
    None => "(none)"
  }
}
