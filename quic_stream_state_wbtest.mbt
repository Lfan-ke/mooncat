// QUIC stream state-machine transitions (RFC 9000 §3.1, §3.2).

///|
test "send stream: the data path Ready -> Send -> Data Sent -> Data Recvd" {
  assert_eq(send_stream_next(Ready, Write(fin=false)), Send)
  assert_eq(send_stream_next(Send, Write(fin=false)), Send)
  assert_eq(send_stream_next(Send, Write(fin=true)), DataSent)
  assert_eq(send_stream_next(DataSent, AllAcked), DataRecvd)
  // An empty stream closed immediately with fin jumps straight to Data Sent.
  assert_eq(send_stream_next(Ready, Write(fin=true)), DataSent)
}

///|
test "send stream: reset from any pre-terminal state" {
  assert_eq(send_stream_next(Ready, ResetStream), ResetSent)
  assert_eq(send_stream_next(Send, ResetStream), ResetSent)
  assert_eq(send_stream_next(DataSent, ResetStream), ResetSent)
  assert_eq(send_stream_next(ResetSent, ResetAcked), ResetRecvd)
}

///|
test "send stream: illegal transitions raise" {
  // Writing after all data is acknowledged.
  let after_terminal = try {
    let _ = send_stream_next(DataRecvd, Write(fin=false))
    false
  } catch {
    _ => true
  }
  assert_eq(after_terminal, true)
  // Acknowledgement before anything was sent.
  let premature_ack = try {
    let _ = send_stream_next(Ready, AllAcked)
    false
  } catch {
    _ => true
  }
  assert_eq(premature_ack, true)
}

///|
test "recv stream: the data path Recv -> Size Known -> Data Recvd -> Data Read" {
  assert_eq(recv_stream_next(Recv, Receive(fin=false)), Recv)
  assert_eq(recv_stream_next(Recv, Receive(fin=true)), SizeKnown)
  assert_eq(recv_stream_next(SizeKnown, AllReceived), DataReceived)
  assert_eq(recv_stream_next(DataReceived, AppRead), DataRead)
}

///|
test "recv stream: reset path from any pre-terminal state" {
  assert_eq(recv_stream_next(Recv, ReceiveReset), ResetReceived)
  assert_eq(recv_stream_next(SizeKnown, ReceiveReset), ResetReceived)
  assert_eq(recv_stream_next(DataReceived, ReceiveReset), ResetReceived)
  assert_eq(recv_stream_next(ResetReceived, AppReadReset), ResetRead)
}

///|
test "recv stream: illegal transitions raise" {
  // Receiving more data after the application has read the whole stream.
  let after_read = try {
    let _ = recv_stream_next(DataRead, Receive(fin=false))
    false
  } catch {
    _ => true
  }
  assert_eq(after_read, true)
  // Declaring all received before the final size is known.
  let premature = try {
    let _ = recv_stream_next(Recv, AllReceived)
    false
  } catch {
    _ => true
  }
  assert_eq(premature, true)
}
