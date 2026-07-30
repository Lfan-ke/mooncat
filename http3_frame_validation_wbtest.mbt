// Frame placement rules across stream kinds (RFC 9114 §7.2).

///|
test "http3 frame validation: DATA and HEADERS ride request/push streams, not control" {
  assert_eq(http3_frame_allowed(Data(b"x"), RequestCtx), true)
  assert_eq(http3_frame_allowed(Headers(b"x"), PushCtx), true)
  assert_eq(http3_frame_allowed(Data(b"x"), ControlCtx), false)
  assert_eq(http3_frame_allowed(Headers(b"x"), ControlCtx), false)
}

///|
test "http3 frame validation: SETTINGS/GOAWAY/MAX_PUSH_ID/CANCEL_PUSH ride only the control stream" {
  assert_eq(http3_frame_allowed(Settings([(0x01UL, 4096UL)]), ControlCtx), true)
  assert_eq(http3_frame_allowed(GoAway(4UL), ControlCtx), true)
  assert_eq(http3_frame_allowed(MaxPushId(9UL), ControlCtx), true)
  assert_eq(http3_frame_allowed(CancelPush(2UL), ControlCtx), true)
  assert_eq(http3_frame_allowed(Settings([]), RequestCtx), false)
  assert_eq(http3_frame_allowed(GoAway(4UL), RequestCtx), false)
}

///|
test "http3 frame validation: PUSH_PROMISE rides a request stream; greased reserved rides anywhere" {
  assert_eq(http3_frame_allowed(PushPromise(1UL, b"h"), RequestCtx), true)
  assert_eq(http3_frame_allowed(PushPromise(1UL, b"h"), ControlCtx), false)
  assert_eq(http3_frame_allowed(Reserved(0x21UL, b""), ControlCtx), true)
  assert_eq(http3_frame_allowed(Reserved(0x21UL, b""), RequestCtx), true)
}

///|
test "http3 frame validation: HTTP/2-reserved frame types are a connection error on any stream" {
  for ctx in [ControlCtx, RequestCtx, PushCtx] {
    assert_eq(http3_frame_allowed(ReservedHttp2(0x02UL), ctx), false)
    assert_eq(http3_frame_allowed(ReservedHttp2(0x06UL), ctx), false)
  }
}

///|
test "http3 frame validation: http3_check_frame raises on a misplaced frame" {
  // A well-placed frame passes.
  http3_check_frame(Data(b"x"), RequestCtx)
  // SETTINGS on a request stream is rejected.
  let rejected = try {
    http3_check_frame(Settings([]), RequestCtx)
    false
  } catch {
    _ => true
  }
  assert_eq(rejected, true)
}
