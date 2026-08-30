// The TLS 1.3 alert protocol (RFC 8446 §6).

///|
test "alert: the wire form is the level then the description" {
  // §6: `struct { AlertLevel level; AlertDescription description; } Alert;` — two bytes, in
  // that order, with the §6.1/§6.2 code tables for each.
  assert_eq(
    qv_hex(tls_encode_alert(tls_warning(tls_alert_close_notify))),
    "0100",
  )
  assert_eq(
    qv_hex(tls_encode_alert(tls_fatal(tls_alert_handshake_failure))),
    "0228",
  )
  assert_eq(
    qv_hex(tls_encode_alert(tls_fatal(tls_alert_missing_extension))),
    "026d",
  )
  assert_eq(
    qv_hex(tls_encode_alert(tls_fatal(tls_alert_no_application_protocol))),
    "0278",
  )
}

///|
test "alert: decoding returns the level and description, and rejects a short read" {
  assert_eq(
    tls_decode_alert(b"\x02\x2f"[:]),
    Some(tls_fatal(tls_alert_illegal_parameter)),
  )
  assert_eq(tls_decode_alert(b"\x02"[:]), None)
  assert_eq(tls_decode_alert(b""[:]), None)
}

///|
test "alert: every alert round-trips through encode and decode" {
  let descriptions = [
    tls_alert_close_notify, tls_alert_unexpected_message, tls_alert_bad_record_mac,
    tls_alert_record_overflow, tls_alert_handshake_failure, tls_alert_bad_certificate,
    tls_alert_unsupported_certificate, tls_alert_certificate_revoked, tls_alert_certificate_expired,
    tls_alert_certificate_unknown, tls_alert_illegal_parameter, tls_alert_unknown_ca,
    tls_alert_access_denied, tls_alert_decode_error, tls_alert_decrypt_error, tls_alert_protocol_version,
    tls_alert_insufficient_security, tls_alert_internal_error, tls_alert_inappropriate_fallback,
    tls_alert_user_canceled, tls_alert_missing_extension, tls_alert_unsupported_extension,
    tls_alert_unrecognized_name, tls_alert_bad_certificate_status_response, tls_alert_unknown_psk_identity,
    tls_alert_certificate_required, tls_alert_no_application_protocol,
  ]
  for d in descriptions {
    let alert = tls_fatal(d)
    assert_eq(tls_encode_alert(alert).length(), 2)
    assert_eq(tls_decode_alert(tls_encode_alert(alert)[:]), Some(alert))
  }
}

///|
test "alert: only close_notify and user_canceled leave the connection alive" {
  // §6.1: TLS 1.3 goes by the description, so a close_notify sent at the fatal level is still
  // a shutdown and a handshake_failure sent as a warning still ends the connection.
  assert_eq(tls_alert_is_fatal(tls_warning(tls_alert_close_notify)), false)
  assert_eq(tls_alert_is_fatal(tls_fatal(tls_alert_close_notify)), false)
  assert_eq(tls_alert_is_fatal(tls_warning(tls_alert_user_canceled)), false)
  assert_eq(tls_alert_is_fatal(tls_warning(tls_alert_handshake_failure)), true)
  assert_eq(tls_alert_is_fatal(tls_fatal(tls_alert_unexpected_message)), true)
}

///|
test "alert: the server state machine reports an out-of-order message as unexpected_message" {
  // RFC 8446 A.2 — a Finished before any ClientHello.
  let early = try {
    let _ = tls_server_recv(TlsServerState::new(), 20)
    None
  } catch {
    a => Some(a)
  }
  assert_eq(early, Some(tls_fatal(tls_alert_unexpected_message)))
  // A client Certificate when none was requested.
  let s = tls_server_send_flight(
    tls_server_recv(TlsServerState::new(), 1),
    false,
  )
  let unexpected = try {
    let _ = tls_server_recv(s, 11)
    None
  } catch {
    a => Some(a)
  }
  assert_eq(unexpected, Some(tls_fatal(tls_alert_unexpected_message)))
}

///|
test "alert: sending the server flight out of turn is this endpoint's own fault" {
  // §6.2 internal_error, not unexpected_message: nothing the peer did caused it.
  let premature = try {
    let _ = tls_server_send_flight(TlsServerState::new(), false)
    None
  } catch {
    a => Some(a)
  }
  assert_eq(premature, Some(tls_fatal(tls_alert_internal_error)))
}

///|
test "alert: the client state machine reports an out-of-order message as unexpected_message" {
  // RFC 8446 A.1 — EncryptedExtensions before the ServerHello.
  let early = try {
    let _ = tls_client_next(TlsClientState::new(), 8)
    None
  } catch {
    a => Some(a)
  }
  assert_eq(early, Some(tls_fatal(tls_alert_unexpected_message)))
}
