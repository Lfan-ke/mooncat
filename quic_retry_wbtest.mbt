///|
test "Retry integrity tag matches RFC 9001 Appendix A.4" {
  let odcid = qv_hexb("8394c8f03e515708")
  // The A.4 Retry packet without its trailing 16-byte integrity tag.
  let retry_body = qv_hexb("ff000000010008f067a5502a4262b5746f6b656e")
  assert_eq(
    qv_hex(quic_retry_integrity_tag(retry_body, odcid)),
    "04a265ba2eff4d829058fb3f0f2496ba",
  )
}

///|
test "a full A.4 Retry packet verifies, and tampering is rejected" {
  let odcid = qv_hexb("8394c8f03e515708")
  let retry = qv_hexb(
    "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba",
  )
  assert_eq(quic_retry_verify(retry, odcid), true)
  // A different ODCID must fail the integrity check.
  assert_eq(quic_retry_verify(retry, qv_hexb("0000000000000000")), false)
  // Flipping a token byte must fail too.
  let bad = Buffer()
  bad.write_bytes(retry[0:16])
  bad.write_byte((retry[16].to_int() ^ 0x01).to_byte())
  bad.write_bytes(retry[17:])
  assert_eq(quic_retry_verify(bad.to_bytes(), odcid), false)
}
