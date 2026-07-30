// The ALPN extension wire format (RFC 7301 §3.1) and the h3 negotiation a real HTTP/3
// client and a mooncat server carry out.

///|
test "alpn: a single-protocol list encodes to the exact RFC 7301 wire form" {
  // ProtocolNameList = u16 list length (0x0003), then 0x02 'h' '3'.
  assert_eq(tls_encode_alpn([alpn_h3]), b"\x00\x03\x02h3")
  assert_eq(tls_decode_alpn(b"\x00\x03\x02h3"[:]), [alpn_h3])
}

///|
test "alpn: a preference list round-trips in order" {
  let offered = ["h3", "h2", "http/1.1"]
  let wire = tls_encode_alpn(offered)
  // 0x02 h3 | 0x02 h2 | 0x08 http/1.1  → inner length 0x02+2 + 0x02+2 + 0x08+1 = 15 (0x000f).
  assert_eq(wire[0].to_int(), 0x00)
  assert_eq(wire[1].to_int(), 0x0f)
  assert_eq(tls_decode_alpn(wire[:]), offered)
}

///|
test "alpn: client offers h3 and the server selects it through the extensions" {
  // A ClientHello offering h3 (and h2 as a fallback); the client's offered list reads back.
  let client_exts : Array[TlsExtension] = [tls_alpn_extension(["h3", "h2"])]
  assert_eq(tls_client_hello_alpn(client_exts), ["h3", "h2"])
  // The server's EncryptedExtensions name the single protocol it picked.
  let server_exts : Array[TlsExtension] = [tls_alpn_extension([alpn_h3])]
  assert_eq(tls_selected_alpn(server_exts), Some("h3"))
  // No ALPN extension at all: nothing offered, nothing selected.
  assert_eq(tls_client_hello_alpn([]), [])
  assert_eq(tls_selected_alpn([]), None)
}
