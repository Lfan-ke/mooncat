// HelloRetryRequest (RFC 8446 §4.1.4): the one round trip a TLS 1.3 handshake is allowed to
// spend. A client guesses which groups are worth a key share and sends shares only for those;
// when the group a server picks is one the client offered in supported_groups but sent no share
// for, the server answers with a HelloRetryRequest naming that group and the client sends the
// ClientHello again with the right share. It travels as a ServerHello — same message type, same
// framing — distinguished only by a fixed random, so a client that ignores that sentinel will
// try to run a key exchange against a key_share that carries no key.

///|
/// The ServerHello.random that marks a HelloRetryRequest (RFC 8446 §4.1.3): the SHA-256 of
/// "HelloRetryRequest". A receiver must compare against it before reading the message as a
/// real ServerHello.
pub let tls13_hello_retry_random : Bytes = b"\xcf\x21\xad\x74\xe5\x9a\x61\x11\xbe\x1d\x8c\x02\x1e\x65\xb8\x91\xc2\xa2\x11\x16\x7a\xbb\x8c\x5e\x07\x9e\x09\xe2\xc8\xa8\x33\x9c"

///|
/// Encode the key_share body of a HelloRetryRequest (RFC 8446 §4.2.8): the selected group
/// alone. There is no key — asking for one is the whole point of the message.
pub fn tls_encode_key_share_retry(group : Int) -> Bytes {
  let buf = Buffer()
  ks_write_u16(buf, group)
  buf.to_bytes()
}

///|
/// The group a HelloRetryRequest's key_share body names, or `None` if it is not two bytes.
pub fn tls_decode_key_share_retry(view : BytesView) -> Int? {
  if view.length() != 2 {
    return None
  }
  Some(ks_read_u16(view, 0))
}

///|
/// A HelloRetryRequest key_share extension naming `group`.
pub fn tls_key_share_retry_extension(group : Int) -> TlsExtension {
  { ext_type: tls_ext_key_share, data: tls_encode_key_share_retry(group), }
}

///|
/// A HelloRetryRequest asking the client to come back with a key share for `group` (RFC 8446
/// §4.1.4): the sentinel random, the client's `session_id` echoed back untouched, the chosen
/// `cipher_suite`, supported_versions, and the group. It encodes through
/// `encode_server_hello` like any other ServerHello.
pub fn tls13_hello_retry_request(
  session_id : Bytes,
  cipher_suite : Int,
  group : Int,
) -> TlsServerHello {
  tls13_server_hello(tls13_hello_retry_random, session_id, cipher_suite, [
    tls_key_share_retry_extension(group),
  ])
}

///|
/// Whether a ServerHello is really a HelloRetryRequest (RFC 8446 §4.1.3).
pub fn tls13_is_hello_retry_request(sh : TlsServerHello) -> Bool {
  sh.random == tls13_hello_retry_random
}

///|
/// The group a HelloRetryRequest asks for a share of, or `None` if the message is an ordinary
/// ServerHello or carries no key_share.
pub fn tls13_hello_retry_group(sh : TlsServerHello) -> Int? {
  if !tls13_is_hello_retry_request(sh) {
    return None
  }
  match tls_find_extension(sh.extensions, tls_ext_key_share) {
    Some(ext) => tls_decode_key_share_retry(ext.data[:])
    None => None
  }
}
