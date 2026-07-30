// The Application-Layer Protocol Negotiation extension (RFC 7301): the client offers a list
// of application protocols in its ClientHello, and the server names the one it picked in its
// EncryptedExtensions (TLS 1.3) or ServerHello (TLS 1.2). For HTTP/3 the protocol is "h3"
// (RFC 9114 §3.1) — a QUIC connection that does not negotiate it is not HTTP/3. The
// extension_data is a ProtocolNameList: a two-byte list length, then each name as a one-byte
// length and its bytes. This is the wire codec that lets a real client (curl --http3) and a
// mooncat server agree they are both speaking h3.

///|
/// The application_layer_protocol_negotiation extension type (RFC 7301 §3.1).
pub let tls_ext_alpn : Int = 0x0010

///|
/// The HTTP/3 ALPN protocol identifier (RFC 9114 §3.1).
pub let alpn_h3 : String = "h3"

///|
/// Encode an ALPN ProtocolNameList (RFC 7301 §3.1): a two-byte length of the name list, then
/// each protocol as a one-byte length and its bytes.
pub fn tls_encode_alpn(protocols : Array[String]) -> Bytes {
  let inner = Buffer()
  for p in protocols {
    let name = @utf8.encode(p)
    inner.write_byte((name.length() & 0xff).to_byte())
    inner.write_bytes(name[:])
  }
  let body = inner.to_bytes()
  let buf = Buffer()
  buf.write_byte(((body.length() >> 8) & 0xff).to_byte())
  buf.write_byte((body.length() & 0xff).to_byte())
  buf.write_bytes(body[:])
  buf.to_bytes()
}

///|
/// Decode an ALPN ProtocolNameList back into its protocol names, stopping at the declared
/// list length or a truncated entry.
pub fn tls_decode_alpn(view : BytesView) -> Array[String] {
  let names : Array[String] = []
  if view.length() < 2 {
    return names
  }
  let total = (view[0].to_int() << 8) | view[1].to_int()
  let end = 2 + total
  let mut off = 2
  while off < end && off < view.length() {
    let n = view[off].to_int()
    off = off + 1
    if off + n > view.length() {
      break
    }
    names.push(@utf8.decode_lossy(view[off:off + n]))
    off = off + n
  }
  names
}

///|
/// Build an ALPN extension carrying `protocols` — the offered list in a ClientHello, or the
/// single selected protocol in a server's reply.
pub fn tls_alpn_extension(protocols : Array[String]) -> TlsExtension {
  { ext_type: tls_ext_alpn, data: tls_encode_alpn(protocols) }
}

///|
/// The protocols a ClientHello's ALPN extension offers, in order (empty if it has none).
pub fn tls_client_hello_alpn(extensions : Array[TlsExtension]) -> Array[String] {
  match tls_find_extension(extensions, tls_ext_alpn) {
    Some(ext) => tls_decode_alpn(ext.data[:])
    None => []
  }
}

///|
/// The single protocol a server's ALPN extension selected, or `None` if there is none.
pub fn tls_selected_alpn(extensions : Array[TlsExtension]) -> String? {
  match tls_find_extension(extensions, tls_ext_alpn) {
    Some(ext) => {
      let names = tls_decode_alpn(ext.data[:])
      if names.length() > 0 {
        Some(names[0])
      } else {
        None
      }
    }
    None => None
  }
}
