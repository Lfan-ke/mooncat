// The TLS 1.3 Certificate message (RFC 8446 §4.4.2): after ServerHello and EncryptedExtensions
// the server sends its certificate chain so the peer can bind the handshake to an identity it
// trusts. The body is a certificate_request_context (empty when the server sends its
// certificate unprompted) followed by a certificate_list — each entry a DER-encoded
// certificate and its (usually empty) extensions. mooncat carries the DER opaque here; the
// CertificateVerify over this chain is a real ES256 signature (tls13_certificate_verify_*).
// This is the wire structure a QUIC/HTTP3 server's Handshake flight puts on the wire — the
// shape curl parses to authenticate the server.

///|
fn cert_write_u24(buf : Buffer, v : Int) -> Unit {
  buf.write_byte(((v >> 16) & 0xff).to_byte())
  buf.write_byte(((v >> 8) & 0xff).to_byte())
  buf.write_byte((v & 0xff).to_byte())
}

///|
fn cert_read_u24(view : BytesView, off : Int) -> Int {
  (view[off].to_int() << 16) |
  (view[off + 1].to_int() << 8) |
  view[off + 2].to_int()
}

///|
/// Encode a Certificate message body (RFC 8446 §4.4.2): the certificate_request_context (empty
/// for a server certificate sent without a CertificateRequest), then the certificate_list —
/// each entry a three-byte-length DER certificate and a two-byte-length extensions block
/// (empty here).
pub fn tls13_encode_certificate(
  certificate_request_context : Bytes,
  certs : Array[Bytes],
) -> Bytes {
  let list = Buffer()
  for cert in certs {
    cert_write_u24(list, cert.length())
    list.write_bytes(cert[:])
    list.write_byte(0)
    list.write_byte(0)
  }
  let list_bytes = list.to_bytes()
  let buf = Buffer()
  buf.write_byte((certificate_request_context.length() & 0xff).to_byte())
  buf.write_bytes(certificate_request_context[:])
  cert_write_u24(buf, list_bytes.length())
  buf.write_bytes(list_bytes[:])
  buf.to_bytes()
}

///|
/// Decode a Certificate message body into its certificate_request_context and the list of DER
/// certificates (RFC 8446 §4.4.2), skipping per-entry extensions. `None` on a truncated message.
pub fn tls13_decode_certificate(body : BytesView) -> (Bytes, Array[Bytes])? {
  if body.length() < 1 {
    return None
  }
  let ctx_len = body[0].to_int()
  let mut off = 1
  if body.length() < off + ctx_len {
    return None
  }
  let context = body[off:off + ctx_len].to_owned()
  off = off + ctx_len
  if body.length() < off + 3 {
    return None
  }
  let list_len = cert_read_u24(body, off)
  off = off + 3
  let end = off + list_len
  if body.length() < end {
    return None
  }
  let certs : Array[Bytes] = []
  while off < end {
    if end < off + 3 {
      return None
    }
    let cert_len = cert_read_u24(body, off)
    off = off + 3
    if end < off + cert_len {
      return None
    }
    certs.push(body[off:off + cert_len].to_owned())
    off = off + cert_len
    if end < off + 2 {
      return None
    }
    let ext_len = (body[off].to_int() << 8) | body[off + 1].to_int()
    off = off + 2
    if end < off + ext_len {
      return None
    }
    off = off + ext_len
  }
  Some((context, certs))
}
