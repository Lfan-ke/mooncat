// HKDF (RFC 5869) and TLS 1.3's HKDF-Expand-Label (RFC 8446 §7.1), built on
// HMAC-SHA256. This is the key-derivation core of the QUIC-TLS handshake: RFC 9001
// §5.2 derives the Initial secrets and packet-protection keys entirely through it.

///|
/// HKDF-Extract (RFC 5869 §2.2): PRK = HMAC(salt, IKM). An empty salt is replaced by
/// a string of `HashLen` zero bytes, per the RFC.
pub fn hkdf_extract(salt : Bytes, ikm : Bytes) -> Bytes {
  let s = if salt.length() == 0 { Bytes::make(32, b'\x00') } else { salt }
  hmac_sha256(s, ikm)
}

///|
/// HKDF-Expand (RFC 5869 §2.3): T(i) = HMAC(PRK, T(i-1) || info || i), with the
/// output the concatenation of the T(i) truncated to `length`. `length` may not
/// exceed 255 * HashLen (RFC 5869 caps the counter at one byte).
pub fn hkdf_expand(prk : Bytes, info : Bytes, length : Int) -> Bytes {
  let out = Buffer()
  let mut t : Bytes = b""
  let mut counter = 1
  while out.length() < length {
    let block = Buffer()
    block.write_bytes(t[:])
    block.write_bytes(info[:])
    block.write_byte(counter.to_byte())
    t = hmac_sha256(prk, block.to_bytes())
    out.write_bytes(t[:])
    counter = counter + 1
  }
  out.to_bytes()[0:length].to_owned()
}

///|
/// HKDF-Expand-Label (RFC 8446 §7.1): expand under the structured HkdfLabel
///
///   struct { uint16 length; opaque label<7..255>; opaque context<0..255>; }
///
/// where the label is prefixed with "tls13 ". QUIC reuses this verbatim (RFC 9001).
pub fn hkdf_expand_label(
  secret : Bytes,
  label : Bytes,
  context : Bytes,
  length : Int,
) -> Bytes {
  let full = Buffer()
  full.write_bytes(b"tls13 "[:])
  full.write_bytes(label[:])
  let full_bytes = full.to_bytes()
  let hkdf_label = Buffer()
  hkdf_label.write_byte(((length >> 8) & 0xff).to_byte())
  hkdf_label.write_byte((length & 0xff).to_byte())
  hkdf_label.write_byte(full_bytes.length().to_byte())
  hkdf_label.write_bytes(full_bytes[:])
  hkdf_label.write_byte(context.length().to_byte())
  hkdf_label.write_bytes(context[:])
  hkdf_expand(secret, hkdf_label.to_bytes(), length)
}
