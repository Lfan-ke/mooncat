// HMAC-SHA256 (RFC 2104 / FIPS 198-1) — keyed hashing, the extract/expand engine
// under HKDF (RFC 5869) and so under the QUIC-TLS key schedule (RFC 9001 §5).

///|
/// HMAC-SHA256 of `msg` under `key`: H((K0 ^ opad) || H((K0 ^ ipad) || msg)),
/// where K0 is `key` hashed down to 32 bytes if it exceeds the 64-byte block, then
/// right-padded with zeros to the block size (RFC 2104 §2).
pub fn hmac_sha256(key : Bytes, msg : Bytes) -> Bytes {
  let block = 64
  let k0 = Array::make(block, b'\x00')
  let shortened = if key.length() > block { sha256(key) } else { key }
  for i = 0; i < shortened.length(); i = i + 1 {
    k0[i] = shortened[i]
  }
  let inner = Buffer()
  for i = 0; i < block; i = i + 1 {
    inner.write_byte((k0[i].to_int() ^ 0x36).to_byte())
  }
  inner.write_bytes(msg[:])
  let outer = Buffer()
  for i = 0; i < block; i = i + 1 {
    outer.write_byte((k0[i].to_int() ^ 0x5c).to_byte())
  }
  outer.write_bytes(sha256(inner.to_bytes())[:])
  sha256(outer.to_bytes())
}
