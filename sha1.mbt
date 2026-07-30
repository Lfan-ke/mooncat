// SHA-1 (FIPS 180-4 §6.1) — needed for the WebSocket opening handshake's Sec-WebSocket-Accept
// (RFC 6455 §4.2.2), which hashes the client's key with the protocol GUID. SHA-1 is broken for
// signatures but WebSocket uses it only as a fixed handshake token, so this is the correct
// primitive there. Self-built on 32-bit words, mirroring the SHA-256 structure.

///|
/// Rotate a 32-bit word left by `n`.
fn rotl32(x : UInt, n : Int) -> UInt {
  (x << n) | (x >> (32 - n))
}

///|
/// The SHA-1 digest of `msg` (20 bytes).
pub fn sha1(msg : Bytes) -> Bytes {
  let h : Array[UInt] = [
    0x67452301U, 0xEFCDAB89U, 0x98BADCFEU, 0x10325476U, 0xC3D2E1F0U,
  ]
  // Pad: 0x80, zeros to length % 64 == 56, then the 64-bit big-endian bit length.
  let padded = Buffer()
  padded.write_bytes(msg[:])
  padded.write_byte(b'\x80')
  while padded.length() % 64 != 56 {
    padded.write_byte(b'\x00')
  }
  let bitlen = msg.length().to_int64() * 8L
  for i = 7; i >= 0; i = i - 1 {
    padded.write_byte((bitlen >> (i * 8)).to_byte())
  }
  let data = padded.to_bytes()
  let nblocks = data.length() / 64
  for blk = 0; blk < nblocks; blk = blk + 1 {
    let base = blk * 64
    let w : Array[UInt] = Array::make(80, 0U)
    for i = 0; i < 16; i = i + 1 {
      let j = base + i * 4
      w[i] = (data[j].to_int().reinterpret_as_uint() << 24) |
        (data[j + 1].to_int().reinterpret_as_uint() << 16) |
        (data[j + 2].to_int().reinterpret_as_uint() << 8) |
        data[j + 3].to_int().reinterpret_as_uint()
    }
    for i = 16; i < 80; i = i + 1 {
      w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
    }
    let mut a = h[0]
    let mut b = h[1]
    let mut c = h[2]
    let mut d = h[3]
    let mut e = h[4]
    for i = 0; i < 80; i = i + 1 {
      let (f, k) = if i < 20 {
        ((b & c) | (b.lnot() & d), 0x5A827999U)
      } else if i < 40 {
        (b ^ c ^ d, 0x6ED9EBA1U)
      } else if i < 60 {
        ((b & c) | (b & d) | (c & d), 0x8F1BBCDCU)
      } else {
        (b ^ c ^ d, 0xCA62C1D6U)
      }
      let temp = rotl32(a, 5) + f + e + k + w[i]
      e = d
      d = c
      c = rotl32(b, 30)
      b = a
      a = temp
    }
    h[0] = h[0] + a
    h[1] = h[1] + b
    h[2] = h[2] + c
    h[3] = h[3] + d
    h[4] = h[4] + e
  }
  let out = Buffer()
  for i = 0; i < 5; i = i + 1 {
    out.write_byte((h[i] >> 24).to_byte())
    out.write_byte((h[i] >> 16).to_byte())
    out.write_byte((h[i] >> 8).to_byte())
    out.write_byte(h[i].to_byte())
  }
  out.to_bytes()
}
