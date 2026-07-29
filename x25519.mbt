// X25519 (RFC 7748) — the Curve25519 Diffie-Hellman that produces the ECDHE shared
// secret feeding the TLS 1.3 / QUIC handshake key schedule. The Montgomery ladder runs
// over the field mod 2^255-19 on core BigInt; the scalar drives the ladder from its
// clamped bytes, so no BigInt bit operations are needed. Subtractions add the prime
// first to stay non-negative rather than assume a Euclidean remainder.

///|
/// The Curve25519 field prime, 2^255 - 19 (RFC 7748 §4.1).
let x25519_p : BigInt = (1N << 255) - 19N

///|
/// The ladder constant (A-2)/4 = 121665 for Curve25519.
let x25519_a24 : BigInt = 121665N

///|
/// Little-endian bytes to a field integer.
fn x25519_le_to_int(b : Array[Int]) -> BigInt {
  let mut acc = 0N
  for i = b.length() - 1; i >= 0; i = i - 1 {
    acc = acc * 256N + BigInt::from_int(b[i])
  }
  acc
}

///|
/// A field integer to 32 little-endian bytes.
fn x25519_int_to_le32(v : BigInt) -> Bytes {
  let out = Buffer()
  let mut acc = v % x25519_p
  for _i = 0; _i < 32; _i = _i + 1 {
    out.write_byte((acc % 256N).to_int().to_byte())
    acc = acc / 256N
  }
  out.to_bytes()
}

///|
/// X25519 (RFC 7748 §5): the scalar `k` applied to u-coordinate `u`, both 32-byte
/// little-endian, returning the 32-byte little-endian result u-coordinate. The scalar
/// is clamped and the u-coordinate's high bit masked per §5.
pub fn x25519(k : Bytes, u : Bytes) -> Bytes {
  let scalar = Array::make(32, 0)
  for i = 0; i < 32; i = i + 1 {
    scalar[i] = k[i].to_int()
  }
  scalar[0] = scalar[0] & 248
  scalar[31] = scalar[31] & 127
  scalar[31] = scalar[31] | 64
  let ubytes = Array::make(32, 0)
  for i = 0; i < 32; i = i + 1 {
    ubytes[i] = u[i].to_int()
  }
  ubytes[31] = ubytes[31] & 127
  let p = x25519_p
  let x1 = x25519_le_to_int(ubytes) % p
  let mut x2 = 1N
  let mut z2 = 0N
  let mut x3 = x1
  let mut z3 = 1N
  let mut swap = 0
  for t = 254; t >= 0; t = t - 1 {
    let kt = (scalar[t / 8] >> (t % 8)) & 1
    swap = swap ^ kt
    if swap == 1 {
      let tx = x2
      x2 = x3
      x3 = tx
      let tz = z2
      z2 = z3
      z3 = tz
    }
    swap = kt
    let a = (x2 + z2) % p
    let aa = a * a % p
    let b = (x2 + p - z2) % p
    let bb = b * b % p
    let e = (aa + p - bb) % p
    let c = (x3 + z3) % p
    let d = (x3 + p - z3) % p
    let da = d * a % p
    let cb = c * b % p
    let sum = (da + cb) % p
    x3 = sum * sum % p
    let diff = (da + p - cb) % p
    z3 = x1 * (diff * diff % p) % p
    x2 = aa * bb % p
    z2 = e * ((aa + x25519_a24 * e) % p) % p
  }
  if swap == 1 {
    let tx = x2
    x2 = x3
    x3 = tx
    let tz = z2
    z2 = z3
    z3 = tz
  }
  // x2 / z2 = x2 * z2^(p-2) mod p (Fermat inverse).
  let inv = BigInt::pow(z2, p - 2N, modulus=p)
  x25519_int_to_le32(x2 * inv % p)
}

///|
/// The Curve25519 base point u=9 as a 32-byte little-endian scalar input, for turning
/// a private key into a public key: `x25519(private, x25519_base())`.
pub fn x25519_base() -> Bytes {
  let b = Buffer()
  b.write_byte(b'\x09')
  for _i = 0; _i < 31; _i = _i + 1 {
    b.write_byte(b'\x00')
  }
  b.to_bytes()
}
