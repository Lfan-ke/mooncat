// AES-128-GCM (NIST SP 800-38D) — the AEAD that protects QUIC packet payloads
// (RFC 9001 §5.3, AEAD_AES_128_GCM). Authenticated encryption is CTR-mode
// confidentiality over the self-built AES-128 plus a GHASH tag over GF(2^128).

///|
/// Multiply two 128-bit blocks in GF(2^128) with the GCM reduction polynomial
/// x^128 + x^7 + x^2 + x + 1 (SP 800-38D §6.3). Blocks are big-endian, bit 0 the MSB
/// of byte 0; the algorithm is the standard right-shift-and-reduce.
fn gf_mul(x : Array[Int], y : Array[Int]) -> Array[Int] {
  let z = Array::make(16, 0)
  let v = Array::make(16, 0)
  for i = 0; i < 16; i = i + 1 {
    v[i] = x[i]
  }
  for i = 0; i < 128; i = i + 1 {
    if ((y[i / 8] >> (7 - i % 8)) & 1) == 1 {
      for j = 0; j < 16; j = j + 1 {
        z[j] = z[j] ^ v[j]
      }
    }
    let lsb = v[15] & 1
    for j = 15; j > 0; j = j - 1 {
      v[j] = ((v[j] >> 1) | ((v[j - 1] & 1) << 7)) & 0xff
    }
    v[0] = (v[0] >> 1) & 0xff
    if lsb == 1 {
      v[0] = v[0] ^ 0xe1
    }
  }
  z
}

///|
/// GHASH_H over `data` (SP 800-38D §6.4): fold each 16-byte block into the running
/// value with XOR then a GF(2^128) multiply by H. `data` must be block-aligned.
fn ghash(h : Array[Int], data : Bytes) -> Array[Int] {
  let y = Array::make(16, 0)
  let n = data.length() / 16
  for blk = 0; blk < n; blk = blk + 1 {
    for j = 0; j < 16; j = j + 1 {
      y[j] = y[j] ^ data[blk * 16 + j].to_int()
    }
    let m = gf_mul(y, h)
    for j = 0; j < 16; j = j + 1 {
      y[j] = m[j]
    }
  }
  y
}

///|
/// Increment the low 32 bits of a counter block, big-endian, mod 2^32 (inc32).
fn gcm_inc32(ctr : Array[Int]) -> Unit {
  for i = 15; i >= 12; i = i - 1 {
    ctr[i] = (ctr[i] + 1) & 0xff
    if ctr[i] != 0 {
      break
    }
  }
}

///|
/// The 16 bytes of `b` as an int array for GF work.
fn block_ints(b : Bytes) -> Array[Int] {
  let a = Array::make(16, 0)
  for i = 0; i < 16; i = i + 1 {
    a[i] = b[i].to_int()
  }
  a
}

///|
/// The 16 counter ints as a `Bytes` block for the cipher.
fn ints_block(a : Array[Int]) -> Bytes {
  let buf = Buffer()
  for i = 0; i < 16; i = i + 1 {
    buf.write_byte(a[i].to_byte())
  }
  buf.to_bytes()
}

///|
/// Append `v` as a 64-bit big-endian integer.
fn write_u64_be(buf : Buffer, v : Int64) -> Unit {
  for i = 7; i >= 0; i = i - 1 {
    buf.write_byte((v >> (i * 8)).to_byte())
  }
}

///|
/// CTR-mode keystream XOR over `input`, starting from counter block `j0` incremented
/// once (the data counter begins at J0+1, SP 800-38D §7.1).
fn gcm_gctr(schedule : Array[Int], j0 : Array[Int], input : Bytes) -> Bytes {
  let counter = Array::make(16, 0)
  for i = 0; i < 16; i = i + 1 {
    counter[i] = j0[i]
  }
  gcm_inc32(counter)
  let out = Buffer()
  let mut off = 0
  while off < input.length() {
    let ks = aes128_encrypt_block(schedule, ints_block(counter))
    let n = if input.length() - off < 16 { input.length() - off } else { 16 }
    for j = 0; j < n; j = j + 1 {
      out.write_byte((input[off + j].to_int() ^ ks[j].to_int()).to_byte())
    }
    gcm_inc32(counter)
    off = off + 16
  }
  out.to_bytes()
}

///|
/// Assemble the GHASH input for `aad` and `ciphertext`: each zero-padded to a block
/// boundary, then a final block of their bit lengths as two 64-bit integers.
fn gcm_ghash_input(aad : Bytes, ciphertext : Bytes) -> Bytes {
  let buf = Buffer()
  buf.write_bytes(aad[:])
  while buf.length() % 16 != 0 {
    buf.write_byte(b'\x00')
  }
  buf.write_bytes(ciphertext[:])
  while buf.length() % 16 != 0 {
    buf.write_byte(b'\x00')
  }
  write_u64_be(buf, aad.length().to_int64() * 8L)
  write_u64_be(buf, ciphertext.length().to_int64() * 8L)
  buf.to_bytes()
}

///|
/// The GCM tag for `ciphertext` under key schedule and hash subkey `h`: the AEAD tag
/// is `E(J0) XOR GHASH_H(A || C || lengths)` (SP 800-38D §7.1).
fn gcm_tag(
  schedule : Array[Int],
  h : Array[Int],
  j0 : Array[Int],
  aad : Bytes,
  ciphertext : Bytes,
) -> Bytes {
  let s = ghash(h, gcm_ghash_input(aad, ciphertext))
  let ej0 = aes128_encrypt_block(schedule, ints_block(j0))
  let buf = Buffer()
  for i = 0; i < 16; i = i + 1 {
    buf.write_byte((ej0[i].to_int() ^ s[i]).to_byte())
  }
  buf.to_bytes()
}

///|
/// The counter block J0 for a 96-bit nonce: nonce || 0x00000001 (SP 800-38D §7.1).
fn gcm_j0(nonce : Bytes) -> Array[Int] {
  let j0 = Array::make(16, 0)
  for i = 0; i < 12; i = i + 1 {
    j0[i] = nonce[i].to_int()
  }
  j0[15] = 1
  j0
}

///|
/// AEAD_AES_128_GCM seal: encrypt `plaintext` under `key` and the 12-byte `nonce`
/// with additional data `aad`, returning `ciphertext || tag` (16-byte tag appended).
pub fn aes128_gcm_seal(
  key : Bytes,
  nonce : Bytes,
  plaintext : Bytes,
  aad : Bytes,
) -> Bytes {
  let schedule = aes128_key_schedule(key)
  let h = block_ints(aes128_encrypt_block(schedule, Bytes::make(16, b'\x00')))
  let j0 = gcm_j0(nonce)
  let ciphertext = gcm_gctr(schedule, j0, plaintext)
  let tag = gcm_tag(schedule, h, j0, aad, ciphertext)
  let out = Buffer()
  out.write_bytes(ciphertext[:])
  out.write_bytes(tag[:])
  out.to_bytes()
}

///|
/// AEAD_AES_128_GCM open: verify the trailing 16-byte tag of `packet` and, on
/// success, return the decrypted plaintext; `None` if authentication fails. The tag
/// comparison runs over all bytes to avoid a length-dependent early exit.
pub fn aes128_gcm_open(
  key : Bytes,
  nonce : Bytes,
  packet : Bytes,
  aad : Bytes,
) -> Bytes? {
  if packet.length() < 16 {
    return None
  }
  let clen = packet.length() - 16
  let ciphertext = packet[0:clen].to_owned()
  let schedule = aes128_key_schedule(key)
  let h = block_ints(aes128_encrypt_block(schedule, Bytes::make(16, b'\x00')))
  let j0 = gcm_j0(nonce)
  let expected = gcm_tag(schedule, h, j0, aad, ciphertext)
  let mut diff = 0
  for i = 0; i < 16; i = i + 1 {
    diff = diff | (expected[i].to_int() ^ packet[clen + i].to_int())
  }
  if diff != 0 {
    return None
  }
  Some(gcm_gctr(schedule, j0, ciphertext))
}
