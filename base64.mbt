// Base64 (RFC 4648 §4): the standard alphabet with `=` padding. The WebSocket handshake needs
// it to encode the Sec-WebSocket-Accept digest, and it is a small, self-contained primitive, so
// mooncat carries its own rather than pull a codec dependency in for one use.

///|
fn base64_char(i : Int) -> Byte {
  if i < 26 {
    (65 + i).to_byte() // 'A'..'Z'
  } else if i < 52 {
    (97 + (i - 26)).to_byte() // 'a'..'z'
  } else if i < 62 {
    (48 + (i - 52)).to_byte() // '0'..'9'
  } else if i == 62 {
    b'+'
  } else {
    b'/'
  }
}

///|
fn base64_value(c : Int) -> Int {
  if c >= 65 && c <= 90 {
    c - 65
  } else if c >= 97 && c <= 122 {
    c - 97 + 26
  } else if c >= 48 && c <= 57 {
    c - 48 + 52
  } else if c == 43 {
    62
  } else if c == 47 {
    63
  } else {
    -1
  }
}

///|
/// Encode `data` as standard base64 with `=` padding (RFC 4648 §4).
pub fn base64_encode(data : Bytes) -> Bytes {
  let out = Buffer()
  let n = data.length()
  let mut i = 0
  while i + 3 <= n {
    let b0 = data[i].to_int()
    let b1 = data[i + 1].to_int()
    let b2 = data[i + 2].to_int()
    out.write_byte(base64_char(b0 >> 2))
    out.write_byte(base64_char(((b0 & 0x3) << 4) | (b1 >> 4)))
    out.write_byte(base64_char(((b1 & 0xf) << 2) | (b2 >> 6)))
    out.write_byte(base64_char(b2 & 0x3f))
    i = i + 3
  }
  let rem = n - i
  if rem == 1 {
    let b0 = data[i].to_int()
    out.write_byte(base64_char(b0 >> 2))
    out.write_byte(base64_char((b0 & 0x3) << 4))
    out.write_byte(b'=')
    out.write_byte(b'=')
  } else if rem == 2 {
    let b0 = data[i].to_int()
    let b1 = data[i + 1].to_int()
    out.write_byte(base64_char(b0 >> 2))
    out.write_byte(base64_char(((b0 & 0x3) << 4) | (b1 >> 4)))
    out.write_byte(base64_char((b1 & 0xf) << 2))
    out.write_byte(b'=')
  }
  out.to_bytes()
}

///|
/// Decode standard base64, ignoring padding and any non-alphabet bytes (RFC 4648 §4).
pub fn base64_decode(data : Bytes) -> Bytes {
  let vals : Array[Int] = []
  for i = 0; i < data.length(); i = i + 1 {
    let v = base64_value(data[i].to_int())
    if v >= 0 {
      vals.push(v)
    }
  }
  let out = Buffer()
  let mut i = 0
  while i + 4 <= vals.length() {
    let n = (vals[i] << 18) |
      (vals[i + 1] << 12) |
      (vals[i + 2] << 6) |
      vals[i + 3]
    out.write_byte(((n >> 16) & 0xff).to_byte())
    out.write_byte(((n >> 8) & 0xff).to_byte())
    out.write_byte((n & 0xff).to_byte())
    i = i + 4
  }
  let rem = vals.length() - i
  if rem == 2 {
    let n = (vals[i] << 18) | (vals[i + 1] << 12)
    out.write_byte(((n >> 16) & 0xff).to_byte())
  } else if rem == 3 {
    let n = (vals[i] << 18) | (vals[i + 1] << 12) | (vals[i + 2] << 6)
    out.write_byte(((n >> 16) & 0xff).to_byte())
    out.write_byte(((n >> 8) & 0xff).to_byte())
  }
  out.to_bytes()
}
