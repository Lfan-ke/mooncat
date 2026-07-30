// ASN.1 Distinguished Encoding Rules (X.690): the type-length-value encoding X.509 certificates
// are built from. Every value is a tag byte, a definite length (short form under 128, long form
// above), and the contents; the constructed types (SEQUENCE, SET) concatenate their members,
// and the primitives (INTEGER, OID, BIT STRING, …) carry their canonical minimal encoding. This
// is the byte layer mooncat's real X.509 server certificate is assembled on, the shape curl
// parses.

///|
/// Encode a definite length (X.690 §8.1.3): the short form is the single byte for lengths under
/// 128; the long form is `0x80 | n` followed by the length in `n` big-endian bytes.
pub fn der_length(n : Int) -> Bytes {
  if n < 128 {
    let b = Buffer()
    b.write_byte(n.to_byte())
    b.to_bytes()
  } else {
    let digits = []
    let mut m = n
    while m > 0 {
      digits.push(m % 256)
      m = m / 256
    }
    let be = digits.rev()
    let buf = Buffer()
    buf.write_byte((0x80 | be.length()).to_byte())
    for d in be {
      buf.write_byte(d.to_byte())
    }
    buf.to_bytes()
  }
}

///|
/// A tag-length-value: the `tag` byte, the definite length of `value`, then `value`.
pub fn der_tlv(tag : Int, value : Bytes) -> Bytes {
  let buf = Buffer()
  buf.write_byte(tag.to_byte())
  buf.write_bytes(der_length(value.length())[:])
  buf.write_bytes(value[:])
  buf.to_bytes()
}

///|
/// A DER INTEGER (tag 0x02) from a big-endian magnitude: strip redundant leading zero bytes,
/// then prepend one 0x00 if the top bit is set, so the value stays non-negative (X.690 §8.3).
pub fn der_integer(magnitude : Bytes) -> Bytes {
  if magnitude.length() == 0 {
    return der_tlv(0x02, b"\x00")
  }
  let mut start = 0
  while start < magnitude.length() - 1 && magnitude[start] == b'\x00' {
    start = start + 1
  }
  let stripped = magnitude[start:magnitude.length()].to_owned()
  let value = if (stripped[0].to_int() & 0x80) != 0 {
    let buf = Buffer()
    buf.write_byte(b'\x00')
    buf.write_bytes(stripped[:])
    buf.to_bytes()
  } else {
    stripped
  }
  der_tlv(0x02, value)
}

///|
/// A DER OBJECT IDENTIFIER (tag 0x06) from its arcs (X.690 §8.19): the first byte encodes
/// `40·arc1 + arc2`, and each later arc is base-128 big-endian with the high bit set on every
/// byte but the last.
pub fn der_oid(arcs : Array[Int]) -> Bytes {
  let body = Buffer()
  body.write_byte((40 * arcs[0] + arcs[1]).to_byte())
  for i = 2; i < arcs.length(); i = i + 1 {
    let v = arcs[i]
    let digits = []
    let mut n = v
    if n == 0 {
      digits.push(0)
    }
    while n > 0 {
      digits.push(n % 128)
      n = n / 128
    }
    let be = digits.rev()
    for j = 0; j < be.length(); j = j + 1 {
      let last = j == be.length() - 1
      body.write_byte((if last { be[j] } else { be[j] | 0x80 }).to_byte())
    }
  }
  der_tlv(0x06, body.to_bytes())
}

///|
/// A DER BIT STRING (tag 0x03) with no unused trailing bits: a leading 0x00 count then `content`.
pub fn der_bit_string(content : Bytes) -> Bytes {
  let buf = Buffer()
  buf.write_byte(b'\x00')
  buf.write_bytes(content[:])
  der_tlv(0x03, buf.to_bytes())
}

///|
/// A DER OCTET STRING (tag 0x04).
pub fn der_octet_string(content : Bytes) -> Bytes {
  der_tlv(0x04, content)
}

///|
/// A DER SEQUENCE (tag 0x30): the concatenated `elements`.
pub fn der_sequence(elements : Array[Bytes]) -> Bytes {
  let buf = Buffer()
  for e in elements {
    buf.write_bytes(e[:])
  }
  der_tlv(0x30, buf.to_bytes())
}

///|
/// A DER SET (tag 0x31): the concatenated `elements`.
pub fn der_set(elements : Array[Bytes]) -> Bytes {
  let buf = Buffer()
  for e in elements {
    buf.write_bytes(e[:])
  }
  der_tlv(0x31, buf.to_bytes())
}

///|
/// A DER NULL (tag 0x05, empty).
pub fn der_null() -> Bytes {
  der_tlv(0x05, b"")
}

///|
/// A context-specific constructed value `[tag_num]` wrapping `content` (tag `0xA0 | tag_num`) —
/// the EXPLICIT tagging X.509 uses for the certificate version and extensions.
pub fn der_explicit(tag_num : Int, content : Bytes) -> Bytes {
  der_tlv(0xa0 | tag_num, content)
}
