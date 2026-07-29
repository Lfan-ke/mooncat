// QUIC packet numbers (RFC 9000 §17.1). A packet number is a 62-bit integer sent
// truncated to 1–4 bytes: the sender emits the fewest bytes that let the peer
// recover the full number given the largest it has seen. Signed Int64 arithmetic
// mirrors the RFC's unbounded integers (the decode window arithmetic goes negative
// for small numbers, which UInt64 would wrap).

///|
/// The number of significant bits in `n` (`n > 0`).
fn quic_bit_length(n : Int64) -> Int {
  let mut c = 0
  let mut x = n
  while x > 0L {
    c = c + 1
    x = x >> 1
  }
  c
}

///|
/// The number of bytes (1–4) needed to encode `full_pn` given the largest packet
/// number the peer has acknowledged (RFC 9000 §17.1 / A.2): enough bytes to cover
/// twice the number of unacknowledged packets, so wraparound is unambiguous. With
/// no acknowledgement yet, the count is `full_pn + 1`.
pub fn quic_pn_len(full_pn : Int64, largest_acked : Int64?) -> Int {
  let num_unacked = match largest_acked {
    Some(la) => full_pn - la
    None => full_pn + 1L
  }
  let min_bits = if num_unacked <= 0L {
    1
  } else {
    quic_bit_length(num_unacked)
  }
  let nb = (min_bits + 7) / 8
  if nb < 1 {
    1
  } else if nb > 4 {
    4
  } else {
    nb
  }
}

///|
/// Encode `full_pn` as its truncated big-endian packet number, using the shortest
/// length that is unambiguous given `largest_acked` (RFC 9000 A.2).
pub fn quic_pn_encode(full_pn : Int64, largest_acked : Int64?) -> Bytes {
  let nb = quic_pn_len(full_pn, largest_acked)
  let buf = Buffer()
  for i = nb - 1; i >= 0; i = i - 1 {
    buf.write_byte((full_pn >> (i * 8)).to_byte())
  }
  buf.to_bytes()
}

///|
/// Recover the full packet number from a `truncated_pn` of `pn_nbits` bits, given
/// the largest full packet number already received (RFC 9000 A.3): pick the value
/// congruent to `truncated_pn` that is closest to the next expected number,
/// resolving wraparound with the half-window rule.
pub fn quic_pn_decode(
  largest_pn : Int64,
  truncated_pn : Int64,
  pn_nbits : Int,
) -> Int64 {
  let expected = largest_pn + 1L
  let pn_win = 1L << pn_nbits
  let pn_hwin = pn_win >> 1
  let pn_mask = pn_win - 1L
  let candidate = (expected & pn_mask.lnot()) | truncated_pn
  if candidate <= expected - pn_hwin && candidate < (1L << 62) - pn_win {
    candidate + pn_win
  } else if candidate > expected + pn_hwin && candidate >= pn_win {
    candidate - pn_win
  } else {
    candidate
  }
}
