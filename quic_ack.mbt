// QUIC ACK generation (RFC 9000 §19.3): a receiver records which packet numbers have
// arrived and, when it acknowledges, reports them as the Largest Acknowledged, the First
// ACK Range, and a descending list of (Gap, ACK Range Length) pairs. This is the set
// logic behind the ACK frame the packet codec already encodes — one AckRangeSet per
// packet-number space (Initial, Handshake, Application). Pure and synchronous.

///|
/// The set of received packet numbers, held as ascending, non-overlapping,
/// non-adjacent inclusive ranges `[lo, hi]`.
pub struct AckRangeSet {
  mut ranges : Array[(UInt64, UInt64)]
}

///|
/// An empty set (nothing received yet).
pub fn AckRangeSet::new() -> AckRangeSet {
  { ranges: [], }
}

///|
/// Whether nothing has been received.
pub fn AckRangeSet::is_empty(self : AckRangeSet) -> Bool {
  self.ranges.length() == 0
}

///|
/// The largest packet number received, or `None` when empty.
pub fn AckRangeSet::largest(self : AckRangeSet) -> UInt64? {
  if self.ranges.length() == 0 {
    None
  } else {
    Some(self.ranges[self.ranges.length() - 1].1)
  }
}

///|
/// Whether packet number `pn` has been received.
pub fn AckRangeSet::contains(self : AckRangeSet, pn : UInt64) -> Bool {
  for range in self.ranges {
    if pn >= range.0 && pn <= range.1 {
      return true
    }
  }
  false
}

///|
/// Record that packet number `pn` was received, coalescing it with any range it touches
/// or bridges.
pub fn AckRangeSet::add(self : AckRangeSet, pn : UInt64) -> Unit {
  self.ranges.push((pn, pn))
  self.ranges = coalesce_ranges(self.ranges)
}

///|
/// The ACK frame fields for the current set (RFC 9000 §19.3): the Largest Acknowledged,
/// the First ACK Range (how many contiguous packets below the largest are acked), and
/// the descending `(Gap, ACK Range Length)` list. `None` when nothing has been received.
pub fn AckRangeSet::to_ack_fields(
  self : AckRangeSet,
) -> (UInt64, UInt64, Array[(UInt64, UInt64)])? {
  let n = self.ranges.length()
  if n == 0 {
    return None
  }
  let (top_lo, top_hi) = self.ranges[n - 1]
  let largest = top_hi
  let first_range = top_hi - top_lo
  let pairs : Array[(UInt64, UInt64)] = []
  // Walk down from the second-highest range, encoding each relative to the smallest of
  // the range above it.
  let mut prev_smallest = top_lo
  for i = n - 2; i >= 0; i = i - 1 {
    let (lo, hi) = self.ranges[i]
    // Largest of this range = prev_smallest - Gap - 2  ->  Gap = prev_smallest - hi - 2.
    let gap = prev_smallest - hi - 2
    let length = hi - lo
    pairs.push((gap, length))
    prev_smallest = lo
  }
  Some((largest, first_range, pairs))
}

///|
/// Sort ranges by low bound and merge any that overlap or sit next to each other
/// (`lo <= hi_prev + 1`), yielding ascending, non-overlapping, non-adjacent ranges.
fn coalesce_ranges(ranges : Array[(UInt64, UInt64)]) -> Array[(UInt64, UInt64)] {
  let sorted = ranges.copy()
  sorted.sort_by((a, b) => a.0.compare(b.0))
  let out : Array[(UInt64, UInt64)] = []
  for range in sorted {
    let (lo, hi) = range
    if out.length() == 0 {
      out.push((lo, hi))
      continue
    }
    let (last_lo, last_hi) = out[out.length() - 1]
    if lo <= last_hi + 1 {
      // Overlapping or adjacent: extend the last range's upper bound if needed.
      if hi > last_hi {
        out[out.length() - 1] = (last_lo, hi)
      }
    } else {
      out.push((lo, hi))
    }
  }
  out
}

///|
/// Reconstruct the acknowledged packet-number ranges from an ACK frame's fields (the
/// inverse of `to_ack_fields`), as ascending inclusive ranges — the receiver side that
/// marks sent packets acknowledged.
pub fn ack_fields_to_ranges(
  largest : UInt64,
  first_range : UInt64,
  pairs : Array[(UInt64, UInt64)],
) -> Array[(UInt64, UInt64)] raise QuicAckError {
  let out : Array[(UInt64, UInt64)] = []
  if first_range > largest {
    raise QuicAckError("First ACK Range larger than Largest Acknowledged")
  }
  let mut smallest = largest - first_range
  out.push((smallest, largest))
  for pair in pairs {
    let (gap, length) = pair
    // Largest of the next range = smallest - Gap - 2.
    if smallest < gap + 2 {
      raise QuicAckError("ACK gap underflows the packet-number space")
    }
    let hi = smallest - gap - 2
    if length > hi {
      raise QuicAckError("ACK Range Length underflows")
    }
    let lo = hi - length
    out.push((lo, hi))
    smallest = lo
  }
  // Present ascending.
  out.rev()
}

///|
/// A malformed ACK frame's ranges.
pub suberror QuicAckError {
  QuicAckError(String)
}
