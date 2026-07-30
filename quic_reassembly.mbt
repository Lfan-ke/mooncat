// QUIC stream reassembly (RFC 9000 §2.2): CRYPTO and STREAM frames deliver a stream's
// bytes as (offset, data) fragments that can arrive out of order, overlap, or repeat. A
// reassembler holds the fragments beyond what the reader has consumed, orders and merges
// them, and hands back the contiguous run from the read cursor. Overlapping bytes must
// be identical (the RFC forbids conflicting data); the earlier fragment's bytes are
// kept. A final size, learned from a fin bit, marks where the stream ends. Pure and
// synchronous — the same buffer serves the handshake's CRYPTO stream, application
// STREAM data, and the HTTP/3 byte stream feeding the frame reader.

///|
/// A conflicting retransmission: a fragment overlaps already-buffered data with
/// different bytes, or contradicts a known final size (RFC 9000 §2.2, §4.5).
pub suberror ReassemblyError {
  ReassemblyError(String)
}

///|
/// A stream reassembly buffer. `consumed` is the next byte offset the reader has not yet
/// taken; `intervals` are the buffered runs beyond it, sorted and non-overlapping, each
/// starting at or after `consumed`; `final_size` is the stream's total length once a fin
/// has been seen.
pub struct StreamReassembler {
  mut consumed : UInt64
  mut intervals : Array[(UInt64, Bytes)]
  mut final_size : UInt64?
}

///|
/// A fresh reassembler positioned at the start of the stream.
pub fn StreamReassembler::new() -> StreamReassembler {
  { consumed: 0, intervals: [], final_size: None }
}

///|
/// The next contiguous byte offset the reader has consumed.
pub fn StreamReassembler::consumed(self : StreamReassembler) -> UInt64 {
  self.consumed
}

///|
/// The stream's final size, if a fin has been received.
pub fn StreamReassembler::final_size(self : StreamReassembler) -> UInt64? {
  self.final_size
}

///|
/// Whether the whole stream has arrived and been read (the read cursor reached the
/// final size).
pub fn StreamReassembler::is_complete(self : StreamReassembler) -> Bool {
  match self.final_size {
    Some(size) => self.consumed == size && self.intervals.length() == 0
    None => false
  }
}

///|
/// Accept a fragment carrying `data` at `offset`, with `fin` marking it as the last. A
/// fragment wholly before the read cursor is ignored; one that overlaps buffered bytes
/// with a different value, or that contradicts a known final size, raises.
pub fn StreamReassembler::insert(
  self : StreamReassembler,
  offset : UInt64,
  data : Bytes,
  fin : Bool,
) -> Unit raise ReassemblyError {
  let end = offset + data.length().to_uint64()
  if fin {
    match self.final_size {
      Some(size) =>
        if size != end {
          raise ReassemblyError("conflicting final size")
        }
      None => self.final_size = Some(end)
    }
  }
  match self.final_size {
    Some(size) =>
      if end > size {
        raise ReassemblyError("data beyond final size")
      }
    None => ()
  }
  // Drop the portion at or before the read cursor.
  let mut start = offset
  let mut payload = data
  if start < self.consumed {
    let skip = self.consumed - start
    if skip >= payload.length().to_uint64() {
      return
    }
    payload = payload[skip.to_int():payload.length()].to_owned()
    start = self.consumed
  }
  if payload.length() == 0 {
    return
  }
  self.intervals.push((start, payload))
  self.intervals = normalize_intervals(self.intervals)
}

///|
/// Take the contiguous run of bytes starting at the read cursor, advancing it past what
/// is returned. Empty when the next expected offset has not arrived.
pub fn StreamReassembler::read(self : StreamReassembler) -> Bytes {
  let buf = Buffer()
  let mut i = 0
  while i < self.intervals.length() {
    let (start, data) = self.intervals[i]
    if start != self.consumed {
      break
    }
    buf.write_bytes(data)
    self.consumed = self.consumed + data.length().to_uint64()
    i = i + 1
  }
  if i > 0 {
    self.intervals = self.intervals[i:self.intervals.length()].to_owned()
  }
  buf.to_bytes()
}

///|
/// Sort fragments by start and merge overlapping or adjacent ones, keeping the earlier
/// fragment's bytes where they overlap and requiring the overlap to be identical.
fn normalize_intervals(
  fragments : Array[(UInt64, Bytes)],
) -> Array[(UInt64, Bytes)] raise ReassemblyError {
  let sorted = fragments.copy()
  sorted.sort_by((a, b) => a.0.compare(b.0))
  let out : Array[(UInt64, Bytes)] = []
  for fragment in sorted {
    let (start, data) = fragment
    let end = start + data.length().to_uint64()
    if out.length() == 0 {
      out.push((start, data))
      continue
    }
    let (last_start, last_data) = out[out.length() - 1]
    let last_end = last_start + last_data.length().to_uint64()
    if start > last_end {
      out.push((start, data))
    } else if end > last_end {
      // Overlap or adjacency that extends the run: verify the shared bytes match, then
      // append only the tail beyond the existing end.
      check_overlap(last_start, last_data, start, data)
      let tail_from = (last_end - start).to_int()
      let tail = data[tail_from:data.length()].to_owned()
      out[out.length() - 1] = (last_start, bytes_concat(last_data, tail))
    } else {
      // Fully covered by the existing run; the overlap must still match.
      check_overlap(last_start, last_data, start, data)
    }
  }
  out
}

///|
/// Verify that where `[bstart, bstart+b.len)` overlaps `[astart, astart+a.len)` the
/// bytes agree (RFC 9000 §2.2: retransmitted data must be identical).
fn check_overlap(
  astart : UInt64,
  a : Bytes,
  bstart : UInt64,
  b : Bytes,
) -> Unit raise ReassemblyError {
  let a_end = astart + a.length().to_uint64()
  let overlap_end = if a_end < bstart + b.length().to_uint64() {
    a_end
  } else {
    bstart + b.length().to_uint64()
  }
  let mut pos = bstart
  while pos < overlap_end {
    let ai = (pos - astart).to_int()
    let bi = (pos - bstart).to_int()
    if a[ai] != b[bi] {
      raise ReassemblyError("overlapping fragments disagree")
    }
    pos = pos + 1
  }
}

///|
/// Concatenate two byte strings.
fn bytes_concat(a : Bytes, b : Bytes) -> Bytes {
  let buf = Buffer()
  buf.write_bytes(a)
  buf.write_bytes(b)
  buf.to_bytes()
}
