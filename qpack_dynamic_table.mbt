// The QPACK dynamic table (RFC 9204 §3.2): a FIFO of name/value entries that the encoder-
// stream instructions drive. Each entry costs `name.length() + value.length() + 32` toward
// the table size (§3.2.1); inserting evicts the oldest entries until the newcomer fits, or
// fails if it can never fit (§3.2.2). Entries keep a stable absolute index across evictions
// (§3.2.4); the encoder stream addresses them by a relative index counted back from the most
// recent insertion (§3.2.5). Applying an instruction resolves its name — from the static
// table, from a dynamic entry, or a literal — and inserts. This is the table the field-line
// decoder will read once dynamic references are enabled.

///|
/// A QPACK dynamic table: the live entries, the bytes they occupy, the capacity, the count
/// of entries ever inserted (the next absolute index), and how many have been evicted.
pub(all) struct QpackDynamicTable {
  entries : Array[(Bytes, Bytes)]
  mut used : Int
  mut capacity : Int
  mut insert_count : Int
  mut dropped : Int
}

///|
/// A fresh, empty dynamic table with the given capacity in bytes.
pub fn QpackDynamicTable::new(capacity : Int) -> QpackDynamicTable {
  { entries: [], used: 0, capacity, insert_count: 0, dropped: 0 }
}

///|
/// The size an entry occupies in the table: its name and value octets plus 32 (RFC 9204
/// §3.2.1).
pub fn qpack_entry_size(name : Bytes, value : Bytes) -> Int {
  name.length() + value.length() + 32
}

///|
/// Evict oldest entries until `incoming` more bytes would fit under the capacity, or the
/// table is empty (RFC 9204 §3.2.2).
fn QpackDynamicTable::evict_to_fit(
  self : QpackDynamicTable,
  incoming : Int,
) -> Unit {
  while self.used + incoming > self.capacity && self.entries.length() > 0 {
    let (n, v) = self.entries[0]
    self.used = self.used - qpack_entry_size(n, v)
    let _ = self.entries.remove(0)
    self.dropped = self.dropped + 1
  }
}

///|
/// Set the table capacity, evicting whatever no longer fits (RFC 9204 §3.2.3).
pub fn QpackDynamicTable::set_capacity(
  self : QpackDynamicTable,
  capacity : Int,
) -> Unit {
  self.capacity = capacity
  self.evict_to_fit(0)
}

///|
/// Insert an entry, evicting as needed. Returns `false` (adding nothing) when the entry
/// cannot fit even in an empty table (RFC 9204 §3.2.2).
pub fn QpackDynamicTable::insert(
  self : QpackDynamicTable,
  name : Bytes,
  value : Bytes,
) -> Bool {
  let size = qpack_entry_size(name, value)
  self.evict_to_fit(size)
  if self.used + size > self.capacity {
    return false
  }
  self.entries.push((name, value))
  self.used = self.used + size
  self.insert_count = self.insert_count + 1
  true
}

///|
/// The entry at absolute index `abs_index`, or `None` if it has been evicted or never
/// existed (RFC 9204 §3.2.4).
pub fn QpackDynamicTable::get(
  self : QpackDynamicTable,
  abs_index : Int,
) -> (Bytes, Bytes)? {
  let pos = abs_index - self.dropped
  if pos < 0 || pos >= self.entries.length() {
    None
  } else {
    Some(self.entries[pos])
  }
}

///|
/// The entry at encoder-stream relative index `rel` (0 = most recently inserted, RFC 9204
/// §3.2.5).
pub fn QpackDynamicTable::get_relative(
  self : QpackDynamicTable,
  rel : Int,
) -> (Bytes, Bytes)? {
  self.get(self.insert_count - 1 - rel)
}

///|
/// Apply an encoder-stream instruction to the table (RFC 9204 §4.3): set the capacity, or
/// insert an entry whose name comes from the static table, a dynamic entry (by relative
/// index), or a literal. Returns whether the resulting insert fit (always `true` for a
/// capacity change). Raises if a referenced name index is out of range.
pub fn QpackDynamicTable::apply(
  self : QpackDynamicTable,
  inst : QpackEncoderInst,
) -> Bool raise QpackError {
  match inst {
    SetCapacity(capacity) => {
      self.set_capacity(capacity)
      true
    }
    InsertLiteralName(name~, value~) => self.insert(name, value)
    InsertNameRef(is_static~, index~, value~) => {
      let name = if is_static {
        match qpack_static_get(index) {
          Some((n, _)) => @utf8.encode(n)
          None =>
            raise QpackError(
              "static name index out of range: " + index.to_string(),
            )
        }
      } else {
        match self.get_relative(index) {
          Some((n, _)) => n
          None =>
            raise QpackError(
              "dynamic name index out of range: " + index.to_string(),
            )
        }
      }
      self.insert(name, value)
    }
    Duplicate(index~) =>
      match self.get_relative(index) {
        Some((n, v)) => self.insert(n, v)
        None =>
          raise QpackError("duplicate index out of range: " + index.to_string())
      }
  }
}
