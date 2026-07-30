// The QPACK static table (RFC 9204 Appendix A): 99 predefined (name, value) entries,
// index 0..98, that a field line can reference instead of spelling the header out. The
// entries are transcribed verbatim from the RFC. An encoder looks an exact (name,
// value) up for an indexed field line, or a name alone for a literal-with-name-
// reference; a decoder reads an entry back by index.

///|
/// The 99 static-table entries in index order (RFC 9204 Appendix A).
let qpack_static : Array[(String, String)] = [
  (":authority", ""),
  (":path", "/"),
  ("age", "0"),
  ("content-disposition", ""),
  ("content-length", "0"),
  ("cookie", ""),
  ("date", ""),
  ("etag", ""),
  ("if-modified-since", ""),
  ("if-none-match", ""),
  ("last-modified", ""),
  ("link", ""),
  ("location", ""),
  ("referer", ""),
  ("set-cookie", ""),
  (":method", "CONNECT"),
  (":method", "DELETE"),
  (":method", "GET"),
  (":method", "HEAD"),
  (":method", "OPTIONS"),
  (":method", "POST"),
  (":method", "PUT"),
  (":scheme", "http"),
  (":scheme", "https"),
  (":status", "103"),
  (":status", "200"),
  (":status", "304"),
  (":status", "404"),
  (":status", "503"),
  ("accept", "*/*"),
  ("accept", "application/dns-message"),
  ("accept-encoding", "gzip, deflate, br"),
  ("accept-ranges", "bytes"),
  ("access-control-allow-headers", "cache-control"),
  ("access-control-allow-headers", "content-type"),
  ("access-control-allow-origin", "*"),
  ("cache-control", "max-age=0"),
  ("cache-control", "max-age=2592000"),
  ("cache-control", "max-age=604800"),
  ("cache-control", "no-cache"),
  ("cache-control", "no-store"),
  ("cache-control", "public, max-age=31536000"),
  ("content-encoding", "br"),
  ("content-encoding", "gzip"),
  ("content-type", "application/dns-message"),
  ("content-type", "application/javascript"),
  ("content-type", "application/json"),
  ("content-type", "application/x-www-form-urlencoded"),
  ("content-type", "image/gif"),
  ("content-type", "image/jpeg"),
  ("content-type", "image/png"),
  ("content-type", "text/css"),
  ("content-type", "text/html;charset=utf-8"),
  ("content-type", "text/plain"),
  ("content-type", "text/plain;charset=utf-8"),
  ("range", "bytes=0-"),
  ("strict-transport-security", "max-age=31536000"),
  ("strict-transport-security", "max-age=31536000;includesubdomains"),
  ("strict-transport-security", "max-age=31536000;includesubdomains;preload"),
  ("vary", "accept-encoding"),
  ("vary", "origin"),
  ("x-content-type-options", "nosniff"),
  ("x-xss-protection", "1; mode=block"),
  (":status", "100"),
  (":status", "204"),
  (":status", "206"),
  (":status", "302"),
  (":status", "400"),
  (":status", "403"),
  (":status", "421"),
  (":status", "425"),
  (":status", "500"),
  ("accept-language", ""),
  ("access-control-allow-credentials", "FALSE"),
  ("access-control-allow-credentials", "TRUE"),
  ("access-control-allow-headers", "*"),
  ("access-control-allow-methods", "get"),
  ("access-control-allow-methods", "get, post, options"),
  ("access-control-allow-methods", "options"),
  ("access-control-expose-headers", "content-length"),
  ("access-control-request-headers", "content-type"),
  ("access-control-request-method", "get"),
  ("access-control-request-method", "post"),
  ("alt-svc", "clear"),
  ("authorization", ""),
  (
    "content-security-policy", "script-src 'none';object-src 'none';base-uri 'none'",
  ),
  ("early-data", "1"),
  ("expect-ct", ""),
  ("forwarded", ""),
  ("if-range", ""),
  ("origin", ""),
  ("purpose", "prefetch"),
  ("server", ""),
  ("timing-allow-origin", "*"),
  ("upgrade-insecure-requests", "1"),
  ("user-agent", ""),
  ("x-forwarded-for", ""),
  ("x-frame-options", "deny"),
  ("x-frame-options", "sameorigin"),
]

///|
/// The number of entries in the QPACK static table (99).
pub fn qpack_static_len() -> Int {
  qpack_static.length()
}

///|
/// The `(name, value)` entry at `index`, or `None` if `index` is out of range.
pub fn qpack_static_get(index : Int) -> (String, String)? {
  if index < 0 || index >= qpack_static.length() {
    None
  } else {
    Some(qpack_static[index])
  }
}

///|
/// The index of the first entry whose name and value both match, for an indexed field
/// line; `None` if no entry matches exactly.
pub fn qpack_static_find(name : String, value : String) -> Int? {
  for i = 0; i < qpack_static.length(); i = i + 1 {
    let entry = qpack_static[i]
    if entry.0 == name && entry.1 == value {
      return Some(i)
    }
  }
  None
}

///|
/// The index of the first entry whose name matches (regardless of value), for a
/// literal field line with a name reference; `None` if no entry has the name.
pub fn qpack_static_find_name(name : String) -> Int? {
  for i = 0; i < qpack_static.length(); i = i + 1 {
    if qpack_static[i].0 == name {
      return Some(i)
    }
  }
  None
}
