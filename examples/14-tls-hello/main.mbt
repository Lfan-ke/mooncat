///|
/// The TLS 1.3 ClientHello / ServerHello wire format (RFC 8446 §4.1) with the
/// key_share (§4.2.8) and ALPN (RFC 7301) extensions. A ClientHello carrying an
/// x25519 share and an h3/h2 ALPN offer is encoded, decoded, and its extensions
/// are read back; a ServerHello round-trips its single share.
///
///     moon run examples/14-tls-hello --target native
#coverage.skip
fn main {
  let priv_key = hexb(
    "2333333333333333333333333333333333333333333333333333333333333333",
  )
  let pub_key = @mooncat.tls13_x25519_public(priv_key)
  let ch = @mooncat.TlsClientHello::{
    random: Bytes::make(32, b'\x23'),
    session_id: b"heke1228",
    cipher_suites: [0x1301],
    extensions: [
      // A ClientHello carries a *list* of key_share entries; tls_key_share_extension
      // builds the ServerHello single-entry form, so encode the client list directly.
      @mooncat.TlsExtension::{
        ext_type: @mooncat.tls_ext_key_share,
        data: @mooncat.tls_encode_key_share_client([
          (@mooncat.tls_group_x25519, pub_key),
        ]),
      },
      @mooncat.tls_alpn_extension(["h3", "h2"]),
    ],
  }
  // encode_* wraps the body in a handshake message (type + length); strip that
  // header with tls_parse_handshake before decoding the hello body back.
  let wire = @mooncat.encode_client_hello(ch)
  println("ClientHello wire = \{wire.length()} bytes")
  match parse_ch(wire) {
    Some(back) => {
      println("cipher_suite     = \{back.cipher_suites[0]} (0x1301 = 4865)")
      println(
        "offered alpn     = \{join(@mooncat.tls_client_hello_alpn(back.extensions))}",
      )
      let shares = @mooncat.tls_client_hello_key_shares(back.extensions)
      println(
        "key_share group  = \{shares[0].0}  pub matches = \{shares[0].1 == pub_key}",
      )
    }
    None => println("decode failed")
  }
  let sh = @mooncat.TlsServerHello::{
    random: Bytes::make(32, b'\x66'),
    session_id: b"heke1228",
    cipher_suite: 0x1301,
    extensions: [
      @mooncat.tls_key_share_extension(@mooncat.tls_group_x25519, pub_key),
    ],
  }
  match parse_sh(@mooncat.encode_server_hello(sh)) {
    Some(back) =>
      println(
        "ServerHello key_share present = \{@mooncat.tls_server_hello_key_share(back) is Some(_)}",
      )
    None => println("sh decode failed")
  }
  println(
    "server selected alpn = \{opt_s(@mooncat.tls_selected_alpn([@mooncat.tls_alpn_extension([@mooncat.alpn_h3])]))}",
  )
}

///|
/// Strip the handshake-message wrapper, then decode the ClientHello body.
fn parse_ch(wire : Bytes) -> @mooncat.TlsClientHello? {
  match @mooncat.tls_parse_handshake(wire[:]) {
    Some((_, body)) => @mooncat.decode_client_hello(body[:])
    None => None
  }
}

///|
/// Strip the handshake-message wrapper, then decode the ServerHello body.
fn parse_sh(wire : Bytes) -> @mooncat.TlsServerHello? {
  match @mooncat.tls_parse_handshake(wire[:]) {
    Some((_, body)) => @mooncat.decode_server_hello(body[:])
    None => None
  }
}

///|
fn join(a : Array[String]) -> String {
  let sb = StringBuilder::new()
  for i = 0; i < a.length(); i = i + 1 {
    if i > 0 {
      sb.write_string(", ")
    }
    sb.write_string(a[i])
  }
  sb.to_string()
}

///|
fn opt_s(o : String?) -> String {
  match o {
    Some(s) => s
    None => "(none)"
  }
}

///|
fn hexb(h : String) -> Bytes {
  let buf = Buffer()
  for i = 0; i < h.length(); i = i + 2 {
    buf.write_byte(
      ((nib(h[i].to_int()) << 4) | nib(h[i + 1].to_int())).to_byte(),
    )
  }
  buf.to_bytes()
}

///|
fn nib(c : Int) -> Int {
  if c >= 0x30 && c <= 0x39 {
    c - 0x30
  } else if c >= 0x61 && c <= 0x66 {
    c - 0x61 + 10
  } else {
    0
  }
}
