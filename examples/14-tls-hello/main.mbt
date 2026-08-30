///|
/// The TLS 1.3 ClientHello / ServerHello wire format (RFC 8446 §4.1) with the
/// extensions §9.2 makes mandatory — supported_versions (§4.2.1), supported_groups
/// (§4.2.7), signature_algorithms (§4.2.3) and key_share (§4.2.8) — plus ALPN
/// (RFC 7301). The hello is encoded, decoded and negotiated; the server's answer
/// carries 0x0304 in supported_versions while legacy_version stays 0x0303. The two
/// ways negotiation does not end in a ServerHello — a HelloRetryRequest (§4.1.4) and
/// a §6 alert — are shown after it.
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
      @mooncat.tls_supported_versions_extension([@mooncat.tls_version_13]),
      @mooncat.tls_supported_groups_extension([@mooncat.tls_group_x25519]),
      @mooncat.tls_signature_algorithms_extension([
        @mooncat.tls_sig_ecdsa_secp256r1_sha256,
      ]),
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
  println("negotiated        = \{describe(negotiate(ch))}")
  // tls13_server_hello adds the supported_versions §9.2 requires; a hello built by hand
  // without it reads as TLS 1.2 to every real client.
  let sh = @mooncat.tls13_server_hello(
    Bytes::make(32, b'\x66'),
    b"heke1228",
    0x1301,
    [@mooncat.tls_key_share_extension(@mooncat.tls_group_x25519, pub_key)],
  )
  let sh_wire = @mooncat.encode_server_hello(sh)
  match parse_sh(sh_wire) {
    Some(back) => {
      println(
        "ServerHello key_share present = \{@mooncat.tls_server_hello_key_share(back) is Some(_)}",
      )
      println(
        "selected version  = \{opt_i(@mooncat.tls_server_hello_version(back))} (0x0304 = 772)",
      )
      // legacy_version is the first two bytes of the message body, past the 4-byte header.
      println(
        "legacy_version    = \{sh_wire[4].to_int()}.\{sh_wire[5].to_int()} (3.3 = TLS 1.2)",
      )
    }
    None => println("sh decode failed")
  }
  // The client offers x25519 but sends no share for it, so it is asked for one.
  let retry_ch = @mooncat.TlsClientHello::{
    ..ch,
    extensions: [
      @mooncat.tls_supported_versions_extension([@mooncat.tls_version_13]),
      @mooncat.tls_supported_groups_extension([@mooncat.tls_group_x25519]),
      @mooncat.tls_signature_algorithms_extension([
        @mooncat.tls_sig_ecdsa_secp256r1_sha256,
      ]),
      @mooncat.TlsExtension::{
        ext_type: @mooncat.tls_ext_key_share,
        data: @mooncat.tls_encode_key_share_client([]),
      },
    ],
  }
  println("no key share      = \{describe(negotiate(retry_ch))}")
  let hrr = @mooncat.tls13_hello_retry_request(
    b"heke1228", 0x1301, @mooncat.tls_group_x25519,
  )
  println(
    "HelloRetryRequest = \{@mooncat.tls13_is_hello_retry_request(hrr)}, group \{opt_i(@mooncat.tls13_hello_retry_group(hrr))}",
  )
  // A client that offers only a group this build cannot run gets told why.
  let refused = @mooncat.TlsClientHello::{
    ..ch,
    extensions: [
      @mooncat.tls_supported_versions_extension([@mooncat.tls_version_13]),
      @mooncat.tls_supported_groups_extension([@mooncat.tls_group_secp384r1]),
      @mooncat.tls_signature_algorithms_extension([
        @mooncat.tls_sig_ecdsa_secp256r1_sha256,
      ]),
      @mooncat.TlsExtension::{
        ext_type: @mooncat.tls_ext_key_share,
        data: @mooncat.tls_encode_key_share_client([
          (@mooncat.tls_group_secp384r1, Bytes::make(97, b'\x04')),
        ]),
      },
    ],
  }
  println("unsupported group = \{describe(negotiate(refused))}")
  println(
    "server selected alpn = \{opt_s(@mooncat.tls_selected_alpn([@mooncat.tls_alpn_extension([@mooncat.alpn_h3])]))}",
  )
}

///|
/// Negotiate a hello, keeping the alert instead of letting it escape.
fn negotiate(
  ch : @mooncat.TlsClientHello,
) -> (@mooncat.TlsNegotiation?, @mooncat.TlsAlert?) {
  (Some(@mooncat.tls13_negotiate(ch)), None) catch {
    a => (None, Some(a))
  }
}

///|
/// One line for whichever of the two a negotiation produced.
fn describe(outcome : (@mooncat.TlsNegotiation?, @mooncat.TlsAlert?)) -> String {
  match outcome {
    (Some(@mooncat.Negotiated(group~, scheme~, ..)), _) =>
      "group \{group}, scheme \{scheme}"
    (Some(@mooncat.Retry(group)), _) => "HelloRetryRequest for group \{group}"
    (_, Some(@mooncat.TlsAlert(level~, description~))) =>
      "alert level \{level} description \{description}"
    _ => "(nothing)"
  }
}

///|
fn opt_i(o : Int?) -> String {
  match o {
    Some(v) => v.to_string()
    None => "(none)"
  }
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
  let sb = StringBuilder()
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
