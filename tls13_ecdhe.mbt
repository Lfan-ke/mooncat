// Deriving the TLS 1.3 handshake-space keys from a real x25519 ECDHE exchange (RFC 8446
// §7.1). Once the ClientHello and ServerHello have carried the two ephemeral key_shares, each
// endpoint owns its private key and the peer's public key, and computes the same shared
// secret. That shared secret feeds the key schedule — Early Secret → Handshake Secret — and
// then the ClientHello..ServerHello transcript derives each side's handshake traffic secret,
// from which `quic_handshake_keys` makes the AEAD key/iv/hp. This is the glue that turns the
// key_share codec, x25519, and the key schedule into the handshake secret a real connection
// derives, instead of one passed in from a test vector.

///|
/// The x25519 ECDHE shared secret from an endpoint's private key and the peer's public key.
pub fn tls13_ecdhe_shared(private_key : Bytes, peer_public : Bytes) -> Bytes {
  x25519(private_key, peer_public)
}

///|
/// The Handshake Secret for an x25519 ECDHE exchange with no PSK (RFC 8446 §7.1): the key
/// schedule extracts the shared secret under the Early Secret's derived salt.
pub fn tls13_handshake_secret_from_ecdhe(
  private_key : Bytes,
  peer_public : Bytes,
) -> Bytes {
  tls13_handshake_secret(
    tls13_early_secret(Bytes::make(32, b'\x00')),
    tls13_ecdhe_shared(private_key, peer_public),
  )
}

///|
/// An endpoint's handshake traffic secret from the ECDHE exchange and the ClientHello..
/// ServerHello transcript hash (RFC 8446 §7.1): the client secret when `is_client`, otherwise
/// the server secret. Both peers derive matching secrets because they share the same DHE.
pub fn tls13_ecdhe_handshake_traffic_secret(
  private_key : Bytes,
  peer_public : Bytes,
  transcript_hash : Bytes,
  is_client : Bool,
) -> Bytes {
  let handshake_secret = tls13_handshake_secret_from_ecdhe(
    private_key, peer_public,
  )
  if is_client {
    tls13_client_hs_traffic_secret(handshake_secret, transcript_hash)
  } else {
    tls13_server_hs_traffic_secret(handshake_secret, transcript_hash)
  }
}
