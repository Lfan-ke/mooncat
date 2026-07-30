// The TLS 1.3 traffic secrets a QUIC endpoint keys its Handshake and 1-RTT packets from
// (RFC 8446 §7.1, RFC 9001 §5.2). Once the handshake progresses, the client and server
// handshake traffic secrets protect Handshake packets, and the application traffic
// secrets protect 1-RTT packets; each is run through `quic_packet_keys` to get the
// AEAD key/iv/hp. The secrets themselves come from the key schedule in `tls13`; these
// are the named derivations and the QUIC key wiring on top of it.

///|
/// The client handshake traffic secret, `Derive-Secret(Handshake Secret, "c hs traffic",
/// ClientHello..ServerHello)` (RFC 8446 §7.1).
pub fn tls13_client_hs_traffic_secret(
  handshake_secret : Bytes,
  transcript_hash : Bytes,
) -> Bytes {
  tls13_derive_secret(handshake_secret, b"c hs traffic", transcript_hash)
}

///|
/// The server handshake traffic secret, `Derive-Secret(Handshake Secret, "s hs traffic",
/// ClientHello..ServerHello)`.
pub fn tls13_server_hs_traffic_secret(
  handshake_secret : Bytes,
  transcript_hash : Bytes,
) -> Bytes {
  tls13_derive_secret(handshake_secret, b"s hs traffic", transcript_hash)
}

///|
/// The client application (1-RTT) traffic secret, `Derive-Secret(Master Secret,
/// "c ap traffic", ClientHello..server Finished)`.
pub fn tls13_client_ap_traffic_secret(
  master_secret : Bytes,
  transcript_hash : Bytes,
) -> Bytes {
  tls13_derive_secret(master_secret, b"c ap traffic", transcript_hash)
}

///|
/// The server application (1-RTT) traffic secret, `Derive-Secret(Master Secret,
/// "s ap traffic", ClientHello..server Finished)`.
pub fn tls13_server_ap_traffic_secret(
  master_secret : Bytes,
  transcript_hash : Bytes,
) -> Bytes {
  tls13_derive_secret(master_secret, b"s ap traffic", transcript_hash)
}

///|
/// The QUIC Handshake-space AEAD key/iv/hp for this endpoint, derived from the handshake
/// traffic secret over the ClientHello..ServerHello transcript (RFC 9001 §5.2).
pub fn quic_handshake_keys(
  handshake_secret : Bytes,
  transcript_hash : Bytes,
  is_client : Bool,
) -> QuicPacketKeys {
  let secret = if is_client {
    tls13_client_hs_traffic_secret(handshake_secret, transcript_hash)
  } else {
    tls13_server_hs_traffic_secret(handshake_secret, transcript_hash)
  }
  quic_packet_keys(secret)
}

///|
/// The QUIC Application (1-RTT) AEAD key/iv/hp for this endpoint, derived from the
/// application traffic secret over the ClientHello..server Finished transcript.
pub fn quic_application_keys(
  master_secret : Bytes,
  transcript_hash : Bytes,
  is_client : Bool,
) -> QuicPacketKeys {
  let secret = if is_client {
    tls13_client_ap_traffic_secret(master_secret, transcript_hash)
  } else {
    tls13_server_ap_traffic_secret(master_secret, transcript_hash)
  }
  quic_packet_keys(secret)
}
