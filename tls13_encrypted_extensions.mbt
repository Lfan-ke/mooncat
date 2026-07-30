// The TLS 1.3 EncryptedExtensions message (RFC 8446 §4.3.1): the first message the server
// sends under handshake encryption, carrying every negotiated extension that is not needed to
// establish the cryptographic context — for a QUIC/HTTP3 server, the negotiated ALPN protocol
// and, required by RFC 9001 §8.2, the server's quic_transport_parameters. The body is just an
// extension list; this names it and gives a QUIC server the exact EncryptedExtensions body it
// puts in its Handshake flight.

///|
/// The EncryptedExtensions message body (RFC 8446 §4.3.1): an extension list.
pub fn tls13_encrypted_extensions_body(exts : Array[TlsExtension]) -> Bytes {
  tls_encode_extensions(exts)
}

///|
/// Decode an EncryptedExtensions body back into its extension list, or `None` if truncated.
pub fn tls13_decode_encrypted_extensions(
  body : BytesView,
) -> Array[TlsExtension]? {
  tls_decode_extensions(body)
}

///|
/// A QUIC server's EncryptedExtensions body: the negotiated ALPN protocol and the server's
/// transport parameters (RFC 9001 §8.2 — a QUIC server MUST send quic_transport_parameters).
pub fn tls13_quic_encrypted_extensions(
  alpn : String,
  params : Array[TransportParam],
) -> Bytes {
  tls13_encrypted_extensions_body([
    tls_alpn_extension([alpn]),
    tls_quic_transport_params_extension(params),
  ])
}
