// Carrying QUIC transport parameters in the TLS handshake (RFC 9001 §8.2): QUIC does not use
// a separate negotiation message — each endpoint's transport-parameter block (RFC 9000 §18)
// travels as a single TLS extension, `quic_transport_parameters` (0x0039), in the client's
// ClientHello and the server's EncryptedExtensions. This is the seam that binds the transport
// parameters (`encode_transport_params`) to the ClientHello/ServerHello extension list a real
// QUIC handshake exchanges — the limits curl and a mooncat server tell each other.

///|
/// The quic_transport_parameters extension type (RFC 9001 §8.2).
pub let tls_ext_quic_transport_params : Int = 0x0039

///|
/// Build a quic_transport_parameters extension carrying `params` — the client's block in a
/// ClientHello, the server's in its EncryptedExtensions.
pub fn tls_quic_transport_params_extension(
  params : Array[TransportParam],
) -> TlsExtension {
  {
    ext_type: tls_ext_quic_transport_params,
    data: encode_transport_params(params),
  }
}

///|
/// The QUIC transport parameters an extension list carries, in order (empty if the extension
/// is absent or its block is truncated).
pub fn tls_hello_quic_transport_params(
  extensions : Array[TlsExtension],
) -> Array[TransportParam] {
  match tls_find_extension(extensions, tls_ext_quic_transport_params) {
    Some(ext) =>
      match decode_transport_params(ext.data[:]) {
        Some(params) => params
        None => []
      }
    None => []
  }
}
