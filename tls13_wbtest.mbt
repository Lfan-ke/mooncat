///|
test "TLS 1.3 key schedule reproduces the RFC 8448 §3 secrets" {
  // Early Secret with a zero PSK.
  let early = tls13_early_secret(Bytes::make(32, b'\x00'))
  assert_eq(
    qv_hex(early),
    "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a",
  )
  // "derived" node feeding the Handshake Secret.
  assert_eq(
    qv_hex(tls13_derive_secret(early, b"derived", sha256(b""))),
    "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba",
  )
  // Handshake Secret from the published ECDHE shared secret.
  let ecdhe = qv_hexb(
    "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d",
  )
  let handshake = tls13_handshake_secret(early, ecdhe)
  assert_eq(
    qv_hex(handshake),
    "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac",
  )
  // Handshake traffic secrets keyed by the ClientHello..ServerHello transcript hash.
  let hs_th = qv_hexb(
    "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8",
  )
  assert_eq(
    qv_hex(tls13_derive_secret(handshake, b"c hs traffic", hs_th)),
    "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21",
  )
  assert_eq(
    qv_hex(tls13_derive_secret(handshake, b"s hs traffic", hs_th)),
    "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38",
  )
  // Master Secret and the application traffic secrets.
  let master = tls13_master_secret(handshake)
  assert_eq(
    qv_hex(master),
    "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919",
  )
  let ap_th = qv_hexb(
    "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13",
  )
  assert_eq(
    qv_hex(tls13_derive_secret(master, b"c ap traffic", ap_th)),
    "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5",
  )
  assert_eq(
    qv_hex(tls13_derive_secret(master, b"s ap traffic", ap_th)),
    "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643",
  )
}
