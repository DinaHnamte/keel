use keel_proto::spki_fingerprint;

#[test]
fn fingerprint_matches_known_vector() {
    // Expected value computed independently:
    // openssl x509 -inform der -in known_cert.der -pubkey -noout \
    //   | openssl pkey -pubin -outform der | sha256sum
    let der = include_bytes!("fixtures/known_cert.der");
    assert_eq!(
        spki_fingerprint(der).unwrap(),
        "a212fe4e1e80d54bcd32dafb73e93da2d318aab684e9a1f94c2bf3e1a9b9d13c"
    );
}

#[test]
fn fingerprint_rejects_garbage() {
    assert!(spki_fingerprint(b"not a certificate").is_err());
    assert!(spki_fingerprint(&[]).is_err());
}
