pub fn test() {
    let subject_alt_names = vec!["localhost".to_string()];
    let cert = rcgen::generate_simple_self_signed(subject_alt_names).unwrap();
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();
}
