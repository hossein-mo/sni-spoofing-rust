use rand::RngCore;
use serde::{Deserialize, Serialize};

/// TLS ClientHello fingerprint profile for the fake injected packet.
///
/// Controls the cipher suites, extensions, and their ordering so that
/// JA3/JA4 fingerprint-aware DPI systems recognise the flow as legitimate
/// browser traffic.
///
/// # Config example
/// ```json
/// { "fingerprint": "chrome120" }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsFingerprint {
    /// Built-in static template (original behaviour, backward compatible).
    #[default]
    Default,
    /// Chrome 120 / Chromium-based browsers.
    ///
    /// JA3: `771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,`
    ///      `0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0`
    Chrome120,
    /// Edge 120 (Chromium engine — identical fingerprint to Chrome120).
    Edge120,
    /// Firefox 120.
    ///
    /// JA3: `771,4865-4867-4866-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53-10-255,`
    ///      `0-23-65281-10-11-35-16-5-13-18-51-45-43-21,29-23-24-25,0`
    Firefox120,
    /// Safari 17 / WebKit.
    ///
    /// JA3: `771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49172-49171-157-156-53-47,`
    ///      `0-23-65281-10-11-16-5-13-18-51-45-43,29-23-24-25,0`
    Safari17,
}

impl TlsFingerprint {
    pub fn build_client_hello(&self, sni: &str) -> Vec<u8> {
        match self {
            TlsFingerprint::Default => super::tls::build_client_hello(sni),
            TlsFingerprint::Chrome120 | TlsFingerprint::Edge120 => build_chrome120(sni),
            TlsFingerprint::Firefox120 => build_firefox120(sni),
            TlsFingerprint::Safari17 => build_safari17(sni),
        }
    }
}

// ── low-level write helpers ───────────────────────────────────────────────────

fn wu16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn wu24(buf: &mut Vec<u8>, v: u32) {
    buf.push((v >> 16) as u8);
    buf.push((v >> 8) as u8);
    buf.push(v as u8);
}

fn push_ext(buf: &mut Vec<u8>, t: u16, data: &[u8]) {
    wu16(buf, t);
    wu16(buf, data.len() as u16);
    buf.extend_from_slice(data);
}

/// Wrap cipher-suites + extensions into a full TLS 1.3-capable ClientHello record.
fn assemble(random: &[u8; 32], sess_id: &[u8; 32], ciphers: &[u16], exts: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    wu16(&mut body, 0x0303); // legacy_version = TLS 1.2
    body.extend_from_slice(random);
    body.push(0x20); // session_id length = 32
    body.extend_from_slice(sess_id);
    wu16(&mut body, (ciphers.len() * 2) as u16);
    for c in ciphers {
        wu16(&mut body, *c);
    }
    body.push(0x01); // compression_methods length
    body.push(0x00); // null compression
    wu16(&mut body, exts.len() as u16);
    body.extend_from_slice(exts);

    let mut hs = Vec::new();
    hs.push(0x01); // ClientHello
    wu24(&mut hs, body.len() as u32);
    hs.extend_from_slice(&body);

    let mut rec = Vec::new();
    rec.push(0x16); // content type: handshake
    wu16(&mut rec, 0x0301); // record layer legacy_version = TLS 1.0
    wu16(&mut rec, hs.len() as u16);
    rec.extend_from_slice(&hs);
    rec
}

// ── extension builders ────────────────────────────────────────────────────────

fn ext_sni(sni: &str) -> Vec<u8> {
    let b = sni.as_bytes();
    let mut d = Vec::new();
    wu16(&mut d, (b.len() + 3) as u16); // ServerNameList length
    d.push(0x00); // name_type = host_name
    wu16(&mut d, b.len() as u16);
    d.extend_from_slice(b);
    let mut out = Vec::new();
    push_ext(&mut out, 0x0000, &d);
    out
}

fn ext_empty(buf: &mut Vec<u8>, t: u16) {
    push_ext(buf, t, &[]);
}

fn ext_renegotiation_info(buf: &mut Vec<u8>) {
    // empty renegotiated_connection for initial handshake
    push_ext(buf, 0xff01, &[0x00]);
}

fn ext_supported_groups(buf: &mut Vec<u8>, groups: &[u16]) {
    let mut d = Vec::new();
    wu16(&mut d, (groups.len() * 2) as u16);
    for g in groups {
        wu16(&mut d, *g);
    }
    push_ext(buf, 0x000a, &d);
}

fn ext_ec_point_formats(buf: &mut Vec<u8>) {
    push_ext(buf, 0x000b, &[0x01, 0x00]); // [len=1, uncompressed]
}

fn ext_alpn(buf: &mut Vec<u8>, protos: &[&str]) {
    let mut list = Vec::new();
    for p in protos {
        list.push(p.len() as u8);
        list.extend_from_slice(p.as_bytes());
    }
    let mut d = Vec::new();
    wu16(&mut d, list.len() as u16);
    d.extend_from_slice(&list);
    push_ext(buf, 0x0010, &d);
}

fn ext_status_request(buf: &mut Vec<u8>) {
    // OCSP: status_type=1, empty responder_id_list, empty extensions
    push_ext(buf, 0x0005, &[0x01, 0x00, 0x00, 0x00, 0x00]);
}

fn ext_sig_algs(buf: &mut Vec<u8>, algs: &[u16]) {
    let mut list = Vec::new();
    for a in algs {
        wu16(&mut list, *a);
    }
    let mut d = Vec::new();
    wu16(&mut d, list.len() as u16);
    d.extend_from_slice(&list);
    push_ext(buf, 0x000d, &d);
}

fn ext_key_share_x25519(buf: &mut Vec<u8>, key: &[u8; 32]) {
    let mut entry = Vec::new();
    wu16(&mut entry, 0x001d); // x25519
    wu16(&mut entry, 32);
    entry.extend_from_slice(key);
    let mut d = Vec::new();
    wu16(&mut d, entry.len() as u16);
    d.extend_from_slice(&entry);
    push_ext(buf, 0x0033, &d);
}

fn ext_psk_modes(buf: &mut Vec<u8>) {
    push_ext(buf, 0x002d, &[0x01, 0x01]); // [len=1, psk_dhe_ke=1]
}

fn ext_supported_versions(buf: &mut Vec<u8>, versions: &[u16]) {
    // u8 inner list length (bytes) + u16 versions
    let mut d = Vec::new();
    d.push((versions.len() * 2) as u8);
    for v in versions {
        wu16(&mut d, *v);
    }
    push_ext(buf, 0x002b, &d);
}

fn ext_compress_cert(buf: &mut Vec<u8>) {
    // u8 list_len_in_bytes + u16 algorithm; brotli = 0x0002
    push_ext(buf, 0x001b, &[0x02, 0x00, 0x02]);
}

fn ext_application_settings(buf: &mut Vec<u8>, protos: &[&str]) {
    // Chrome ALPS (0x4469): each protocol as u8_len + bytes, no outer list length
    let mut d = Vec::new();
    for p in protos {
        d.push(p.len() as u8);
        d.extend_from_slice(p.as_bytes());
    }
    push_ext(buf, 0x4469, &d);
}

fn ext_grease(buf: &mut Vec<u8>, grease: u16) {
    push_ext(buf, grease, &[0x00]);
}

// ── browser profile builders ──────────────────────────────────────────────────

/// Pick a random value from the RFC 8701 GREASE set.
fn random_grease(rng: &mut impl RngCore) -> u16 {
    const SET: &[u16] = &[
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
        0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    ];
    SET[(rng.next_u32() as usize) % SET.len()]
}

fn build_chrome120(sni: &str) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut random = [0u8; 32];
    let mut sess_id = [0u8; 32];
    let mut key_share = [0u8; 32];
    rng.fill_bytes(&mut random);
    rng.fill_bytes(&mut sess_id);
    rng.fill_bytes(&mut key_share);
    let grease = random_grease(&mut rng);

    let ciphers: Vec<u16> = vec![
        grease,
        0x1301, 0x1302, 0x1303,
        0xc02b, 0xc02f, 0xc02c, 0xc030,
        0xcca9, 0xcca8,
        0xc013, 0xc014,
        0x009c, 0x009d,
        0x002f, 0x0035,
    ];

    #[rustfmt::skip]
    let sig_algs: &[u16] = &[
        0x0403, 0x0804, 0x0401,
        0x0503, 0x0805, 0x0501,
        0x0806, 0x0601, 0x0201,
    ];

    let mut exts = Vec::new();
    ext_grease(&mut exts, grease);
    exts.extend(ext_sni(sni));
    ext_empty(&mut exts, 0x0017);               // extended_master_secret
    ext_renegotiation_info(&mut exts);
    ext_supported_groups(&mut exts, &[0x001d, 0x0017, 0x0018]); // x25519, P-256, P-384
    ext_ec_point_formats(&mut exts);
    ext_empty(&mut exts, 0x0023);               // session_ticket
    ext_alpn(&mut exts, &["h2", "http/1.1"]);
    ext_status_request(&mut exts);
    ext_sig_algs(&mut exts, sig_algs);
    ext_empty(&mut exts, 0x0012);               // signed_cert_timestamp
    ext_key_share_x25519(&mut exts, &key_share);
    ext_psk_modes(&mut exts);
    ext_supported_versions(&mut exts, &[0x0304, 0x0303]);
    ext_compress_cert(&mut exts);
    ext_application_settings(&mut exts, &["h2"]);
    ext_grease(&mut exts, grease);              // trailing GREASE
    push_ext(&mut exts, 0x0015, &[]);           // padding (empty; type matters for JA3)

    assemble(&random, &sess_id, &ciphers, &exts)
}

fn build_firefox120(sni: &str) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut random = [0u8; 32];
    let mut sess_id = [0u8; 32];
    let mut key_share = [0u8; 32];
    rng.fill_bytes(&mut random);
    rng.fill_bytes(&mut sess_id);
    rng.fill_bytes(&mut key_share);

    // Firefox puts CHACHA before AES-256 in cipher order (hardware preference)
    let ciphers: &[u16] = &[
        0x1301, 0x1303, 0x1302,
        0xc02b, 0xc02f, 0xc02c, 0xc030,
        0xcca9, 0xcca8,
        0xc013, 0xc014,
        0x009c, 0x009d,
        0x002f, 0x0035,
        0x000a,  // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        0x00ff,  // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    ];

    #[rustfmt::skip]
    let sig_algs: &[u16] = &[
        0x0403, 0x0503, 0x0603,
        0x0804, 0x0805, 0x0806,
        0x0401, 0x0501, 0x0601,
    ];

    let mut exts = Vec::new();
    exts.extend(ext_sni(sni));
    ext_empty(&mut exts, 0x0017);               // extended_master_secret
    ext_renegotiation_info(&mut exts);
    ext_supported_groups(&mut exts, &[0x001d, 0x0017, 0x0018, 0x0019]); // + P-521
    ext_ec_point_formats(&mut exts);
    ext_empty(&mut exts, 0x0023);               // session_ticket
    ext_alpn(&mut exts, &["h2", "http/1.1"]);
    ext_status_request(&mut exts);
    ext_sig_algs(&mut exts, sig_algs);
    ext_empty(&mut exts, 0x0012);               // signed_cert_timestamp
    ext_key_share_x25519(&mut exts, &key_share);
    ext_psk_modes(&mut exts);
    ext_supported_versions(&mut exts, &[0x0304, 0x0303]);
    push_ext(&mut exts, 0x0015, &[]);           // padding

    assemble(&random, &sess_id, ciphers, &exts)
}

fn build_safari17(sni: &str) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut random = [0u8; 32];
    let mut sess_id = [0u8; 32];
    let mut key_share = [0u8; 32];
    rng.fill_bytes(&mut random);
    rng.fill_bytes(&mut sess_id);
    rng.fill_bytes(&mut key_share);

    // Safari prefers ECDSA-based suites first, then RSA
    let ciphers: &[u16] = &[
        0x1301, 0x1302, 0x1303,
        0xc02c, 0xc02b, 0xcca9, // ECDSA: AES-256, AES-128, CHACHA
        0xc030, 0xc02f, 0xcca8, // RSA:   AES-256, AES-128, CHACHA
        0xc014, 0xc013,
        0x009d, 0x009c,
        0x0035, 0x002f,
    ];

    #[rustfmt::skip]
    let sig_algs: &[u16] = &[
        0x0403, 0x0804, 0x0401,
        0x0503, 0x0603,
        0x0805, 0x0806,
        0x0501, 0x0601,
        0x0201, 0x0203,          // sha1 variants (Safari still lists these)
    ];

    // Safari omits: GREASE, session_ticket, compress_cert, application_settings
    let mut exts = Vec::new();
    exts.extend(ext_sni(sni));
    ext_empty(&mut exts, 0x0017);               // extended_master_secret
    ext_renegotiation_info(&mut exts);
    ext_supported_groups(&mut exts, &[0x001d, 0x0017, 0x0018, 0x0019]);
    ext_ec_point_formats(&mut exts);
    ext_alpn(&mut exts, &["h2", "http/1.1"]);
    ext_status_request(&mut exts);
    ext_sig_algs(&mut exts, sig_algs);
    ext_empty(&mut exts, 0x0012);               // signed_cert_timestamp
    ext_key_share_x25519(&mut exts, &key_share);
    ext_psk_modes(&mut exts);
    ext_supported_versions(&mut exts, &[0x0304, 0x0303]);

    assemble(&random, &sess_id, ciphers, &exts)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn check_tls_record(buf: &[u8], sni: &str) {
        assert!(buf.len() > 9, "packet too short");
        assert_eq!(buf[0], 0x16, "not a handshake record");
        assert_eq!(buf[1], 0x03, "unexpected record version major");
        assert_eq!(buf[2], 0x01, "unexpected record version minor");

        let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        assert_eq!(
            record_len + 5,
            buf.len(),
            "record length mismatch"
        );

        assert_eq!(buf[5], 0x01, "not a ClientHello");

        // Scan for SNI in the packet
        let sni_bytes = sni.as_bytes();
        let found = buf
            .windows(sni_bytes.len())
            .any(|w| w == sni_bytes);
        assert!(found, "SNI '{}' not found in packet", sni);
    }

    #[test]
    fn chrome120_valid_structure() {
        let ch = TlsFingerprint::Chrome120.build_client_hello("example.com");
        check_tls_record(&ch, "example.com");
    }

    #[test]
    fn firefox120_valid_structure() {
        let ch = TlsFingerprint::Firefox120.build_client_hello("example.com");
        check_tls_record(&ch, "example.com");
    }

    #[test]
    fn safari17_valid_structure() {
        let ch = TlsFingerprint::Safari17.build_client_hello("example.com");
        check_tls_record(&ch, "example.com");
    }

    #[test]
    fn edge120_same_as_chrome120() {
        // Both should produce structurally identical packets (same cipher/extension set)
        let c = TlsFingerprint::Chrome120.build_client_hello("test.com");
        let e = TlsFingerprint::Edge120.build_client_hello("test.com");
        // Same length (modulo random bytes) — check structural parts
        assert_eq!(c[0], e[0]); // content type
        assert_eq!(c[5], e[5]); // handshake type
        assert_eq!(c.len(), e.len(), "Chrome120 and Edge120 packet sizes differ");
    }

    #[test]
    fn default_fingerprint_unchanged() {
        let ch = TlsFingerprint::Default.build_client_hello("test.com");
        assert_eq!(ch[0], 0x16);
        assert_eq!(ch[1], 0x03);
        assert_eq!(ch[2], 0x01);
    }

    #[test]
    fn long_sni_works() {
        let sni = "a".repeat(100) + ".example.com";
        for fp in [
            TlsFingerprint::Chrome120,
            TlsFingerprint::Firefox120,
            TlsFingerprint::Safari17,
        ] {
            let ch = fp.build_client_hello(&sni);
            check_tls_record(&ch, &sni);
        }
    }
}
