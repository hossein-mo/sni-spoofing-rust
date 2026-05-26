use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Maximum TLS plaintext record size (RFC 8446 §5.1).
const MAX_TLS_RECORD: usize = (1 << 14) + 2048;

/// How long to wait for the client to send its first TLS record.
const READ_TIMEOUT_SECS: u64 = 10;

/// Controls ClientHello fragmentation for the fake-SNI bypass.
///
/// When set, the proxy reads the real ClientHello from the client after the
/// fake injection is confirmed, splits it around the SNI hostname, and
/// writes the pieces to the upstream connection as separate TCP segments.
/// This defeats DPI that pattern-matches on individual TCP segments rather
/// than reassembled streams.
///
/// # Config example
/// ```json
/// { "fragment": { "sni_chunk": 3, "delay_ms": 0 } }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentConfig {
    /// Bytes per SNI chunk. `0` sends the entire hostname as one write but
    /// still isolates it from surrounding TLS data. Default: `3` (matches
    /// the Go reference implementation's `DefaultSNIChunkBytes`).
    #[serde(default = "default_sni_chunk")]
    pub sni_chunk: usize,
    /// Milliseconds to sleep between consecutive fragment writes. Default: `0`.
    #[serde(default)]
    pub delay_ms: u64,
}

fn default_sni_chunk() -> usize {
    3
}

impl Default for FragmentConfig {
    fn default() -> Self {
        Self {
            sni_chunk: default_sni_chunk(),
            delay_ms: 0,
        }
    }
}

/// Read the real ClientHello from `client`, split it around the SNI hostname,
/// and write the fragments to `upstream` with optional inter-fragment delays.
///
/// TCP_NODELAY is set on `upstream` for the duration of the writes so each
/// fragment lands in its own TCP segment; it is restored afterwards.
///
/// If the client's first bytes are not a valid TLS handshake record the data
/// is forwarded as-is and the relay handles the rest.
pub async fn forward_fragmented(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    cfg: &FragmentConfig,
) -> std::io::Result<()> {
    let record = tokio::time::timeout(
        Duration::from_secs(READ_TIMEOUT_SECS),
        read_tls_record(client),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "fragment read timeout"))??;

    let fragments = split_client_hello(&record, cfg.sni_chunk);

    upstream.set_nodelay(true)?;

    let delay = Duration::from_millis(cfg.delay_ms);
    let mut sent = 0usize;
    for frag in &fragments {
        if frag.is_empty() {
            continue;
        }
        if sent > 0 && cfg.delay_ms > 0 {
            tokio::time::sleep(delay).await;
        }
        upstream.write_all(frag).await?;
        sent += 1;
    }

    // Restore Nagle's algorithm so the subsequent relay is not penalised.
    let _ = upstream.set_nodelay(false);

    Ok(())
}

// ── internal helpers ──────────────────────────────────────────────────────────

/// Read exactly one TLS record from `stream`.
///
/// If the first byte is not 22 (handshake) or the declared length is invalid,
/// returns only the 5-byte header; the relay will forward the remainder.
async fn read_tls_record(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut hdr = [0u8; 5];
    stream.read_exact(&mut hdr).await?;

    if hdr[0] != 22 {
        return Ok(hdr.to_vec());
    }

    let payload_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if payload_len == 0 || payload_len > MAX_TLS_RECORD {
        return Ok(hdr.to_vec());
    }

    let mut record = vec![0u8; 5 + payload_len];
    record[..5].copy_from_slice(&hdr);
    stream.read_exact(&mut record[5..]).await?;
    Ok(record)
}

/// Return the byte range `[start, end)` of the SNI hostname inside `record`.
///
/// Direct port of Go's `sniValueRange` in `packet/ch_fragment.go`.
/// All offsets are absolute into the original `record` slice.
fn find_sni_range(record: &[u8]) -> Option<(usize, usize)> {
    if record.len() < 5 || record[0] != 22 {
        return None;
    }
    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if record_len == 0 || record.len() < 5 + record_len {
        return None;
    }

    // Handshake message: record[5..]
    let hs = &record[5..5 + record_len];
    if hs.len() < 4 || hs[0] != 1 {
        return None; // not ClientHello
    }
    let hs_len = (hs[1] as usize) << 16 | (hs[2] as usize) << 8 | hs[3] as usize;
    if hs_len == 0 || hs.len() < 4 + hs_len {
        return None;
    }

    // ClientHello body: hs[4..] → record[9..]
    let body = &hs[4..4 + hs_len];

    // Skip legacy_version (2) + random (32)
    let mut pos = 2 + 32;
    if body.len() < pos + 1 {
        return None;
    }
    let session_len = body[pos] as usize;
    pos += 1;
    if body.len() < pos + session_len + 2 {
        return None;
    }
    pos += session_len;

    let cipher_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if body.len() < pos + cipher_len + 1 {
        return None;
    }
    pos += cipher_len;

    let compression_len = body[pos] as usize;
    pos += 1;
    if body.len() < pos + compression_len {
        return None;
    }
    pos += compression_len;

    if body.len() == pos {
        return None; // no extensions section
    }
    if body.len() < pos + 2 {
        return None;
    }
    let extensions_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if body.len() < pos + extensions_len {
        return None;
    }
    let extensions_end = pos + extensions_len;

    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        let ext_data_start = pos + 4;
        let ext_data_end = ext_data_start + ext_len;
        if ext_data_end > extensions_end {
            return None;
        }
        if ext_type == 0 {
            // SNI extension found — locate the hostname within it
            let (s, e) = sni_name_range_in_ext(&body[ext_data_start..ext_data_end])?;
            // Absolute offset in record:
            //   5  (TLS record header)
            // + 4  (handshake header)
            // + ext_data_start (offset of ext data within body)
            let abs = 9 + ext_data_start;
            return Some((abs + s, abs + e));
        }
        pos = ext_data_end;
    }
    None
}

/// Return `[start, end)` of the host_name within a raw SNI extension value.
///
/// Direct port of Go's `sniNameRangeInExtension`.
fn sni_name_range_in_ext(ext: &[u8]) -> Option<(usize, usize)> {
    if ext.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
    let mut pos = 2;
    if list_len == 0 || ext.len() < pos + list_len {
        return None;
    }
    let list_end = pos + list_len;
    while pos + 3 <= list_end {
        let name_type = ext[pos];
        let name_len = u16::from_be_bytes([ext[pos + 1], ext[pos + 2]]) as usize;
        let name_start = pos + 3;
        let name_end = name_start + name_len;
        if name_end > list_end {
            return None;
        }
        if name_type == 0 && name_len > 0 {
            return Some((name_start, name_end));
        }
        pos = name_end;
    }
    None
}

/// Split a TLS ClientHello record around the SNI hostname.
///
/// Direct port of Go's `SplitClientHelloRecord`.
///
/// Returns a `Vec` of byte slices; concatenating them reconstructs `record`
/// exactly.  If the SNI cannot be found, returns `vec![record.to_vec()]`.
fn split_client_hello(record: &[u8], sni_chunk: usize) -> Vec<Vec<u8>> {
    if record.is_empty() {
        return Vec::new();
    }
    let (s, e) = match find_sni_range(record) {
        Some((s, e)) if e > s => (s, e),
        _ => return vec![record.to_vec()],
    };

    let mut out: Vec<Vec<u8>> = Vec::new();

    if s > 0 {
        out.push(record[..s].to_vec());
    }
    if sni_chunk == 0 {
        out.push(record[s..e].to_vec());
    } else {
        let mut i = s;
        while i < e {
            let j = (i + sni_chunk).min(e);
            out.push(record[i..j].to_vec());
            i = j;
        }
    }
    if e < record.len() {
        out.push(record[e..].to_vec());
    }

    if out.is_empty() {
        vec![record.to_vec()]
    } else {
        out
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::fingerprint::TlsFingerprint;

    fn build(fp: &TlsFingerprint, sni: &str) -> Vec<u8> {
        fp.build_client_hello(sni)
    }

    /// Every split must reassemble to the original record.
    fn assert_reassembly(record: &[u8], chunk: usize) {
        let frags = split_client_hello(record, chunk);
        let got: Vec<u8> = frags.iter().flat_map(|f| f.iter().copied()).collect();
        assert_eq!(got, record, "reassembly failed for chunk_size={chunk}");
    }

    #[test]
    fn test_find_sni_range_chrome120() {
        let sni = "hcaptcha.com";
        let rec = build(&TlsFingerprint::Chrome120, sni);
        let (s, e) = find_sni_range(&rec).expect("SNI range not found");
        assert_eq!(&rec[s..e], sni.as_bytes());
    }

    #[test]
    fn test_find_sni_range_default_fingerprint() {
        let sni = "security.vercel.com";
        let rec = build(&TlsFingerprint::Default, sni);
        let (s, e) = find_sni_range(&rec).expect("SNI range not found");
        assert_eq!(&rec[s..e], sni.as_bytes());
        // Must agree with the legacy hardcoded offset in parse_sni()
        assert_eq!(s, 127);
    }

    #[test]
    fn test_split_chunk3_reassembly() {
        // "hcaptcha.com" (11 bytes) → "hca","ptc","ha.","com"
        let rec = build(&TlsFingerprint::Chrome120, "hcaptcha.com");
        assert_reassembly(&rec, 3);
    }

    #[test]
    fn test_split_chunk3_sni_is_fragmented() {
        let sni = "hcaptcha.com";
        let rec = build(&TlsFingerprint::Chrome120, sni);
        let frags = split_client_hello(&rec, 3);
        // The full SNI must NOT appear in any single fragment
        let sni_bytes = sni.as_bytes();
        assert!(
            !frags
                .iter()
                .any(|f| f.windows(sni_bytes.len()).any(|w| w == sni_bytes)),
            "SNI hostname found intact in a fragment — fragmentation did not split it"
        );
    }

    #[test]
    fn test_split_chunk0_sni_is_whole() {
        let sni = "example.com";
        let rec = build(&TlsFingerprint::Chrome120, sni);
        let frags = split_client_hello(&rec, 0);
        assert_reassembly(&rec, 0);
        // The entire SNI hostname must appear as exactly one fragment
        let sni_bytes = sni.as_bytes();
        assert!(
            frags.iter().any(|f| f.as_slice() == sni_bytes),
            "whole-SNI fragment not found with chunk_size=0"
        );
    }

    #[test]
    fn test_split_no_sni_returns_whole() {
        // TLS application_data record — not a ClientHello
        let record: Vec<u8> = vec![0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5];
        let frags = split_client_hello(&record, 3);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0], record);
    }

    #[test]
    fn test_reassembly_all_fingerprints() {
        let sni = "test.example.com";
        for fp in [
            TlsFingerprint::Default,
            TlsFingerprint::Chrome120,
            TlsFingerprint::Firefox120,
            TlsFingerprint::Safari17,
        ] {
            let rec = build(&fp, sni);
            for chunk in [0usize, 1, 3, 7, 50] {
                assert_reassembly(&rec, chunk);
            }
        }
    }

    #[test]
    fn test_sni_found_all_fingerprints() {
        let sni = "bypass.example.com";
        for fp in [
            TlsFingerprint::Default,
            TlsFingerprint::Chrome120,
            TlsFingerprint::Firefox120,
            TlsFingerprint::Safari17,
            TlsFingerprint::Edge120,
        ] {
            let rec = build(&fp, sni);
            let (s, e) = find_sni_range(&rec)
                .unwrap_or_else(|| panic!("SNI not found for fingerprint {:?}", fp));
            assert_eq!(&rec[s..e], sni.as_bytes(), "wrong SNI range for {:?}", fp);
        }
    }
}
