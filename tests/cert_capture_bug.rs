//! Reproduces the BAD_CERTIFICATE miss for self-signed and expired certs.
//!
//! With cert_verification(false), wreq should:
//!   1. Complete the TLS handshake (not reject)
//!   2. Capture the peer certificate chain in the thread-local
//!   3. Return a successful Response with TlsInfo containing the cert
//!
//! BUG: The current verify_callback only captures the chain when `ok == true`.
//! When cert_verification(false) is set, set_cert_verification installs
//! SslVerifyMode::NONE, but set_verify_callback re-arms PEER mode.
//! For self-signed/expired certs, BoringSSL's native verifier sets ok=false,
//! the callback skips capture AND returns false, so the handshake fails.
//!
//! FIX (in wreq-fork-new): `ok || bypass_verify` for both capture and return.

use std::time::Duration;
use wreq::{Client, tls::TlsInfo};

/// Test against self-signed.badssl.com — a known self-signed cert.
/// With cert_verification(false), this should succeed and return TlsInfo.
#[tokio::test]
async fn self_signed_cert_is_captured() {
    let client = Client::builder()
        .cert_verification(false)
        .connect_timeout(Duration::from_secs(15))
        .tls_info(true)
        .no_proxy()
        .build()
        .unwrap();

    let resp = client
        .get("https://self-signed.badssl.com/")
        .send()
        .await
        .expect("cert_verification(false) should allow self-signed certs");

    assert!(resp.status().is_success(), "should get 200");

    let tls_info = resp.extensions().get::<TlsInfo>();
    assert!(tls_info.is_some(), "TlsInfo should be present");

    let peer_cert = tls_info.unwrap().peer_certificate();
    assert!(
        peer_cert.is_some(),
        "BUG: peer certificate not captured for self-signed cert"
    );
    println!(
        "✓ self-signed cert captured, {} bytes",
        peer_cert.unwrap().len()
    );
}

/// Test against expired.badssl.com — a known expired cert.
#[tokio::test]
async fn expired_cert_is_captured() {
    let client = Client::builder()
        .cert_verification(false)
        .connect_timeout(Duration::from_secs(15))
        .tls_info(true)
        .no_proxy()
        .build()
        .unwrap();

    let resp = client
        .get("https://expired.badssl.com/")
        .send()
        .await
        .expect("cert_verification(false) should allow expired certs");

    assert!(resp.status().is_success(), "should get 200");

    let tls_info = resp.extensions().get::<TlsInfo>();
    assert!(tls_info.is_some(), "TlsInfo should be present");

    let peer_cert = tls_info.unwrap().peer_certificate();
    assert!(
        peer_cert.is_some(),
        "BUG: peer certificate not captured for expired cert"
    );
    println!(
        "✓ expired cert captured, {} bytes",
        peer_cert.unwrap().len()
    );
}

/// Test against the actual URLs from the probe that MP missed.
/// 32.38rf8t.info — self-signed cert
/// Note: these servers may not respond to HTTP after TLS, so we accept
/// both Ok (got response) and Err (send failed after handshake) as long
/// as the error is NOT a Connect/CERTIFICATE_VERIFY_FAILED.
#[tokio::test]
async fn probe_url_self_signed_38rf8t() {
    let client = Client::builder()
        .cert_verification(false)
        .connect_timeout(Duration::from_secs(12))
        .timeout(Duration::from_secs(15))
        .tls_info(true)
        .no_proxy()
        .build()
        .unwrap();

    let result = client.get("https://32.38rf8t.info/").send().await;
    match result {
        Ok(resp) => {
            let tls_info = resp.extensions().get::<TlsInfo>();
            let has_cert = tls_info.and_then(|t| t.peer_certificate()).is_some();
            println!(
                "32.38rf8t.info: status={}, has_cert={}",
                resp.status(),
                has_cert
            );
            assert!(has_cert, "cert should be captured for self-signed site");
        }
        Err(e) => {
            let err_str = format!("{}", e);
            // SendRequest = TLS handshake succeeded, HTTP failed (server is flaky)
            // Connect + CERTIFICATE_VERIFY_FAILED = TLS handshake rejected (the bug)
            if err_str.contains("CERTIFICATE_VERIFY_FAILED") {
                panic!(
                    "BUG: cert_verification(false) did not bypass — \
                     verify_callback returned false for self-signed cert: {e}"
                );
            }
            println!("32.38rf8t.info: post-TLS error (handshake OK): {e}");
        }
    }
}

/// zc2qx39p.kkcdn123456789s.top — expired cert
#[tokio::test]
async fn probe_url_expired_kkcdn() {
    let client = Client::builder()
        .cert_verification(false)
        .connect_timeout(Duration::from_secs(12))
        .timeout(Duration::from_secs(15))
        .tls_info(true)
        .no_proxy()
        .build()
        .unwrap();

    let result = client
        .get("https://zc2qx39p.kkcdn123456789s.top/")
        .send()
        .await;
    match result {
        Ok(resp) => {
            let tls_info = resp.extensions().get::<TlsInfo>();
            let has_cert = tls_info.and_then(|t| t.peer_certificate()).is_some();
            println!(
                "zc2qx39p.kkcdn123456789s.top: status={}, has_cert={}",
                resp.status(),
                has_cert
            );
            assert!(has_cert, "cert should be captured for expired site");
        }
        Err(e) => {
            let err_str = format!("{}", e);
            if err_str.contains("CERTIFICATE_VERIFY_FAILED") {
                panic!(
                    "BUG: cert_verification(false) did not bypass — \
                     verify_callback returned false for expired cert: {e}"
                );
            }
            println!("zc2qx39p.kkcdn123456789s.top: post-TLS error (handshake OK): {e}");
        }
    }
}
