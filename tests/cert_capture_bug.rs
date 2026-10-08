//! Local regressions for the Allure TLS evidence extensions.
//! Capture must survive verification errors, response errors, timeouts and pool reuse.

use std::{sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        self,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    },
};
use wreq::{Client, tls::TlsInfo};

#[derive(Clone, Copy)]
enum Reply {
    Ok,
    Stall,
    Close,
    OkThenStall,
}

struct Fixture {
    url: String,
    der: Vec<u8>,
    task: JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn fixture(version: &'static rustls::SupportedProtocolVersion, reply: Reply) -> Fixture {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = cert.der().to_vec();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[version])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der())),
    )
    .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "https://localhost:{}/",
        listener.local_addr().unwrap().port()
    );
    let task = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(socket).await else {
                    return;
                };
                let mut count = 0;
                loop {
                    let mut buf = [0; 8192];
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        _ => {}
                    }
                    count += 1;
                    match reply {
                        Reply::Close => return,
                        Reply::Stall => {
                            tokio::time::sleep(Duration::from_secs(3)).await;
                            return;
                        }
                        Reply::OkThenStall if count > 1 => {
                            tokio::time::sleep(Duration::from_secs(3)).await;
                            return;
                        }
                        _ => {}
                    }
                    if stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok").await.is_err() { return; }
                    if stream.flush().await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    Fixture { url, der, task }
}

fn client(verify: bool) -> Client {
    Client::builder()
        .tls_cert_verification(verify)
        .tls_info(true)
        .no_proxy()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_millis(700))
        .build()
        .unwrap()
}

async fn assert_capture(version: &'static rustls::SupportedProtocolVersion, encrypted: bool) {
    let f = fixture(version, Reply::Ok).await;
    let response = client(false).get(&f.url).send().await.unwrap();
    let info = response.extensions().get::<TlsInfo>().unwrap();
    assert_eq!(info.peer_certificate().unwrap(), f.der);
    assert_eq!(info.captured_chain_der().unwrap().next().unwrap(), f.der);
    assert!(info.server_hello().is_some_and(|hello| hello.len() > 32));
    assert_eq!(info.encrypted_extensions().is_some(), encrypted);
}

#[tokio::test]
async fn captures_tls12_certificate_and_server_hello() {
    assert_capture(&rustls::version::TLS12, false).await;
}
#[tokio::test]
async fn captures_tls13_certificate_and_encrypted_extensions() {
    assert_capture(&rustls::version::TLS13, true).await;
}

#[tokio::test]
async fn capture_does_not_disable_certificate_verification() {
    let f = fixture(&rustls::version::TLS13, Reply::Ok).await;
    let error = client(true)
        .get(&f.url)
        .send()
        .await
        .expect_err("self-signed certificate must fail verification");
    assert_eq!(error.captured_chain_der().unwrap().next().unwrap(), f.der);
}

#[tokio::test]
async fn response_timeout_retains_certificate() {
    let f = fixture(&rustls::version::TLS13, Reply::Stall).await;
    let error = client(false).get(&f.url).send().await.err().unwrap();
    assert!(error.is_timeout());
    assert_eq!(error.captured_chain_der().unwrap().next().unwrap(), f.der);
}

#[tokio::test]
async fn response_error_retains_certificate() {
    let f = fixture(&rustls::version::TLS13, Reply::Close).await;
    let error = client(false).get(&f.url).send().await.err().unwrap();
    assert_eq!(error.captured_chain_der().unwrap().next().unwrap(), f.der);
}

#[tokio::test]
async fn reused_connection_timeout_retains_certificate() {
    let f = fixture(&rustls::version::TLS13, Reply::OkThenStall).await;
    let client = client(false);
    assert_eq!(
        client
            .get(&f.url)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "ok"
    );
    let error = client
        .get(&f.url)
        .send()
        .await
        .expect_err("fixture stalls only on a reused connection");
    assert!(error.is_timeout());
    assert_eq!(error.captured_chain_der().unwrap().next().unwrap(), f.der);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_connections_keep_their_own_evidence() {
    let (a, b) = tokio::join!(
        fixture(&rustls::version::TLS13, Reply::Ok),
        fixture(&rustls::version::TLS13, Reply::Ok)
    );
    assert_ne!(a.der, b.der);
    let client = client(false);
    let (ra, rb) = tokio::join!(client.get(&a.url).send(), client.get(&b.url).send());
    for (response, expected) in [(ra.unwrap(), &a.der), (rb.unwrap(), &b.der)] {
        assert_eq!(
            response
                .extensions()
                .get::<TlsInfo>()
                .unwrap()
                .captured_chain_der()
                .unwrap()
                .next()
                .unwrap(),
            expected
        );
    }
}
