//! The checked endpoint must survive proxy routing without changing origin identity.
mod support;
use std::{net::SocketAddr, time::Duration};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wreq::{Client, dns::PinnedDestination};

async fn pinned(
    client: &Client,
    url: &str,
    address: SocketAddr,
) -> Result<wreq::Response, wreq::Error> {
    let mut req = client.get(url).build().unwrap();
    let pin = PinnedDestination::new(req.uri(), address);
    req.extensions_mut().insert(pin);
    client.execute(req).await
}

#[tokio::test]
async fn direct_pin_retains_host_and_isolates_pool() {
    let a = support::server::http(|req| {
        assert_eq!(req.headers()["host"], "unresolvable.invalid:8123");
        assert_eq!(req.uri().path(), "/Case");
        async { http::Response::new(wreq::Body::from("first")) }
    });
    let b = support::server::http(|req| {
        assert_eq!(req.headers()["host"], "unresolvable.invalid:8123");
        async { http::Response::new(wreq::Body::from("second")) }
    });
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let url = "http://unresolvable.invalid:8123/Case";
    assert_eq!(
        pinned(&client, url, a.addr())
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "first"
    );
    assert_eq!(
        pinned(&client, url, b.addr())
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "second"
    );
}

#[tokio::test]
async fn http_proxy_uses_pinned_absolute_uri_and_original_host() {
    let proxy = support::server::http(|req| {
        assert_eq!(req.uri(), "http://192.0.2.8:8089/Case?Token=A");
        assert_eq!(req.headers()["host"], "unresolvable.invalid:8089");
        async { http::Response::default() }
    });
    let client = Client::builder()
        .proxy(wreq::Proxy::all(format!("http://{}", proxy.addr())).unwrap())
        .build()
        .unwrap();
    let url = "http://unresolvable.invalid:8089/Case?Token=A";
    let response = pinned(&client, url, "192.0.2.8:8089".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(response.uri(), url);
}

#[tokio::test]
async fn https_connect_uses_pin_and_preserves_sni_and_evidence() {
    use std::sync::Arc;

    use tokio_rustls::{
        TlsAcceptor,
        rustls::{
            self,
            pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
        },
    };
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["unresolvable.invalid".into()]).unwrap();
    let der = cert.der().clone();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![der.clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der())),
    )
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(socket.read_u8().await.unwrap());
        }
        assert!(
            String::from_utf8(request)
                .unwrap()
                .starts_with("CONNECT 192.0.2.8:8443 HTTP/1.1\r\n")
        );
        socket
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .unwrap();
        let mut tls = acceptor.accept(socket).await.unwrap();
        assert_eq!(tls.get_ref().1.server_name(), Some("unresolvable.invalid"));
        let mut buf = [0; 8192];
        let n = tls.read(&mut buf).await.unwrap();
        assert!(
            String::from_utf8_lossy(&buf[..n])
                .to_lowercase()
                .contains("host: unresolvable.invalid:8443")
        );
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    let client = Client::builder()
        .proxy(wreq::Proxy::all(format!("http://{addr}")).unwrap())
        .tls_cert_verification(false)
        .tls_info(true)
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let response = pinned(
        &client,
        "https://unresolvable.invalid:8443/",
        "192.0.2.8:8443".parse().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        response
            .extensions()
            .get::<wreq::tls::TlsInfo>()
            .unwrap()
            .peer_certificate()
            .unwrap(),
        der.as_ref()
    );
    assert_eq!(response.text().await.unwrap(), "ok");
    task.await.unwrap();
}

#[cfg(feature = "socks")]
#[tokio::test]
async fn socks_remote_dns_cannot_replace_pin() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        assert_eq!(socket.read_u8().await.unwrap(), 5);
        let n = socket.read_u8().await.unwrap();
        let mut methods = vec![0; n as usize];
        socket.read_exact(&mut methods).await.unwrap();
        socket.write_all(&[5, 0]).await.unwrap();
        let mut request = [0; 10];
        socket.read_exact(&mut request).await.unwrap();
        assert_eq!(request, [5, 1, 0, 1, 192, 0, 2, 8, 0x1f, 0x99]); // 8089
        socket
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
        let mut buf = [0; 8192];
        let n = socket.read(&mut buf).await.unwrap();
        assert!(
            String::from_utf8_lossy(&buf[..n])
                .to_lowercase()
                .contains("host: unresolvable.invalid:8089")
        );
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    let client = Client::builder()
        .proxy(wreq::Proxy::all(format!("socks5h://{addr}")).unwrap())
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    assert_eq!(
        pinned(
            &client,
            "http://unresolvable.invalid:8089/",
            "192.0.2.8:8089".parse().unwrap()
        )
        .await
        .unwrap()
        .text()
        .await
        .unwrap(),
        "ok"
    );
    task.await.unwrap();
}

#[tokio::test]
async fn cross_origin_redirect_cannot_reuse_approval() {
    let server = support::server::http(|_| async {
        http::Response::builder()
            .status(302)
            .header("location", "http://other.invalid/private")
            .body(wreq::Body::default())
            .unwrap()
    });
    let client = Client::builder()
        .no_proxy()
        .redirect(wreq::redirect::Policy::limited(5))
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let error = pinned(&client, "http://unresolvable.invalid/", server.addr())
        .await
        .unwrap_err();
    assert!(format!("{error:?}").contains("pinned destination origin changed"));
}
