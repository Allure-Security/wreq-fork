# Allure TLS evidence extensions

This fork is based on upstream `wreq` v0.16.1 (the upstream project reset its version numbering after 6.0.0-rc.31). It requires Rust 1.98 or later and uses btls/tokio-btls.

The fork retains connection-local Certificate, ServerHello and EncryptedExtensions capture for MarcoPolo. `TlsInfo::captured_chain_der`, `server_hello` and `encrypted_extensions` expose successful-handshake evidence; `Error::captured_chain_der` preserves certificates on verification failures, response errors and response-header timeouts, including pooled connections. Capture callbacks do not replace certificate verification.

Request capture state is carried separately from connection-pool identity. The upstream total timeout continues across response headers and body without restarting its timer.

Local fixtures in `tests/cert_capture_bug.rs` cover TLS 1.2/1.3, verification enforcement, concurrent connection isolation, response failures and reused-connection timeouts. They require no external sites.

```sh
cargo test --lib --test cert_capture_bug --test timeouts --features stream
cargo clippy --all-targets --all-features -- -D warnings
cargo +nightly fmt --all -- --check
```

Applications should pin this fork by Git revision and commit their Cargo.lock. The empty workspace declaration permits standalone fork testing even when checked out inside an application's directory.
