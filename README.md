# axum-negotiate-layer

This crate provides an `axum`-compatible `tower` service and layer to authenticate
connections using the Microsoft "HTTP Negotiate" protocol.

NTLM is currently only supported on Windows.

```rust
use axum::{routing::get, Extension, Router};
use axum_negotiate_layer::{Authenticated, NegotiateInfo, NegotiateLayer};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let router = Router::new()
        .route("/", get(hello))
        .layer(NegotiateLayer::new("HTTP/example.com"))
        .into_make_service_with_connect_info::<NegotiateInfo>();
    let listener = TcpListener::bind("0.0.0.0:80").await.unwrap();
    axum::serve(listener, router).await.unwrap();
}

async fn hello(Extension(a): Extension<Authenticated>) -> String {
    format!("Hello, {}!", a.client().unwrap_or("whoever"))
}
```

# Dependencies
This crate uses the [cross-krb5](https://crates.io/crates/cross-krb5) crate for Kerberos authentication and the [winauth](https://crates.io/crates/winauth) crate for (Windows-only) NTLM support.

It (so far) operates within the limited scope of those packages, but this project is planned to be made more extensive.

This crate closely relies on current behaviour of axum's [ConnectInfo](https://docs.rs/axum/latest/axum/extract/struct.ConnectInfo.html) API, a relatively new feature of that crate. This crate may become unsupported with changes to this axum feature.

# Contributing
I will take contributions as they come and will try to support this crate further along, depending on the needs of submissions. Feel free to ask for features or fixes!

# Planned Features

- Non-windows NTLM support
- Finer behaviour control
