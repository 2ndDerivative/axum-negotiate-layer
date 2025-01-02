# axum-negotiate-layer

This crate provides an `axum`-compatible `tower` service and layer to authenticate
connections using the Microsoft "HTTP Negotiate" protocol.

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
    let listener = TcpListener::bind("0.0.0.0:80").await.unwrap().with_negotiate_info();
    axum::serve(listener, router).await.unwrap();
}

async fn hello(Extension(a): Extension<Authenticated>) -> String {
    format!("Hello, {}!", a.client().unwrap_or("whoever"))
}
```

# Dependencies
This crate uses the [cross-krb5](https://crates.io/crates/cross-krb5) crate for Kerberos/Negotiate authentication.

# Contributing
I will take contributions as they come and will try to support this crate further along, depending on the needs of submissions. Feel free to ask for features or fixes!

# Planned Features
- Finer behaviour control
