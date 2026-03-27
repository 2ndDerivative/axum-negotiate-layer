use std::{borrow::Cow, net::Ipv4Addr};

use axum::{Router, routing::get};
use axum_negotiate_layer::{Authenticated, NegotiateInfo, NegotiateLayer};
use http::Request;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tower::Service;

#[tokio::test]
async fn main() {
    tracing_subscriber::fmt::init();
    let spn = std::env::var("TEST_SPN").ok();
    let router = Router::new()
        .route("/", get(cheers))
        .layer(NegotiateLayer::new(spn.as_deref()));
    let tcp = TcpListener::bind((Ipv4Addr::from_octets([0, 0, 0, 0]), 5000))
        .await
        .unwrap();
    loop {
        let (con, _addr) = tcp.accept().await.unwrap();
        let Ok(tower_service) = router
            .clone()
            .into_make_service_with_connect_info::<NegotiateInfo>()
            .call(NegotiateInfo::new())
            .await;
        let hyper = hyper::service::service_fn(move |req: Request<Incoming>| tower_service.clone().call(req));
        let _ret = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
            .serve_connection_with_upgrades(TokioIo::new(con), hyper)
            .await;
    }
}

async fn cheers(mut auth: Authenticated) -> Cow<'static, str> {
    auth.client().map(Into::into).unwrap_or("UNKNOWN".into())
}
