use crate::{unauthorized, StepResult};
use axum::{
    http::{
        header::{CONNECTION, WWW_AUTHENTICATE},
        HeaderMap, HeaderValue, StatusCode,
    },
    response::IntoResponse,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use cross_krb5::{PendingServerCtx, Step};

pub fn handle_kerberos(context: PendingServerCtx, token: &str) -> StepResult {
    let Ok(header_bytes) = BASE64_STANDARD.decode(token) else {
        return StepResult::Error(StatusCode::BAD_REQUEST.into_response());
    };
    match context.step(&header_bytes) {
        Ok(Step::Continue((ctx, server_response_bytes))) => {
            let mut header_map = HeaderMap::new();
            let encoded = BASE64_STANDARD.encode(server_response_bytes.as_ref());
            let hv = HeaderValue::from_str(&format!("Negotiate {encoded}"))
                .expect("Base64-string should be valid header material");
            header_map.insert(WWW_AUTHENTICATE, hv);
            header_map.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
            let response = (StatusCode::UNAUTHORIZED, header_map, "").into_response();
            StepResult::ContinueWith(crate::ServerContext::Kerberos(ctx), response)
        }
        Ok(Step::Finished((_ctx, _e))) => StepResult::Finished,
        Err(_e) => StepResult::Error(unauthorized("authorization failed")),
    }
}
