use crate::{StepResult, to_negotiate_header, unauthorized};
use axum_core::response::IntoResponse;
use base64::{Engine, prelude::BASE64_STANDARD};
use cross_krb5::{K5ServerCtx, PendingServerCtx, Step};
use http::{
    HeaderMap, HeaderValue, StatusCode,
    header::{CONNECTION, WWW_AUTHENTICATE},
};

pub fn handle_sspi(context: PendingServerCtx, token: &str) -> StepResult {
    tracing::trace!(token_length = token.len());
    let Ok(header_bytes) = BASE64_STANDARD.decode(token) else {
        return StepResult::Error(StatusCode::BAD_REQUEST.into_response());
    };
    match context.step(&header_bytes) {
        Ok(Step::Continue((context, response_bytes))) => {
            tracing::debug!("SPNEGO Continue, sending {} bytes", response_bytes.len());
            let mut header_map = HeaderMap::new();
            header_map.insert(WWW_AUTHENTICATE, to_negotiate_header(&response_bytes));
            header_map.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
            let response = (StatusCode::UNAUTHORIZED, header_map, "continue").into_response();
            StepResult::ContinueWith(context, response)
        }
        Ok(Step::Finished((mut context, maybe_token))) => {
            tracing::info!(
                "SPNEGO Finished: authenticated {}",
                context.client().as_deref().unwrap_or("unknown")
            );
            StepResult::Finished(context, maybe_token.map(|x| x.as_ref().into()))
        }
        Err(e) => {
            #[cfg(feature = "tracing")]
            tracing::error!("Authentication failed: {e:?}");
            StepResult::Error(unauthorized("authorization failed"))
        }
    }
}
