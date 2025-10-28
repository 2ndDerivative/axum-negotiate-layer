use crate::{to_negotiate_header, unauthorized, StepResult};
use axum::{
    http::{
        header::{CONNECTION, WWW_AUTHENTICATE},
        HeaderMap, HeaderValue, StatusCode,
    },
    response::IntoResponse,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use kenobi::{Step, StepSuccess};

pub fn handle_sspi(context: impl Step, token: &str) -> StepResult {
    let Ok(header_bytes) = BASE64_STANDARD.decode(token) else {
        return StepResult::Error(StatusCode::BAD_REQUEST.into_response());
    };
    match context.step(&header_bytes) {
        Ok(StepSuccess::Continue(context, response_bytes)) => {
            let mut header_map = HeaderMap::new();
            let hv = to_negotiate_header(&response_bytes);
            header_map.insert(WWW_AUTHENTICATE, hv);
            header_map.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
            let response = (StatusCode::UNAUTHORIZED, header_map, "").into_response();
            StepResult::ContinueWith(context, response)
        }
        Ok(StepSuccess::Finished(context, maybe_token)) => StepResult::Finished(context, maybe_token),
        Err(e) => {
            #[cfg(feature = "tracing")]
            tracing::error!("Authentication failed: {e:?}");
            StepResult::Error(unauthorized("authorization failed"))
        }
    }
}
