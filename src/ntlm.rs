use axum::{
    http::{
        header::{CONNECTION, WWW_AUTHENTICATE},
        HeaderMap, HeaderValue, StatusCode,
    },
    response::IntoResponse,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use winauth::{windows::NtlmSspi, NextBytes};

use crate::{unauthorized, FinishedServerContext, PendingServerContext, StepResult};

pub fn handle_ntlm(mut ntlm: NtlmSspi, header: &str) -> StepResult {
    let Ok(header_bytes) = BASE64_STANDARD.decode(header) else {
        return StepResult::Error(StatusCode::BAD_REQUEST.into_response());
    };
    match ntlm.next_bytes(Some(&header_bytes)) {
        Ok(Some(response_bytes)) => {
            let mut headers = HeaderMap::new();
            let encoded = BASE64_STANDARD.encode(response_bytes);
            let hv = HeaderValue::from_str(&format!("Negotiate {encoded}"))
                .expect("Base64-string should be valid header material");
            headers.insert(WWW_AUTHENTICATE, hv);
            headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
            let response = (StatusCode::UNAUTHORIZED, headers, "").into_response();
            StepResult::ContinueWith(PendingServerContext::Ntlm(ntlm), response)
        }
        Ok(None) => StepResult::Finished(FinishedServerContext::Ntlm(ntlm)),
        Err(_) => StepResult::Error(unauthorized("authorization failed")),
    }
}
