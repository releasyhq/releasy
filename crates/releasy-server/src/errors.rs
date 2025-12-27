use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ErrorDetail {
    code: String,
    message: String,
}

#[derive(Debug, Clone)]
pub struct ApiError {
    status: StatusCode,
    code: String,
    message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        let code = default_code_for_status(status).to_string();
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn new_with_code(
        status: StatusCode,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized")
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }

    #[cfg(test)]
    pub(crate) fn status(&self) -> StatusCode {
        self.status
    }

    #[cfg(test)]
    pub(crate) fn code(&self) -> &str {
        &self.code
    }

    #[cfg(test)]
    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ErrorBody {
            error: ErrorDetail {
                code: self.code,
                message: self.message,
            },
        });
        (self.status, body).into_response()
    }
}

fn default_code_for_status(status: StatusCode) -> &'static str {
    match status {
        StatusCode::BAD_REQUEST => "bad_request",
        StatusCode::UNAUTHORIZED => "unauthorized",
        StatusCode::FORBIDDEN => "forbidden",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::CONFLICT => "conflict",
        StatusCode::SERVICE_UNAVAILABLE => "service_unavailable",
        _ => "internal_error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_error_sets_default_code() {
        let err = ApiError::bad_request("missing");
        assert_eq!(err.code(), "bad_request");
    }

    #[test]
    fn api_error_allows_custom_code() {
        let err = ApiError::new_with_code(
            StatusCode::CONFLICT,
            "idempotency_conflict",
            "idempotency key already used",
        );
        assert_eq!(err.code(), "idempotency_conflict");
    }
}
