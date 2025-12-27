use axum::Json;
use axum::response::IntoResponse;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, Http, HttpAuthScheme, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::errors::{ErrorBody, ErrorDetail};
use crate::handlers::{
    AdminCreateCustomerRequest, AdminCreateCustomerResponse, AdminCreateKeyRequest,
    AdminCreateKeyResponse, AdminRevokeKeyRequest, AdminRevokeKeyResponse, ArtifactPresignRequest,
    ArtifactPresignResponse, ArtifactRegisterRequest, ArtifactRegisterResponse, ArtifactSummary,
    AuditEventListQuery, AuditEventListResponse, AuditEventResponse, DownloadTokenRequest,
    DownloadTokenResponse, EntitlementCreateRequest, EntitlementListQuery, EntitlementListResponse,
    EntitlementResponse, EntitlementUpdateRequest, ReleaseCreateRequest, ReleaseListQuery,
    ReleaseListResponse, ReleaseResponse,
};
use crate::models::ApiKeyIntrospection;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Releasy API",
        version = env!("CARGO_PKG_VERSION"),
        description = "Releasy API surface for releases, artifacts, downloads, and admin ops."
    ),
    paths(
        crate::handlers::admin_create_customer,
        crate::handlers::list_entitlements,
        crate::handlers::create_entitlement,
        crate::handlers::update_entitlement,
        crate::handlers::delete_entitlement,
        crate::handlers::list_audit_events,
        crate::handlers::admin_create_key,
        crate::handlers::admin_revoke_key,
        crate::handlers::create_release,
        crate::handlers::list_releases,
        crate::handlers::publish_release,
        crate::handlers::unpublish_release,
        crate::handlers::delete_release,
        crate::handlers::presign_release_artifact_upload,
        crate::handlers::register_release_artifact,
        crate::handlers::create_download_token,
        crate::handlers::resolve_download_token,
        crate::handlers::auth_introspect,
        crate::openapi::openapi_json
    ),
    components(
        schemas(
            ErrorBody,
            ErrorDetail,
            AdminCreateCustomerRequest,
            AdminCreateCustomerResponse,
            AdminCreateKeyRequest,
            AdminCreateKeyResponse,
            AdminRevokeKeyRequest,
            AdminRevokeKeyResponse,
            EntitlementCreateRequest,
            EntitlementUpdateRequest,
            EntitlementResponse,
            EntitlementListResponse,
            EntitlementListQuery,
            AuditEventResponse,
            AuditEventListResponse,
            AuditEventListQuery,
            ReleaseCreateRequest,
            ReleaseResponse,
            ReleaseListResponse,
            ReleaseListQuery,
            ArtifactSummary,
            ArtifactPresignRequest,
            ArtifactPresignResponse,
            ArtifactRegisterRequest,
            ArtifactRegisterResponse,
            DownloadTokenRequest,
            DownloadTokenResponse,
            ApiKeyIntrospection
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "admin", description = "Bootstrap administration endpoints."),
        (name = "entitlements", description = "Customer entitlements management."),
        (name = "audit", description = "Audit event access."),
        (name = "keys", description = "API key management."),
        (name = "releases", description = "Release lifecycle endpoints."),
        (name = "artifacts", description = "Artifact upload and registration."),
        (name = "downloads", description = "Download token issuance and resolution."),
        (name = "auth", description = "API key introspection."),
        (name = "meta", description = "Service metadata endpoints.")
    )
)]
pub struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "admin_key",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("x-releasy-admin-key"))),
            );
            components.add_security_scheme(
                "api_key",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("x-releasy-api-key"))),
            );
            components.add_security_scheme(
                "operator_jwt",
                SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
            );
        }
    }
}

#[utoipa::path(
    get,
    path = "/openapi.json",
    tag = "meta",
    summary = "Fetch the OpenAPI document",
    description = "Returns the generated OpenAPI JSON document.",
    responses(
        (status = 200, description = "OpenAPI document")
    )
)]
pub(crate) async fn openapi_json() -> impl IntoResponse {
    Json(ApiDoc::openapi())
}

pub fn openapi_json_pretty() -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&ApiDoc::openapi())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn parse_openapi() -> Value {
        let json = openapi_json_pretty().expect("openapi json");
        serde_json::from_str(&json).expect("parse openapi json")
    }

    #[test]
    fn openapi_contains_release_paths() {
        let value = parse_openapi();
        let paths = value
            .get("paths")
            .and_then(Value::as_object)
            .expect("paths object");
        assert!(paths.contains_key("/v1/releases"));
    }

    #[test]
    fn openapi_does_not_include_swagger_ui() {
        let value = parse_openapi();
        let paths = value
            .get("paths")
            .and_then(Value::as_object)
            .expect("paths object");
        assert!(!paths.contains_key("/swagger-ui"));
    }
}
