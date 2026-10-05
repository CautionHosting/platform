// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    Json,
    extract::{FromRequest, Request},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;

use crate::validation;

pub struct Validated<T>(pub T);

/// Rejection for [`Validated`] (JSON body mode). A source-less leaf; axum
/// requires `Rejection: IntoResponse`, so this type implements it with a fixed
/// generic body. The internal location never reaches the client.
#[derive(Debug, thiserror::Error)]
#[error("invalid JSON body [{location}]")]
pub struct JsonBodyRejection {
    location: &'static std::panic::Location<'static>,
}

impl IntoResponse for JsonBodyRejection {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, "bad request").into_response()
    }
}

impl<T, S> FromRequest<S> for Validated<T>
where
    T: DeserializeOwned + Validate,
    S: Send + Sync,
{
    type Rejection = JsonBodyRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state)
            .await
            .map_err(|_source| JsonBodyRejection {
                location: std::panic::Location::caller(),
            })?;

        match value.validate() {
            Ok(()) => {}
            Err(_source) => {
                return Err(JsonBodyRejection {
                    location: std::panic::Location::caller(),
                });
            }
        }

        Ok(Validated(value))
    }
}

pub trait Validate {
    fn validate(&self) -> Result<(), ValidationError>;
}

use crate::errors::ValidationError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub username: Option<String>,
    pub email: Option<String>,
}

impl Validate for UpdateUserRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.username.is_none() && self.email.is_none() {
            return Err(ValidationError::AtLeastOneFieldRequired {
                location: std::panic::Location::caller(),
            });
        }

        if let Some(username) = &self.username {
            validation::validate_username(username)?;
        }

        if let Some(email) = &self.email
            && !email.trim().is_empty()
        {
            validation::validate_email(email)?;
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateOrganizationRequest {
    pub name: String,
}

impl Validate for CreateOrganizationRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        validation::validate_org_name(&self.name)?;

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateOrganizationRequest {
    pub name: Option<String>,
}

impl Validate for UpdateOrganizationRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.name.is_none() {
            return Err(ValidationError::AtLeastOneFieldRequired {
                location: std::panic::Location::caller(),
            });
        }

        if let Some(name) = &self.name {
            validation::validate_org_name(name)?;
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct AddMemberRequest {
    pub user_id: Uuid,
    pub role: String,
}

impl Validate for AddMemberRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        validation::validate_role(&self.role)?;

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct InviteMemberRequest {
    pub email: String,
}

impl Validate for InviteMemberRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        validation::validate_email(self.email.trim())?;
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateMemberRequest {
    pub role: String,
}

impl Validate for UpdateMemberRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        validation::validate_role(&self.role)?;

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateResourceRequest {
    pub cmd: String,
    pub name: Option<String>,
}

impl Validate for CreateResourceRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        validation::validate_cmd(&self.cmd)?;

        if let Some(name) = &self.name {
            validation::validate_app_name(name)?;
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct DeployRequest {
    pub org_id: Uuid,
    pub app_id: Uuid,
    #[serde(default = "default_branch")]
    pub branch: String,
    #[serde(default)]
    pub commit_sha: Option<String>,
    /// Builder instance size: "small" (default), "medium", or "large"
    #[serde(default)]
    pub builder_size: Option<String>,
}

fn default_branch() -> String {
    "main".to_string()
}

impl Validate for DeployRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        validation::validate_branch_name(&self.branch)?;
        if let Some(commit_sha) = &self.commit_sha
            && (commit_sha.len() != 40 || !commit_sha.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(ValidationError::CommitShaInvalid {
                location: std::panic::Location::caller(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct CreateResourceResponse {
    pub id: Uuid,
    pub resource_name: String,
    pub git_url: String,
    pub state: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub managed_hostname: String,
    pub dns_status: String,
    pub dns_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeployResponse {
    pub url: String,
    pub attestation_url: String,
    pub resource_id: Uuid,
    pub public_ip: String,
    pub domain: Option<String>,
    pub managed_hostname: String,
    pub dns_status: String,
    pub dns_error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RenameResourceRequest {
    pub name: String,
}

impl Validate for RenameResourceRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        validation::validate_app_name(&self.name)?;

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateOrgSettingsRequest {
    pub require_pin: Option<bool>,
}

impl Validate for UpdateOrgSettingsRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.require_pin.is_none() {
            return Err(ValidationError::AtLeastOneFieldRequired {
                location: std::panic::Location::caller(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AddMemberRequest, CreateResourceRequest, DeployRequest, UpdateUserRequest, Validate,
    };
    use crate::validation::ValidationError;
    use uuid::Uuid;

    fn deploy_request(commit_sha: Option<&str>) -> DeployRequest {
        DeployRequest {
            org_id: Uuid::nil(),
            app_id: Uuid::nil(),
            branch: "main".to_string(),
            commit_sha: commit_sha.map(str::to_string),
            builder_size: None,
        }
    }

    #[test]
    fn deploy_request_accepts_valid_commit_sha() {
        let req = deploy_request(Some("abcdef123456abcdef123456abcdef123456abcd"));

        assert!(req.validate().is_ok());
    }

    #[test]
    fn deploy_request_rejects_invalid_commit_sha() {
        let req = deploy_request(Some("not-a-sha"));

        let err = req.validate().unwrap_err();

        assert!(matches!(err, ValidationError::CommitShaInvalid { .. }));
    }

    #[test]
    fn update_user_request_requires_at_least_one_field() {
        let req = UpdateUserRequest {
            username: None,
            email: None,
        };

        let err = req.validate().unwrap_err();

        assert!(matches!(
            err,
            ValidationError::AtLeastOneFieldRequired { .. }
        ));
    }

    #[test]
    fn update_user_request_rejects_invalid_username() {
        let req = UpdateUserRequest {
            username: Some("a".to_string()),
            email: None,
        };

        let err = req.validate().unwrap_err();

        assert!(matches!(err, ValidationError::UsernameLength { .. }));
    }

    #[test]
    fn add_member_request_rejects_invalid_role() {
        let req = AddMemberRequest {
            user_id: Uuid::nil(),
            role: "wizard".to_string(),
        };

        let err = req.validate().unwrap_err();

        assert!(matches!(err, ValidationError::InvalidRole { .. }));
    }

    #[test]
    fn create_resource_request_rejects_empty_cmd() {
        let req = CreateResourceRequest {
            cmd: String::new(),
            name: None,
        };

        let err = req.validate().unwrap_err();

        assert!(matches!(err, ValidationError::CmdEmpty { .. }));
    }
}
