// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::{FromRequest, Request},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::de::DeserializeOwned;

use crate::validation;

pub struct Validated<T>(pub T);

impl<T, S> FromRequest<S> for Validated<T>
where
    T: DeserializeOwned + Validate,
    S: Send + Sync,
{
    type Rejection = ValidationRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state)
            .await
            .map_err(|err| ValidationRejection {
                message: format!("Invalid JSON: {}", err),
                status: StatusCode::BAD_REQUEST,
            })?;

        value.validate().map_err(|err| ValidationRejection {
            message: format!("Validation failed: {}", err),
            status: StatusCode::BAD_REQUEST,
        })?;

        Ok(Validated(value))
    }
}

pub trait Validate {
    fn validate(&self) -> Result<(), String>;
}

pub struct ValidationRejection {
    pub message: String,
    pub status: StatusCode,
}

impl IntoResponse for ValidationRejection {
    fn into_response(self) -> Response {
        #[derive(serde::Serialize)]
        struct ErrorResponse {
            error: String,
        }

        let body = Json(ErrorResponse {
            error: self.message,
        });

        (self.status, body).into_response()
    }
}

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub username: Option<String>,
    pub email: Option<String>,
}

impl Validate for UpdateUserRequest {
    fn validate(&self) -> Result<(), String> {
        if self.username.is_none() && self.email.is_none() {
            return Err("At least one field must be provided".to_string());
        }

        if let Some(username) = &self.username {
            validation::validate_username(username)
                .map_err(|e| e.to_string())?;
        }

        if let Some(email) = &self.email {
            validation::validate_email(email)
                .map_err(|e| e.to_string())?;
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateOrganizationRequest {
    pub name: String,
}

impl Validate for CreateOrganizationRequest {
    fn validate(&self) -> Result<(), String> {
        validation::validate_org_name(&self.name)
            .map_err(|e| format!("Invalid name: {}", e))?;

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateOrganizationRequest {
    pub name: Option<String>,
}

impl Validate for UpdateOrganizationRequest {
    fn validate(&self) -> Result<(), String> {
        if self.name.is_none() {
            return Err("At least one field must be provided".to_string());
        }

        if let Some(name) = &self.name {
            validation::validate_org_name(name)
                .map_err(|e| format!("Invalid name: {}", e))?;
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
    fn validate(&self) -> Result<(), String> {
        validation::validate_role(&self.role)
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateMemberRequest {
    pub role: String,
}

impl Validate for UpdateMemberRequest {
    fn validate(&self) -> Result<(), String> {
        validation::validate_role(&self.role)
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateResourceRequest {
    pub cmd: String,
}

impl Validate for CreateResourceRequest {
    fn validate(&self) -> Result<(), String> {
        if self.cmd.is_empty() {
            return Err("Command cannot be empty".to_string());
        }

        if self.cmd.len() > 1000 {
            return Err("Command is too long (max 1000 characters)".to_string());
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct DeployRequest {
    pub org_id: Uuid,
    pub app_name: String,
    #[serde(default = "default_branch")]
    pub branch: String,
}

fn default_branch() -> String {
    "main".to_string()
}

impl Validate for DeployRequest {
    fn validate(&self) -> Result<(), String> {
        validation::validate_app_name(&self.app_name)
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct CreateResourceResponse {
    pub id: Uuid,
    pub resource_name: String,
    pub git_url: String,
    pub state: String,
    pub created_at: chrono::NaiveDateTime,
}

#[derive(Debug, Serialize)]
pub struct DeployResponse {
    pub url: String,
    pub attestation_url: String,
    pub resource_id: Uuid,
    pub public_ip: String,
    pub domain: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RenameResourceRequest {
    pub name: String,
}

impl Validate for RenameResourceRequest {
    fn validate(&self) -> Result<(), String> {
        validation::validate_app_name(&self.name)
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}
