// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use serde::{Deserialize, Serialize};
use sqlx::Type;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Owner,
    Admin,
    Member,
    Viewer,
}

impl UserRole {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "owner" => Some(UserRole::Owner),
            "admin" => Some(UserRole::Admin),
            "member" => Some(UserRole::Member),
            "viewer" => Some(UserRole::Viewer),
            _ => None,
        }
    }

    pub fn can_manage_org(&self) -> bool {
        matches!(self, UserRole::Owner | UserRole::Admin)
    }

    pub fn is_owner(&self) -> bool {
        matches!(self, UserRole::Owner)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "resource_state", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ResourceState {
    Initialized,
    Pending,
    Running,
    Stopped,
    Terminating,
    Terminated,
    Failed,
}

impl ResourceState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResourceState::Initialized => "initialized",
            ResourceState::Pending => "pending",
            ResourceState::Running => "running",
            ResourceState::Stopped => "stopped",
            ResourceState::Terminating => "terminating",
            ResourceState::Terminated => "terminated",
            ResourceState::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AWSResourceType {
    #[serde(rename = "ec2-instance")]
    EC2Instance,
    #[serde(rename = "rds-instance")]
    RDSInstance,
    #[serde(rename = "s3-bucket")]
    S3Bucket,
}

impl AWSResourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AWSResourceType::EC2Instance => "ec2-instance",
            AWSResourceType::RDSInstance => "rds-instance",
            AWSResourceType::S3Bucket => "s3-bucket",
        }
    }
}
