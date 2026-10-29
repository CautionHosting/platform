// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! The AWS account an app's deployments live in: Caution's (fully managed) or
//! the customer's linked account (BYOC). The app network records which when
//! it is created (`AppNetwork::scope_tag`), so linking another environment
//! later never redirects operations on existing resources.

use crate::{AppState, cloud_credentials, deployment, ec2, fully_managed_capacity};
use dterror::{BoxError, CtxError, Location, ResultExt};
use uuid::Uuid;

/// Where an app's deployments live.
#[derive(Debug, Clone)]
pub(crate) enum AppAccount {
    /// Caution's account, with the API's own credentials.
    Platform { region: String },
    /// A linked (BYOC) account, with its delegated user's keys.
    Linked(deployment::AwsCredentials),
}

impl AppAccount {
    pub(crate) fn platform(region: &str) -> Self {
        Self::Platform {
            region: region.to_string(),
        }
    }

    pub(crate) fn region(&self) -> &str {
        match self {
            Self::Platform { region } => region,
            Self::Linked(credentials) => &credentials.region,
        }
    }

    /// The keys OpenTofu's AWS provider takes as variables. `None` keeps the
    /// fully managed configuration (environment credentials) unchanged.
    pub(crate) fn provider_credentials(&self) -> Option<&deployment::AwsCredentials> {
        match self {
            Self::Platform { .. } => None,
            Self::Linked(credentials) => Some(credentials),
        }
    }

    pub(crate) fn ec2(&self) -> ec2::Ec2Client {
        match self {
            Self::Platform { region } => ec2::Ec2Client::new(
                &fully_managed_capacity::platform_credentials_for_region(region),
            ),
            Self::Linked(credentials) => ec2::Ec2Client::new(credentials),
        }
    }
}

/// Failure modes for [`app_account`].
#[derive(Debug, thiserror::Error, CtxError, caution_error::ProviderError)]
pub(crate) enum AppAccountError {
    #[error("database error while reading the account of app {app_id}")]
    Database {
        app_id: Uuid,
        #[provide]
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("failed to read the linked AWS access of app {app_id}")]
    Credential {
        app_id: Uuid,
        #[provide]
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("the linked AWS access of app {app_id} is unavailable")]
    Unavailable {
        app_id: Uuid,
        #[provide]
        location: Location,
    },
    #[error("app {app_id} is linked to another environment than its network's")]
    EnvironmentChanged {
        app_id: Uuid,
        #[provide]
        location: Location,
    },
}

/// The account of `app_id`'s deployments in `region` (the caller's resources'
/// region). Caution's account only for a network created there, or for an app
/// with neither a network nor a linked credential. Never Caution's account for
/// a linked app: there its instances would look missing. A linked network's
/// credential must still be its environment (same provisioner deployment and
/// `region`). A linked app without a network (never pushed, a first push that
/// failed before its network, or a forced app destroy) uses its credential's
/// account and region: there is no network to verify it against. Unreadable
/// access is an error either way.
pub(crate) async fn app_account(
    state: &AppState,
    app_id: Uuid,
    region: &str,
) -> Result<AppAccount, AppAccountError> {
    use AppAccountErrorCtx as Ctx;

    let unavailable = || AppAccountError::Unavailable {
        app_id,
        location: std::panic::Location::caller(),
    };
    let (has_network, scope_tag): (bool, Option<String>) = sqlx::query_as(
        "SELECT app_network IS NOT NULL, app_network->>'scope_tag'
         FROM compute_resources WHERE id = $1",
    )
    .bind(app_id)
    .fetch_optional(&state.db)
    .await
    .with_context(Ctx::database(app_id))?
    .unwrap_or((false, None));
    let credential: Option<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT id, organization_id FROM cloud_credentials
         WHERE resource_id = $1 AND managed_on_prem",
    )
    .bind(app_id)
    .fetch_optional(&state.db)
    .await
    .with_context(Ctx::database(app_id))?;
    let scope_tag = match (scope_tag, &credential) {
        (Some(scope_tag), _) => Some(scope_tag),
        // Caution's network, whatever was linked since; or a fully managed app.
        (None, _) if has_network => return Ok(AppAccount::platform(region)),
        (None, None) => return Ok(AppAccount::platform(region)),
        // A linked app without a network: whatever exists is in its account.
        (None, Some(_)) => None,
    };
    let (credential_id, org_id) = credential.ok_or_else(unavailable)?;
    let encryptor = state.encryptor.as_deref().ok_or_else(unavailable)?;
    let data = cloud_credentials::get_managed_onprem_credential(
        &state.db,
        encryptor,
        org_id,
        credential_id,
    )
    .await
    .with_context(Ctx::credential(app_id))?
    .ok_or_else(unavailable)?;
    linked_account(app_id, scope_tag.as_deref(), region, data)
}

/// The delegated user's keys, if complete and, for a linked network
/// (`scope_tag`), still its environment (same provisioner deployment ID and
/// region). Without a network (`None`), the credential's own region.
fn linked_account(
    app_id: Uuid,
    scope_tag: Option<&str>,
    region: &str,
    data: cloud_credentials::ManagedOnPremCredentialData,
) -> Result<AppAccount, AppAccountError> {
    if let Some(scope_tag) = scope_tag
        && (data.deployment_id != scope_tag || data.aws_region != region)
    {
        return Err(AppAccountError::EnvironmentChanged {
            app_id,
            location: std::panic::Location::caller(),
        });
    }
    if data.aws_access_key_id.is_empty() || data.aws_secret_access_key.is_empty() {
        return Err(AppAccountError::Unavailable {
            app_id,
            location: std::panic::Location::caller(),
        });
    }
    Ok(AppAccount::Linked(deployment::AwsCredentials {
        access_key_id: data.aws_access_key_id,
        secret_access_key: data.aws_secret_access_key,
        region: data.aws_region,
    }))
}

/// The environment an app network lives in: `(scope_tag, vpc_id, region)`. No
/// row before the first deployment or after app destruction.
pub(crate) const NETWORK_ENVIRONMENT_SQL: &str =
    "SELECT app_network->>'scope_tag', app_network->>'vpc_id', app_network->>'region'
     FROM compute_resources WHERE id = $1 AND app_network IS NOT NULL";

/// A linked environment a push deploys into, or a relink links.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Linked<'a> {
    /// The provisioner deployment ID.
    pub(crate) scope_tag: &'a str,
    /// `None`: not compared (a relink, whose network may sit in a `provider`
    /// block's VPC).
    pub(crate) vpc_id: Option<&'a str>,
    pub(crate) region: &'a str,
}

/// Whether deploying with, or linking, `linked` (`None` for Caution's account)
/// keeps an app on the environment its network lives in (`(scope_tag, vpc_id,
/// region)` from [`NETWORK_ENVIRONMENT_SQL`]). A network without a scope tag is
/// in Caution's account and takes no linked environment.
pub(crate) fn keeps_environment(
    (network_scope, network_vpc, network_region): (Option<&str>, Option<&str>, Option<&str>),
    linked: Option<Linked<'_>>,
) -> bool {
    match (network_scope, linked) {
        (None, None) => true,
        (Some(scope), Some(linked)) => {
            scope == linked.scope_tag
                && network_region == Some(linked.region)
                && linked
                    .vpc_id
                    .is_none_or(|vpc_id| network_vpc == Some(vpc_id))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(
        deployment_id: &str,
        region: &str,
        key: &str,
    ) -> cloud_credentials::ManagedOnPremCredentialData {
        cloud_credentials::ManagedOnPremCredentialData {
            deployment_id: deployment_id.to_string(),
            asg_name: String::new(),
            launch_template_name: String::new(),
            launch_template_id: String::new(),
            vpc_id: "vpc-a".to_string(),
            subnet_ids: Vec::new(),
            eif_bucket: String::new(),
            instance_profile_name: String::new(),
            builder_instance_profile_name: None,
            aws_access_key_id: key.to_string(),
            aws_secret_access_key: "secret".to_string(),
            aws_region: region.to_string(),
        }
    }

    #[test]
    fn a_linked_network_uses_only_its_own_environment() {
        let app = Uuid::nil();
        let account = linked_account(
            app,
            Some("dep-a"),
            "us-east-1",
            data("dep-a", "us-east-1", "AKIA"),
        )
        .unwrap();
        assert_eq!(
            account.provider_credentials().unwrap().access_key_id,
            "AKIA"
        );
        assert_eq!(account.region(), "us-east-1");
        for other in [
            data("dep-b", "us-east-1", "AKIA"),
            data("dep-a", "us-west-2", "AKIA"),
        ] {
            assert!(matches!(
                linked_account(app, Some("dep-a"), "us-east-1", other),
                Err(AppAccountError::EnvironmentChanged { .. })
            ));
        }
        for scope_tag in [Some("dep-a"), None] {
            assert!(matches!(
                linked_account(app, scope_tag, "us-east-1", data("dep-a", "us-east-1", "")),
                Err(AppAccountError::Unavailable { .. })
            ));
            let mut no_secret = data("dep-a", "us-east-1", "AKIA");
            no_secret.aws_secret_access_key.clear();
            assert!(matches!(
                linked_account(app, scope_tag, "us-east-1", no_secret),
                Err(AppAccountError::Unavailable { .. })
            ));
        }
    }

    #[test]
    fn a_linked_app_without_a_network_uses_its_credentials_account() {
        let account = linked_account(
            Uuid::nil(),
            None,
            "us-east-1",
            data("dep-b", "us-west-2", "AKIA"),
        )
        .unwrap();
        assert_eq!(
            account.provider_credentials().unwrap().access_key_id,
            "AKIA"
        );
        assert_eq!(account.region(), "us-west-2");
    }

    #[test]
    fn the_platform_account_keeps_the_managed_configuration() {
        let account = AppAccount::platform("us-west-2");
        assert_eq!(account.region(), "us-west-2");
        assert!(account.provider_credentials().is_none());
    }

    #[test]
    fn an_app_keeps_the_environment_its_network_lives_in() {
        fn push<'a>(scope_tag: &'a str, vpc_id: &'a str, region: &'a str) -> Option<Linked<'a>> {
            Some(Linked {
                scope_tag,
                vpc_id: Some(vpc_id),
                region,
            })
        }
        fn relink<'a>(scope_tag: &'a str, region: &'a str) -> Option<Linked<'a>> {
            Some(Linked {
                scope_tag,
                vpc_id: None,
                region,
            })
        }
        let linked = (Some("dep-a"), Some("vpc-a"), Some("us-east-1"));
        let managed = (None, Some("vpc-m"), Some("us-east-1"));

        assert!(keeps_environment(managed, None), "Caution's account");
        assert!(keeps_environment(
            linked,
            push("dep-a", "vpc-a", "us-east-1")
        ));
        assert!(
            !keeps_environment(linked, push("dep-b", "vpc-a", "us-east-1")),
            "another provisioned environment"
        );
        assert!(
            !keeps_environment(linked, push("dep-a", "vpc-b", "us-east-1")),
            "a provider block's other VPC"
        );
        assert!(
            !keeps_environment(linked, push("dep-a", "vpc-a", "us-west-2")),
            "another region"
        );
        assert!(
            !keeps_environment(linked, None),
            "the linked credential is gone"
        );
        assert!(
            !keeps_environment(managed, push("dep-a", "vpc-a", "us-east-1")),
            "BYOC onto a fully managed network"
        );

        // A relink compares the environment and region, not the VPC.
        assert!(
            keeps_environment(linked, relink("dep-a", "us-east-1")),
            "rotating the keys"
        );
        assert!(
            keeps_environment(
                (Some("dep-a"), Some("vpc-provider"), Some("us-east-1")),
                relink("dep-a", "us-east-1")
            ),
            "rotating the keys of a network in a provider block's VPC"
        );
        assert!(
            !keeps_environment(linked, relink("dep-b", "us-east-1")),
            "relinking another environment"
        );
        assert!(
            !keeps_environment(linked, relink("dep-a", "us-west-2")),
            "relinking another region"
        );
        assert!(
            !keeps_environment(managed, relink("dep-a", "us-east-1")),
            "relinking a fully managed network"
        );
    }
}
