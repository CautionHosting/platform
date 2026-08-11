// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Drift Detector CLI
//!
//! This binary loads database connection and AWS credentials from environment variables,
//! queries the expected state from the database and actual state from AWS EC2,
//! then prints a formatted drift report to stdout.
//!
//! Arguments:
//! - `ORG_ID` (optional): scan only this organization; all active organizations are
//!   scanned when omitted
//! - `MIN_SEVERITY` (optional): `info`, `warning`, or `critical`; drifts below this
//!   threshold are omitted from the report (default `info`)
//!
//! Environment variables:
//! - `DATABASE_URL` (required): `PostgreSQL` connection string
//! - `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (optional): static AWS credentials;
//!   when both are unset, the default credential chain is used
//! - `RUST_LOG` (optional): tracing filter, defaults to `info`

use drift_detector::aws::{AwsCredentials, AwsError, Ec2Inspector, Ec2Instance};
use drift_detector::db::{
    ComputeResource, DbError, ProviderAccount, get_active_organization_ids, get_compute_resources,
    get_provider_accounts,
};
use drift_detector::drift::{
    DriftReport, DriftSeverity, OrganizationDriftReport, ParseDriftSeverityError,
    detect_orphaned_resources, detect_resource_drift, format_drift_report,
};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::collections::{HashMap, HashSet};
use std::env;
use thiserror::Error;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use uuid::Uuid;

/// Drift detector entry point.
///
/// Initializes tracing, runs the scan, and exits with a non-zero status when
/// a fatal error occurs or critical drift is detected.
#[tokio::main]
async fn main() {
    init_tracing();

    if let Err(err) = run().await {
        tracing::error!(?err, "drift detection failed");
        std::process::exit(1);
    }
}

/// Run the drift detection scan.
///
/// Fatal failures (environment, database connection, organization resolution)
/// are returned as errors; per-organization failures are logged and counted so
/// the remaining organizations can still be scanned.
async fn run() -> Result<(), RunError> {
    let (database_url, aws_access_key_id, aws_secret_access_key) = load_environment()?;
    let pool = connect_database(&database_url).await?;

    let org_id_arg: Option<Uuid> = env::args().nth(1).and_then(|s| s.parse().ok());
    let min_severity: DriftSeverity = match env::args().nth(2) {
        Some(raw) => raw.parse()?,
        None => DriftSeverity::Info,
    };

    let org_ids = resolve_org_ids(&pool, org_id_arg).await?;

    let mut any_critical = false;
    let mut failed_scans = 0;
    let mut total_resources_checked = 0;

    println!(
        "  DRIFT DETECTION REPORT - Scanning {} organization(s) (minimum severity: {})",
        org_ids.len(),
        min_severity
    );

    for (idx, org_id) in org_ids.iter().enumerate() {
        if idx > 0 {
            println!("\n---\n");
        }

        match detect_organization_drift(
            &pool,
            *org_id,
            idx,
            min_severity,
            &aws_access_key_id,
            &aws_secret_access_key,
        )
        .await
        {
            Ok(Some(scan)) => {
                total_resources_checked += scan.resources_checked;

                println!("\n{}", format_drift_report(&scan.report));

                if scan.report.has_critical() {
                    tracing::error!(%org_id, "CRITICAL drift detected");
                    any_critical = true;
                } else if !scan.report.drifts.is_empty() {
                    println!(
                        "[{}] ✓ Drift detected but no critical issues for organization {}",
                        idx + 1,
                        org_id
                    );
                } else {
                    println!("✓ No drift detected for organization {org_id}");
                }
            }
            Ok(None) => {}
            Err(err) => {
                failed_scans += 1;
                tracing::error!(%org_id, ?err, "Failed to scan organization; skipping");
            }
        }
    }

    print_summary(
        &org_ids,
        total_resources_checked,
        any_critical,
        failed_scans,
    );

    Ok(())
}

/// Fatal errors that abort the whole scan.
#[derive(Debug, Error)]
enum RunError {
    /// Failed to load environment configuration.
    #[error("failed to load environment configuration")]
    Environment(#[from] EnvironmentError),

    /// Failed to connect to the database.
    #[error("failed to connect to the database")]
    Database(#[from] DatabaseConnectError),

    /// Failed to resolve the organizations to scan.
    #[error("failed to resolve the organizations to scan")]
    ResolveOrgs(#[from] ResolveOrgsError),

    /// The minimum severity argument could not be parsed.
    #[error("failed to parse minimum drift severity")]
    InvalidSeverity(#[from] ParseDriftSeverityError),
}

/// Errors loading the CLI environment.
#[derive(Debug, Error)]
enum EnvironmentError {
    /// `DATABASE_URL` is not set or not valid unicode.
    #[error("DATABASE_URL environment variable must be set")]
    MissingDatabaseUrl(#[source] env::VarError),
}

/// Errors connecting to `PostgreSQL`.
#[derive(Debug, Error)]
enum DatabaseConnectError {
    /// The connection attempt failed.
    #[error("failed to connect to PostgreSQL database")]
    Connect(#[source] sqlx::Error),
}

/// Errors resolving which organizations to scan.
#[derive(Debug, Error)]
enum ResolveOrgsError {
    /// The database contains no active organizations.
    #[error("no active organizations found in database")]
    NoActiveOrganizations,

    /// Listing active organizations failed.
    #[error("failed to list active organizations")]
    List(#[from] DbError),
}

/// Errors that prevent scanning a single organization (the scan is skipped).
#[derive(Debug, Error)]
enum OrgScanError {
    /// Failed to load the organization's provider accounts.
    #[error("failed to load provider accounts for organization {org_id}")]
    LoadProviderAccounts {
        /// The organization being scanned.
        org_id: Uuid,
        /// The underlying database error.
        #[source]
        source: DbError,
    },

    /// Failed to load the organization's compute resources.
    #[error("failed to load compute resources for organization {org_id}")]
    LoadComputeResources {
        /// The organization being scanned.
        org_id: Uuid,
        /// The underlying database error.
        #[source]
        source: DbError,
    },

    /// None of the organization's provider accounts could be queried.
    #[error("no provider account could be queried for organization {org_id}")]
    NoAccountsQueried {
        /// The organization being scanned.
        org_id: Uuid,
    },
}

/// Initialize tracing with an optional `RUST_LOG` filter (defaults to `info`).
fn init_tracing() {
    tracing_subscriber::registry()
        .with(EnvFilter::new(
            env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .init();
}

/// Load configuration from environment variables.
fn load_environment() -> Result<(String, String, String), EnvironmentError> {
    let database_url = env::var("DATABASE_URL").map_err(EnvironmentError::MissingDatabaseUrl)?;

    let aws_access_key_id = env::var("AWS_ACCESS_KEY_ID").unwrap_or_default();
    let aws_secret_access_key = env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default();

    Ok((database_url, aws_access_key_id, aws_secret_access_key))
}

/// Connect to `PostgreSQL`.
async fn connect_database(database_url: &str) -> Result<PgPool, DatabaseConnectError> {
    tracing::info!("Connecting to database...");
    PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .map_err(DatabaseConnectError::Connect)
}

/// Resolve the organizations to scan, either from the CLI argument or by querying
/// all active organizations.
async fn resolve_org_ids(
    pool: &PgPool,
    org_id_arg: Option<Uuid>,
) -> Result<Vec<Uuid>, ResolveOrgsError> {
    if let Some(id) = org_id_arg {
        tracing::info!(org_id = %id, "Scanning single organization");
        return Ok(vec![id]);
    }

    tracing::info!("No org_id provided, scanning all active organizations");
    let org_ids = get_active_organization_ids(pool).await?;

    if org_ids.is_empty() {
        return Err(ResolveOrgsError::NoActiveOrganizations);
    }

    tracing::info!(
        org_count = %org_ids.len(),
        "Finished searching active organizations"
    );
    Ok(org_ids)
}

/// Result of scanning a single organization for drift.
struct OrgScan {
    /// The drift report for this organization.
    report: OrganizationDriftReport,
    /// Number of expected resources that were compared against AWS.
    resources_checked: usize,
}

/// Detect drift for one organization.
///
/// Returns `Ok(None)` when the organization has no provider accounts or no
/// tracked resources to compare (the corresponding message is printed to
/// stdout), `Err` when the scan could not be completed (for example when none
/// of the organization's accounts could be queried).
async fn detect_organization_drift(
    pool: &PgPool,
    org_id: Uuid,
    idx: usize,
    min_severity: DriftSeverity,
    aws_access_key_id: &str,
    aws_secret_access_key: &str,
) -> Result<Option<OrgScan>, OrgScanError> {
    tracing::info!(%org_id, "Loading expected state");

    let provider_accounts = get_provider_accounts(pool, org_id)
        .await
        .map_err(|source| OrgScanError::LoadProviderAccounts { org_id, source })?;

    if provider_accounts.is_empty() {
        println!(
            "[{}] No active provider accounts found for organization {}\n",
            idx + 1,
            org_id
        );
        return Ok(None);
    }

    let expected_resources = get_compute_resources(pool, org_id)
        .await
        .map_err(|source| OrgScanError::LoadComputeResources { org_id, source })?;

    if expected_resources.is_empty() {
        println!(
            "[{}] No drift detected for organization {}: no resources tracked in database\n",
            idx + 1,
            org_id
        );
        return Ok(None);
    }

    tracing::info!(
        account_count = %provider_accounts.len(),
        resource_count = %expected_resources.len(),
        "Found provider accounts and resources"
    );

    let result = detect_aws_drift(
        &provider_accounts,
        &expected_resources,
        aws_access_key_id,
        aws_secret_access_key,
    )
    .await;

    if result.accounts_failed == provider_accounts.len() {
        return Err(OrgScanError::NoAccountsQueried { org_id });
    }

    Ok(Some(OrgScan {
        report: OrganizationDriftReport::new(org_id, provider_accounts, result.drifts)
            .with_severity(min_severity),
        resources_checked: result.resources_checked,
    }))
}

/// Result of comparing expected resources against AWS.
struct AwsScanResult {
    /// Drift detected across all queried accounts.
    drifts: Vec<DriftReport>,
    /// Number of expected resources actually compared against AWS.
    resources_checked: usize,
    /// Number of provider accounts that could not be queried.
    accounts_failed: usize,
}

/// Compare expected resources against AWS and collect all detected drift,
/// including orphaned instances that exist in AWS but not in the database.
///
/// Each expected resource is matched against the instances of its own
/// provider account, so a resource is only reported missing when it does not
/// exist in that account. Resources whose owning account could not be queried
/// are skipped (a warning is logged at the account level) rather than being
/// reported missing. Orphan detection is likewise scoped per account, so an
/// instance is only treated as tracked when the database records a resource
/// for the same account.
async fn detect_aws_drift(
    provider_accounts: &[ProviderAccount],
    expected_resources: &[ComputeResource],
    aws_access_key_id: &str,
    aws_secret_access_key: &str,
) -> AwsScanResult {
    let mut drifts = Vec::new();
    let mut resources_checked = 0;
    let mut accounts_failed = 0;

    let mut queried_accounts: Vec<(&ProviderAccount, Vec<Ec2Instance>)> = Vec::new();
    for account in provider_accounts {
        match query_live_instances(account, aws_access_key_id, aws_secret_access_key).await {
            Ok(instances) => queried_accounts.push((account, instances)),
            Err(err) => {
                accounts_failed += 1;
                tracing::warn!(
                    account_id = %account.external_account_id,
                    ?err,
                    "Failed to query AWS; skipping account"
                );
            }
        }
    }

    let account_index: HashMap<Uuid, usize> = queried_accounts
        .iter()
        .enumerate()
        .map(|(index, (account, _))| (account.id, index))
        .collect();

    for resource in expected_resources {
        match account_index.get(&resource.provider_account_id).copied() {
            Some(index) => {
                let instances = &queried_accounts[index].1;
                let aws_instance = instances
                    .iter()
                    .find(|instance| instance.instance_id == resource.provider_resource_id);
                drifts.extend(detect_resource_drift(resource, aws_instance));
                resources_checked += 1;
            }
            None => {
                tracing::debug!(
                    resource_id = %resource.id,
                    account_id = %resource.provider_account_id,
                    "Skipping resource: its provider account could not be queried"
                );
            }
        }
    }

    for (account, instances) in &queried_accounts {
        let account_db_ids: HashSet<String> = expected_resources
            .iter()
            .filter(|resource| resource.provider_account_id == account.id)
            .map(|resource| resource.provider_resource_id.clone())
            .collect();
        drifts.extend(detect_orphaned_resources(
            &account_db_ids,
            instances,
            account,
        ));
    }

    AwsScanResult {
        drifts,
        resources_checked,
        accounts_failed,
    }
}

/// List live EC2 instances for a provider account.
async fn query_live_instances(
    account: &ProviderAccount,
    aws_access_key_id: &str,
    aws_secret_access_key: &str,
) -> Result<Vec<Ec2Instance>, AwsError> {
    let creds = aws_credentials(account, aws_access_key_id, aws_secret_access_key);

    let inspector = Ec2Inspector::from_credentials(&creds).await;
    tracing::info!(region = %inspector.region(), "Querying AWS EC2");
    inspector.list_live_instances().await
}

/// Build AWS credentials for a provider account, falling back to the default
/// credential chain when static keys are not configured.
fn aws_credentials(
    account: &ProviderAccount,
    aws_access_key_id: &str,
    aws_secret_access_key: &str,
) -> AwsCredentials {
    AwsCredentials {
        access_key_id: if aws_access_key_id.is_empty() {
            tracing::warn!("AWS_ACCESS_KEY_ID not set, using default credential chain");
            String::new()
        } else {
            aws_access_key_id.to_string()
        },
        secret_access_key: if aws_secret_access_key.is_empty() {
            String::new()
        } else {
            aws_secret_access_key.to_string()
        },
        region: account.region.clone(),
    }
}

/// Print the aggregate scan summary and exit with the appropriate status code.
///
/// The process exits non-zero when critical drift was detected or when any
/// organization could not be scanned, so an incomplete run never looks green.
fn print_summary(
    org_ids: &[Uuid],
    total_resources_checked: usize,
    any_critical: bool,
    failed_scans: usize,
) {
    println!("  DRIFT DETECTION SUMMARY");
    println!("Organizations scanned: {}", org_ids.len());
    println!("Total resources checked: {total_resources_checked}");
    if failed_scans > 0 {
        println!("Organizations skipped due to errors: {failed_scans}");
    }

    if any_critical || failed_scans > 0 {
        if any_critical {
            tracing::error!("CRITICAL DRIFT DETECTED - Immediate action required");
        }
        if failed_scans > 0 {
            tracing::error!(
                "{failed_scans} organization(s) could not be scanned; the report is incomplete"
            );
        }
        std::process::exit(1);
    } else {
        println!("\n✓ Scan complete. No critical drift detected.");
        std::process::exit(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment_error_display() {
        let err = EnvironmentError::MissingDatabaseUrl(env::VarError::NotPresent);
        assert_eq!(
            err.to_string(),
            "DATABASE_URL environment variable must be set"
        );
    }

    #[test]
    fn test_resolve_orgs_error_display() {
        let err = ResolveOrgsError::NoActiveOrganizations;
        assert_eq!(err.to_string(), "no active organizations found in database");
    }

    #[test]
    fn test_org_scan_error_display_no_accounts_queried() {
        let err = OrgScanError::NoAccountsQueried {
            org_id: Uuid::nil(),
        };
        assert_eq!(
            err.to_string(),
            "no provider account could be queried for organization 00000000-0000-0000-0000-000000000000"
        );
    }
}
