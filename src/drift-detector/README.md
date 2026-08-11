<!-- SPDX-FileCopyrightText: 2026 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

# drift-detector

A library crate for detecting drift between expected resource state in the database and actual AWS resources.

## Overview

The drift detector compares what's recorded in the database (expected state) with what actually exists in AWS (actual state), identifying:

- **Missing resources**: Resources tracked in the database but not found in AWS
- **Orphaned resources**: Resources in AWS that aren't tracked in the database  
- **State mismatches**: Resources where the state differs between DB and AWS
- **Configuration drift**: Differences in IP addresses, instance types, etc.

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Database  │────▶│ Drift Logic  │◀────│    AWS EC2  │
│ (Expected)  │     │   Compare    │     │  (Actual)   │
└─────────────┘     └──────────────┘     └─────────────┘
       │                     │                    │
       ▼                     ▼                    ▼
  ProviderAccounts    DriftReport         Ec2Instance
  ComputeResources    Summary             Tags/State/IP
```

## Modules

### `db` - Database Access Layer

Reads expected state from the database:

- `get_active_organization_ids(pool)` - Fetch IDs of all active organizations
- `get_provider_accounts(pool, org_id)` - Fetch all active provider accounts for an organization
- `get_compute_resources(pool, org_id)` - Fetch all active compute resources  
- `get_compute_resource(pool, org_id, resource_id)` - Fetch a specific resource

### `aws` - AWS API Client

Queries actual state from AWS EC2:

```rust
use drift_detector::aws::{AwsCredentials, Ec2Inspector};

let creds = AwsCredentials {
    access_key_id: "...".to_string(),
    secret_access_key: "...".to_string(),
    region: "us-west-2".to_string(),
};

let inspector = Ec2Inspector::from_credentials(&creds).await;
let instances = inspector.describe_instances(&filters).await?;
```

### `drift` - Core Drift Detection Logic

Compares expected vs actual state and generates reports:

```rust
use drift_detector::db::ProviderAccount;
use drift_detector::drift::{detect_resource_drift, detect_orphaned_resources};

// Check a single resource
let drifts = detect_resource_drift(&expected_resource, Some(&aws_instance));

// Find orphaned resources within one provider account
let orphaned = detect_orphaned_resources(&db_resources, &aws_instances, &account);
```

## Usage Example

```rust
use std::collections::{HashMap, HashSet};
use drift_detector::db::{get_compute_resources, get_provider_accounts};
use drift_detector::aws::{AwsCredentials, Ec2Inspector};
use drift_detector::drift::{detect_resource_drift, detect_orphaned_resources, OrganizationDriftReport};

async fn detect_org_drift(
    pool: &sqlx::PgPool,
    org_id: uuid::Uuid,
) -> Result<OrganizationDriftReport, Box<dyn std::error::Error>> {
    // 1. Get expected state from the database (AWS accounts only)
    let accounts = get_provider_accounts(pool, org_id).await?;
    let resources = get_compute_resources(pool, org_id).await?;

    // 2. Query actual state from AWS once per provider account. Empty static
    //    credentials fall back to the default credential chain.
    let mut all_drifts = Vec::new();
    for account in &accounts {
        let creds = AwsCredentials {
            access_key_id: std::env::var("AWS_ACCESS_KEY_ID").unwrap_or_default(),
            secret_access_key: std::env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default(),
            region: account.region.clone(),
        };

        let inspector = Ec2Inspector::from_credentials(&creds).await;
        let instances = inspector.list_live_instances().await?;

        let aws_by_id: HashMap<_, _> = instances
            .iter()
            .map(|i| (i.instance_id.as_str(), i))
            .collect();

        // Compare each resource of this account against its own account's state
        for resource in resources.iter().filter(|r| r.provider_account_id == account.id) {
            let aws_instance = aws_by_id
                .get(resource.provider_resource_id.as_str())
                .copied();
            all_drifts.extend(detect_resource_drift(resource, aws_instance));
        }

        // Find instances in this account that aren't tracked in the database.
        // Orphaned instances carrying a `ResourceId` tag are cross-referenced
        // against `resources` so the report includes the matching resource's
        // name and expected state when the row still exists.
        all_drifts.extend(detect_orphaned_resources(&resources, &instances, account));
    }

    // 3. Generate report
    Ok(OrganizationDriftReport::new(org_id, accounts, all_drifts))
}
```

## Error Handling

The crate uses `thiserror` for well-typed errors. Every fallible operation returns a
distinct, context-carrying error type:

- `db::DbError` - Database query failures. Variants are named after the query and
  embed the identifiers involved, e.g. `ListComputeResources { org_id, source }`
  or `FetchComputeResource { org_id, resource_id, source }`.
- `aws::AwsError` - AWS API call failures. `DescribeInstances { region, source }`
  carries the region that was queried alongside the underlying SDK error.

The binary additionally defines small per-function error enums in `main.rs`
(`EnvironmentError`, `DatabaseConnectError`, `ResolveOrgsError`, `OrgScanError`,
`RunError`) so fatal and per-organization failures can be handled separately.

## Testing

Run tests with:

```bash
cargo test -p drift-detector
```

The crate includes comprehensive unit tests for:
- Database row parsing
- AWS instance conversion  
- Drift detection logic
- Report formatting

## Dependencies

- `sqlx` - PostgreSQL database access
- `aws-sdk-ec2` - AWS EC2 API client
- `thiserror` - Error handling
- `uuid` - Identifiers

## License

AGPL-3.0-only OR LicenseRef-Commercial
