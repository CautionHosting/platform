// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::error::Error;

use chrono::{DateTime, Utc};
use dterror::{FromContext, ResultExt as _};
use sqlx::FromRow;
use uuid::Uuid;

use crate::model::{Field, Resource, ResourceKind, ResourceSummary, timestamp};

#[derive(Debug, thiserror::Error, FromContext)]
#[error("failed to decode database resource kind `{kind}`")]
pub(super) struct SummaryRowError {
    #[context(borrow = str)]
    kind: String,
    #[source]
    source: Box<dyn Error + Send + Sync + 'static>,
}

#[derive(FromRow)]
pub(super) struct SummaryRow {
    kind: String,
    id: Uuid,
    label: String,
    context: Option<String>,
}

impl TryFrom<SummaryRow> for ResourceSummary {
    type Error = SummaryRowError;

    fn try_from(row: SummaryRow) -> Result<Self, Self::Error> {
        use SummaryRowErrorCtx as Ctx;

        let kind = row.kind.parse().with_context(Ctx::new(&row.kind))?;
        Ok(Self {
            kind,
            id: row.id,
            label: row.label,
            context: row.context,
        })
    }
}

#[derive(FromRow)]
pub(super) struct UserRow {
    id: Uuid,
    username: String,
    email: Option<String>,
    is_active: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl UserRow {
    pub(super) fn into_resource(self) -> Resource {
        Resource {
            kind: ResourceKind::User,
            id: self.id,
            label: self.username.clone(),
            fields: vec![
                Field {
                    label: "Username",
                    value: self.username,
                },
                Field {
                    label: "Email",
                    value: optional(self.email),
                },
                Field {
                    label: "Status",
                    value: status(self.is_active),
                },
                Field {
                    label: "Created",
                    value: timestamp(self.created_at),
                },
                Field {
                    label: "Updated",
                    value: timestamp(self.updated_at),
                },
            ],
        }
    }
}

#[derive(FromRow)]
pub(super) struct OrganizationRow {
    id: Uuid,
    name: String,
    is_active: bool,
    credit_suspended_at: Option<DateTime<Utc>>,
    dunning_stage: String,
    credit_balance_cents: i64,
    subscription_tier: Option<String>,
    subscription_status: Option<String>,
    billing_source: Option<String>,
    subscription_max_apps: Option<i32>,
    pending_tier: Option<String>,
    pending_max_apps: Option<i32>,
    allocated_byoc_apps: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl OrganizationRow {
    pub(super) fn into_resource(self) -> Resource {
        let mut fields = vec![
            Field {
                label: "Name",
                value: self.name.clone(),
            },
            Field {
                label: "Status",
                value: status(self.is_active),
            },
            Field {
                label: "Credit balance",
                value: money(self.credit_balance_cents),
            },
            Field {
                label: "Credit state",
                value: credit_state(self.credit_suspended_at, &self.dunning_stage),
            },
            Field {
                label: "BYOC plan",
                value: self
                    .subscription_tier
                    .as_deref()
                    .map(tier_name)
                    .unwrap_or_else(|| "—".to_string()),
            },
            Field {
                label: "Subscription status",
                value: optional(self.subscription_status),
            },
            Field {
                label: "Billing source",
                value: self
                    .billing_source
                    .as_deref()
                    .map(billing_source)
                    .unwrap_or_else(|| "—".to_string()),
            },
            Field {
                label: "BYOC capacity",
                value: byoc_capacity(
                    self.allocated_byoc_apps,
                    self.subscription_max_apps,
                    self.pending_max_apps,
                ),
            },
        ];
        if self.pending_tier.is_some() || self.pending_max_apps.is_some() {
            fields.push(Field {
                label: "Pending change",
                value: pending_change(self.pending_tier.as_deref(), self.pending_max_apps),
            });
        }
        fields.extend([
            Field {
                label: "Created",
                value: timestamp(self.created_at),
            },
            Field {
                label: "Updated",
                value: timestamp(self.updated_at),
            },
        ]);

        Resource {
            kind: ResourceKind::Organization,
            id: self.id,
            label: self.name,
            fields,
        }
    }
}

#[derive(FromRow)]
pub(super) struct AppRow {
    id: Uuid,
    resource_name: Option<String>,
    state: String,
    organization_name: String,
    managed_on_prem: bool,
    provider: String,
    provider_account: String,
    resource_type: String,
    provider_resource_id: String,
    region: Option<String>,
    public_ip: Option<String>,
    domain: Option<String>,
    dns_status: String,
    dns_error: Option<String>,
    destroyed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl AppRow {
    pub(super) fn into_resource(self) -> Resource {
        let label = self
            .resource_name
            .clone()
            .unwrap_or_else(|| "(unnamed app)".to_string());
        let mut provider = self.provider.to_ascii_uppercase();
        provider.push_str(" · ");
        provider.push_str(&self.provider_account);
        provider.push_str(" · ");
        provider.push_str(&self.resource_type);
        let mut dns = self.dns_status;
        if let Some(error) = self.dns_error {
            dns.push_str(" · ");
            dns.push_str(&error);
        }
        Resource {
            kind: ResourceKind::App,
            id: self.id,
            label,
            fields: vec![
                Field {
                    label: "Name",
                    value: optional(self.resource_name),
                },
                Field {
                    label: "State",
                    value: self.state,
                },
                Field {
                    label: "Organization",
                    value: self.organization_name,
                },
                Field {
                    label: "Mode",
                    value: deployment_mode(self.managed_on_prem).to_string(),
                },
                Field {
                    label: "Provider",
                    value: provider,
                },
                Field {
                    label: "Provider resource",
                    value: self.provider_resource_id,
                },
                Field {
                    label: "Region",
                    value: optional(self.region),
                },
                Field {
                    label: "Public IP",
                    value: optional(self.public_ip),
                },
                Field {
                    label: "Domain",
                    value: optional(self.domain),
                },
                Field {
                    label: "DNS",
                    value: dns,
                },
                Field {
                    label: "Destroyed",
                    value: self
                        .destroyed_at
                        .map(timestamp)
                        .unwrap_or_else(|| "—".to_string()),
                },
                Field {
                    label: "Created",
                    value: timestamp(self.created_at),
                },
                Field {
                    label: "Updated",
                    value: timestamp(self.updated_at),
                },
            ],
        }
    }
}

fn optional(value: Option<String>) -> String {
    value.unwrap_or_else(|| "—".to_string())
}

fn status(active: bool) -> String {
    if active { "active" } else { "inactive" }.to_string()
}

fn money(cents: i64) -> String {
    let magnitude = cents.unsigned_abs();
    let mut value = String::new();
    if cents < 0 {
        value.push('-');
    }
    value.push('$');
    value.push_str(&(magnitude / 100).to_string());
    value.push('.');
    let remainder = magnitude % 100;
    if remainder < 10 {
        value.push('0');
    }
    value.push_str(&remainder.to_string());
    value
}

fn credit_state(suspended_at: Option<DateTime<Utc>>, dunning_stage: &str) -> String {
    let mut value = suspended_at.map_or_else(
        || match dunning_stage {
            "none" => "clear".to_string(),
            "suspended" => "suspended".to_string(),
            _ => "warning".to_string(),
        },
        |suspended_at| ["suspended since ", &timestamp(suspended_at)].concat(),
    );
    if dunning_stage != "none" {
        value.push_str(" · dunning ");
        value.push_str(&dunning_stage.replace('_', " "));
    }
    value
}

fn tier_name(tier: &str) -> String {
    tier.split('_')
        .map(|word| {
            let mut characters = word.chars();
            characters.next().map_or_else(String::new, |first| {
                first.to_uppercase().to_string() + characters.as_str()
            })
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn billing_source(source: &str) -> String {
    match source {
        "legacy_credits" => "Credits".to_string(),
        "paddle" => "Paddle".to_string(),
        "enterprise" => "Enterprise".to_string(),
        other => other.replace('_', " "),
    }
}

fn byoc_capacity(allocated: i64, maximum: Option<i32>, pending: Option<i32>) -> String {
    let Some(maximum) = maximum else {
        return "—".to_string();
    };
    let effective = pending.map_or(maximum, |pending| pending.min(maximum));
    let mut value = allocated.to_string();
    value.push_str(" / ");
    value.push_str(&effective.to_string());
    value.push_str(" used");
    value
}

fn pending_change(tier: Option<&str>, limit: Option<i32>) -> String {
    let mut value = tier
        .map(tier_name)
        .unwrap_or_else(|| "plan unchanged".to_string());
    if let Some(limit) = limit {
        value.push_str(" · ");
        value.push_str(&limit.to_string());
        value.push_str(" apps");
    }
    value
}

const fn deployment_mode(managed_on_prem: bool) -> &'static str {
    if managed_on_prem {
        "BYOC"
    } else {
        "Fully managed"
    }
}

#[cfg(test)]
mod tests {
    use super::{byoc_capacity, credit_state, deployment_mode, money, tier_name};

    #[test]
    fn billing_and_mode_summaries_use_operator_terms() {
        assert_eq!(money(8_000), "$80.00");
        assert_eq!(money(-125), "-$1.25");
        assert_eq!(tier_name("3_enclaves"), "3 Enclaves");
        assert_eq!(byoc_capacity(1, Some(3), Some(2)), "1 / 2 used");
        assert_eq!(byoc_capacity(0, None, None), "—");
        assert_eq!(deployment_mode(true), "BYOC");
        assert_eq!(deployment_mode(false), "Fully managed");
        assert_eq!(credit_state(None, "none"), "clear");
        assert_eq!(
            credit_state(None, "warning_sent"),
            "warning · dunning warning sent"
        );
        assert_eq!(
            credit_state(None, "suspended"),
            "suspended · dunning suspended"
        );
    }
}
