// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! App summaries derived from deployment rows (spec: "Derive the app summary").

use super::{LIFECYCLE_DEPLOYMENTS, max_candidates_per_app};
use dterror::{BoxError, CtxError, Location, ResultExt};
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

/// Monthly estimates use the dashboard's existing 730-hour month.
pub(crate) const HOURS_PER_MONTH: f64 = 730.0;

pub(crate) fn monthly_estimate(hourly_usd: Option<f64>) -> Option<f64> {
    hourly_usd.map(|hourly| (hourly * HOURS_PER_MONTH * 100.0).round() / 100.0)
}

/// Holds resources or a candidate slot: built/running, or cleanup unresolved.
pub(crate) fn is_retained(status: &str, cleaned_up: bool) -> bool {
    matches!(
        status,
        "reserved" | "building" | "provisioning" | "running" | "destroying"
    ) || (status == "failed" && !cleaned_up)
}

/// An instance is metered: the predicate of `lifecycle::retained_instances` (running,
/// destroying, or failed with cleanup pending, with an instance) plus the live deployment,
/// which is running. A provisioning instance is not metered until it runs. Reconciliation
/// stops the meter of a confirmed-lost instance (`runtime_lost`), whose slot stays until
/// destroyed.
pub(crate) fn bills_instance(
    status: &str,
    cleaned_up: bool,
    instance_id: Option<&str>,
    failure_kind: Option<&str>,
) -> bool {
    instance_id.is_some()
        && (matches!(status, "running" | "destroying") || (status == "failed" && !cleaned_up))
        && failure_kind != Some("runtime_lost")
}

/// Whether the resources of a terminal deployment are released: `done` or
/// `pending` for `failed` and `destroyed`, nothing for the others.
pub(crate) fn cleanup_state(status: &str, cleaned_up: bool) -> Option<&'static str> {
    matches!(status, "failed" | "destroyed").then_some(if cleaned_up { "done" } else { "pending" })
}

#[derive(Clone, Copy)]
pub(crate) struct SummaryInput<'a> {
    pub(crate) app_state: &'a str,
    pub(crate) live_status: Option<&'a str>,
    pub(crate) live_failure_kind: Option<&'a str>,
    pub(crate) attempts: i64,
    pub(crate) building: bool,
    pub(crate) provisioning: bool,
    pub(crate) cleanup_pending: bool,
    /// Running deployments with an instance that are not the live one (as
    /// `reconcile::repair_live` counts them).
    pub(crate) unselected_running: i64,
    /// `failed` or `destroyed`: the most recent terminal attempt.
    pub(crate) latest_terminal: Option<&'a str>,
}

/// The first matching rule of the spec's app summary table.
pub(crate) fn summary_state(input: &SummaryInput<'_>) -> &'static str {
    if input.app_state == "terminating" {
        return "cleanup_pending";
    }
    if let Some(status) = input.live_status {
        return match (status, input.live_failure_kind, input.app_state) {
            ("running", _, "stopped") => "stopped",
            ("running", _, _) => "running",
            ("failed", Some("runtime_lost"), _) => "unavailable",
            _ => "unknown",
        };
    }
    if input.attempts == 0 {
        return if input.app_state == "terminated" {
            "destroyed"
        } else {
            "initialized"
        };
    }
    if input.building {
        return "building";
    }
    if input.provisioning {
        return "starting";
    }
    if input.cleanup_pending {
        return "cleanup_pending";
    }
    // Mirrors `reconcile::live_repair` with nothing live: the reconciler activates exactly one
    // Running deployment within about a minute, and never guesses between several. A single
    // Running deployment whose activation hit a holder mismatch shows `starting` until an
    // operator repairs the address (message at `activation_failure_message`, `main.rs`).
    match input.unselected_running {
        0 => {}
        1 => return "starting",
        _ => return "unavailable",
    }
    match input.latest_terminal {
        Some("destroyed") => "destroyed",
        Some(_) => "failed",
        None => "initialized",
    }
}

/// Active: initialized, an ongoing attempt or retained runtime, or unresolved
/// cleanup. Terminal history alone is inactive.
pub(crate) fn is_active(summary_state: &str) -> bool {
    !matches!(summary_state, "failed" | "destroyed")
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct AppSummary {
    pub(crate) summary_state: String,
    pub(crate) active: bool,
    pub(crate) live_commit_sha: Option<String>,
    pub(crate) candidates: Option<i64>,
    pub(crate) candidate_limit: Option<i64>,
}

/// Legacy apps keep their state and any recorded commit
/// (`configuration->>'commit_sha'`); only destroyed (terminated) apps are inactive.
pub(crate) fn legacy(state: &str, commit_sha: Option<&str>) -> AppSummary {
    AppSummary {
        summary_state: state.to_string(),
        active: state != "terminated",
        live_commit_sha: commit_sha.map(str::to_string),
        candidates: None,
        candidate_limit: None,
    }
}

#[derive(sqlx::FromRow)]
struct SummaryRow {
    app_id: Uuid,
    app_state: String,
    live_status: Option<String>,
    live_failure_kind: Option<String>,
    live_commit_sha: Option<String>,
    attempts: i64,
    candidates: i64,
    building: bool,
    provisioning: bool,
    cleanup_pending: bool,
    unselected_running: i64,
    latest_terminal: Option<String>,
}

/// Failure modes for [`summaries`].
#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to summarise {app_count} deployments apps [{location}]")]
pub(crate) struct SummariesError {
    app_count: usize,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

/// Summaries of the given deployments-lifecycle apps (others are skipped).
/// `candidates` uses the same predicate as `admission::reserve`.
pub(crate) async fn summaries(
    db: &PgPool,
    app_ids: &[Uuid],
) -> Result<HashMap<Uuid, AppSummary>, SummariesError> {
    if app_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<SummaryRow> = sqlx::query_as(
        "SELECT cr.id AS app_id, cr.state::text AS app_state,
                l.status AS live_status, l.failure_kind AS live_failure_kind, l.commit_sha AS live_commit_sha,
                COUNT(d.id) AS attempts,
                COUNT(d.id) FILTER (WHERE d.id IS DISTINCT FROM cr.live_deployment_id
                    AND (d.status IN ('reserved', 'building', 'provisioning', 'running', 'destroying')
                         OR (d.status = 'failed' AND d.cleaned_up_at IS NULL))) AS candidates,
                COALESCE(BOOL_OR(d.status IN ('reserved', 'building')), false) AS building,
                COALESCE(BOOL_OR(d.status = 'provisioning'), false) AS provisioning,
                COALESCE(BOOL_OR(d.status = 'destroying'
                    OR (d.status = 'failed' AND d.cleaned_up_at IS NULL)), false) AS cleanup_pending,
                COUNT(d.id) FILTER (WHERE d.status = 'running' AND d.instance_id IS NOT NULL
                    AND d.id IS DISTINCT FROM cr.live_deployment_id) AS unselected_running,
                (SELECT t.status FROM app_deployments t
                 WHERE t.app_id = cr.id AND t.status IN ('failed', 'destroyed')
                 ORDER BY COALESCE(t.destroyed_at, t.failed_at, t.created_at) DESC LIMIT 1) AS latest_terminal
         FROM compute_resources cr
         LEFT JOIN app_deployments l ON l.id = cr.live_deployment_id
         LEFT JOIN app_deployments d ON d.app_id = cr.id
         WHERE cr.id = ANY($1) AND cr.lifecycle = $2
         GROUP BY cr.id, l.status, l.failure_kind, l.commit_sha",
    )
    .bind(app_ids)
    .bind(LIFECYCLE_DEPLOYMENTS)
    .fetch_all(db)
    .await
    .with_context(SummariesErrorCtx::new(app_ids.len()))?;
    let limit = max_candidates_per_app();
    Ok(rows
        .into_iter()
        .map(|row| {
            let state = summary_state(&SummaryInput {
                app_state: &row.app_state,
                live_status: row.live_status.as_deref(),
                live_failure_kind: row.live_failure_kind.as_deref(),
                attempts: row.attempts,
                building: row.building,
                provisioning: row.provisioning,
                cleanup_pending: row.cleanup_pending,
                unselected_running: row.unselected_running,
                latest_terminal: row.latest_terminal.as_deref(),
            });
            (
                row.app_id,
                AppSummary {
                    summary_state: state.to_string(),
                    active: is_active(state),
                    live_commit_sha: row.live_commit_sha,
                    candidates: Some(row.candidates),
                    candidate_limit: Some(limit),
                },
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_state_is_only_for_failed_and_destroyed() {
        assert_eq!(cleanup_state("failed", false), Some("pending"));
        assert_eq!(cleanup_state("failed", true), Some("done"));
        assert_eq!(cleanup_state("destroyed", false), Some("pending"));
        assert_eq!(cleanup_state("destroyed", true), Some("done"));
        for status in [
            "reserved",
            "building",
            "provisioning",
            "running",
            "destroying",
        ] {
            assert_eq!(cleanup_state(status, true), None, "{status}");
            assert_eq!(cleanup_state(status, false), None, "{status}");
        }
    }

    fn input() -> SummaryInput<'static> {
        SummaryInput {
            app_state: "initialized",
            live_status: None,
            live_failure_kind: None,
            attempts: 1,
            building: false,
            provisioning: false,
            cleanup_pending: false,
            unselected_running: 0,
            latest_terminal: None,
        }
    }

    #[test]
    fn summary_follows_the_spec_state_table_first_match_wins() {
        // A selected deployment reports its runtime; candidate activity never overwrites it.
        let live = SummaryInput {
            app_state: "running",
            live_status: Some("running"),
            building: true,
            ..input()
        };
        assert_eq!(summary_state(&live), "running");
        assert_eq!(
            summary_state(&SummaryInput {
                app_state: "stopped",
                ..live
            }),
            "stopped"
        );
        assert_eq!(
            summary_state(&SummaryInput {
                live_status: Some("failed"),
                live_failure_kind: Some("runtime_lost"),
                ..live
            }),
            "unavailable"
        );
        assert_eq!(
            summary_state(&SummaryInput {
                attempts: 0,
                ..input()
            }),
            "initialized"
        );
        assert_eq!(
            summary_state(&SummaryInput {
                attempts: 0,
                app_state: "terminated",
                ..input()
            }),
            "destroyed"
        );
        assert_eq!(
            summary_state(&SummaryInput {
                building: true,
                ..input()
            }),
            "building"
        );
        assert_eq!(
            summary_state(&SummaryInput {
                provisioning: true,
                ..input()
            }),
            "starting"
        );
        assert_eq!(
            summary_state(&SummaryInput {
                cleanup_pending: true,
                ..input()
            }),
            "cleanup_pending"
        );
        // Mirrors `reconcile::live_repair`: one Running deployment is activated within about a
        // minute; several are never guessed between.
        assert_eq!(
            summary_state(&SummaryInput {
                unselected_running: 1,
                ..input()
            }),
            "starting"
        );
        assert_eq!(
            summary_state(&SummaryInput {
                unselected_running: 2,
                ..input()
            }),
            "unavailable"
        );
        assert_eq!(
            summary_state(&SummaryInput {
                unselected_running: 1,
                building: true,
                ..input()
            }),
            "building"
        );
        assert_eq!(
            summary_state(&SummaryInput {
                latest_terminal: Some("failed"),
                ..input()
            }),
            "failed"
        );
        assert_eq!(
            summary_state(&SummaryInput {
                latest_terminal: Some("destroyed"),
                ..input()
            }),
            "destroyed"
        );
        assert_eq!(
            summary_state(&SummaryInput {
                app_state: "terminating",
                live_status: Some("running"),
                ..input()
            }),
            "cleanup_pending"
        );
    }

    #[test]
    fn terminal_history_alone_is_inactive() {
        for state in [
            "running",
            "stopped",
            "unavailable",
            "initialized",
            "building",
            "starting",
            "cleanup_pending",
        ] {
            assert!(is_active(state), "{state}");
        }
        assert!(!is_active("failed"));
        assert!(!is_active("destroyed"));
        assert!(legacy("running", None).active);
        assert!(!legacy("terminated", None).active);
        assert_eq!(legacy("running", None).candidates, None);
        assert_eq!(
            legacy("running", Some("04fa2381"))
                .live_commit_sha
                .as_deref(),
            Some("04fa2381")
        );
    }

    #[test]
    fn retained_instances_are_estimated_per_month() {
        assert_eq!(monthly_estimate(Some(0.192)), Some(140.16));
        assert_eq!(monthly_estimate(None), None);
        assert!(is_retained("running", false));
        assert!(is_retained("destroying", false));
        assert!(is_retained("failed", false), "cleanup pending stays billed");
        assert!(!is_retained("failed", true));
        assert!(!is_retained("destroyed", true));
        // Billed exactly where metering keeps a meter (`lifecycle::retained_instances`):
        // running, destroying, or failed with cleanup pending. A confirmed-lost instance
        // holds its slot but bills nothing.
        assert!(bills_instance("running", false, Some("i-a"), None));
        assert!(bills_instance("destroying", false, Some("i-a"), None));
        assert!(bills_instance(
            "failed",
            false,
            Some("i-a"),
            Some("provisioning")
        ));
        assert!(!bills_instance(
            "failed",
            false,
            Some("i-a"),
            Some("runtime_lost")
        ));
        assert!(!bills_instance(
            "failed",
            true,
            Some("i-a"),
            Some("provisioning")
        ));
        assert!(
            !bills_instance("provisioning", false, Some("i-a"), None),
            "not metered until running"
        );
        assert!(!bills_instance("running", false, None, None));
    }
}
