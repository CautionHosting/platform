// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Debug endpoints that deliberately fail, used to exercise Sentry reporting.
//!
//! Nothing here is registered unless `ENABLE_TEST_ENDPOINTS` is set (see
//! [`enabled`] and the startup guard in `main`). The real purpose of
//! [`force_error_test`] is the breadcrumb trail: it walks a nested chain of
//! helpers that emit info/warn events before failing, so a Sentry event can be
//! inspected for the fields those events carried. It also raises typed internal
//! errors so the endpoint exercises the same error plumbing production handlers
//! use.

use axum::{
    Json,
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use dterror::{BoxError, CtxError, Location, ResultExt};
use uuid::Uuid;

/// Whether the debug endpoints are enabled via `ENABLE_TEST_ENDPOINTS`.
pub(crate) fn enabled() -> bool {
    std::env::var("ENABLE_TEST_ENDPOINTS")
        .map(|value| value == "true" || value == "1")
        .unwrap_or(false)
}

/// Input for [`force_error_test`].
#[derive(Debug, serde::Deserialize)]
pub(crate) struct ForceErrorTestQuery {
    /// Which synthetic stage should fail. Defaults to the deepest stage so the
    /// full breadcrumb trail is produced.
    #[serde(default)]
    fail: ForceErrorTestStage,
}

/// The synthetic pipeline stage selected by [`ForceErrorTestQuery::fail`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ForceErrorTestStage {
    Prepare,
    Validate,
    #[default]
    Dispatch,
}

/// State threaded through the [`force_error_test`] call chain.
#[derive(Debug, Clone, Copy)]
struct ForceErrorTestRun {
    /// Random per-invocation token. Surfaced in every breadcrumb and in the
    /// response error so a request can be matched to its Sentry event.
    token: Uuid,
    /// The stage that should fail, threaded through so each helper can decide
    /// whether to raise.
    fail: ForceErrorTestStage,
}

impl ForceErrorTestRun {
    fn new(fail: ForceErrorTestStage) -> Self {
        Self {
            token: Uuid::new_v4(),
            fail,
        }
    }

    /// Deterministic pseudo-random value derived from the token. Gives the
    /// breadcrumb fields varied values without a random-number dependency.
    fn salt(&self, index: usize) -> u32 {
        u32::from(self.token.as_bytes()[index % 16])
    }
}

/// Failure raised by a synthetic pipeline stage.
///
/// Source-less leaf error (plain `thiserror`) with a location, one variant per
/// stage. The helpers raise it and [`force_error_test`] boxes it into the
/// response error, so the endpoint exercises the same typed-error plumbing that
/// production handlers use.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ForceErrorTestStageError {
    #[error("synthetic prepare stage rejected the payload [{location}]")]
    Prepare { location: Location },

    #[error(
        "synthetic validate stage found no healthy replica after {attempts} attempts [{location}]"
    )]
    Validate { attempts: u32, location: Location },

    #[error("synthetic dispatch stage failed with checksum {checksum} [{location}]")]
    Dispatch { checksum: u32, location: Location },
}

/// Failure deliberately produced by [`force_error_test`], attached to the 500.
///
/// Carries the run token so a Sentry event can be matched to the request that
/// produced it, and boxes the underlying stage error as its source.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ForceErrorTestError {
    #[error("deliberate test error from the force-error endpoint (token {token}) [{location}]")]
    Stage {
        token: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for ForceErrorTestError {
    fn into_response(self) -> Response {
        sentry_middleware::error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "deliberate test error",
            self,
        )
    }
}

/// Public endpoint that always fails with a reported 5xx.
///
/// Registered only when [`enabled`] is true, and refuses to run in production
/// (see the guard in `main`). It walks a nested call chain that emits info/warn
/// events, collected by `RequestBreadcrumbLayer`, before failing at the stage
/// named by `?fail=` (default `dispatch`). Use `?fail=prepare` or
/// `?fail=validate` to exercise the shorter trails and the other internal error
/// variants.
///
/// Note: this endpoint deliberately re-records the run token in each event's
/// fields even though the top span already holds it. Breadcrumb `data` is built
/// from event fields alone, so the token must be on the event to appear in the
/// trail.
///
/// Breadcrumbs are collected for every level except debug and trace, so the
/// `error!` events (including the `err(Debug)` log from each instrumented frame)
/// appear in the trail alongside the info and warn events.
#[tracing::instrument(skip_all, err(Debug), fields(token = tracing::field::Empty))]
pub(crate) async fn force_error_test(
    Query(query): Query<ForceErrorTestQuery>,
) -> Result<Json<serde_json::Value>, ForceErrorTestError> {
    use ForceErrorTestErrorCtx as Ctx;

    let run = ForceErrorTestRun::new(query.fail);
    tracing::Span::current().record("token", tracing::field::display(run.token));

    tracing::info!(
        token = %run.token,
        stage = "start",
        fail_stage = ?run.fail,
        "force-error: starting synthetic run"
    );

    force_error_test_prepare(run).with_context(Ctx::stage(run.token))
}

/// First nested step: records the prepared payload size, then hands off.
#[tracing::instrument(skip_all, err(Debug))]
fn force_error_test_prepare(
    run: ForceErrorTestRun,
) -> Result<Json<serde_json::Value>, ForceErrorTestStageError> {
    let payload_bytes = 128 + run.salt(1);
    tracing::info!(
        token = %run.token,
        stage = "prepare",
        payload_bytes,
        "force-error: prepared synthetic payload"
    );

    if run.fail == ForceErrorTestStage::Prepare {
        return Err(ForceErrorTestStageError::Prepare {
            location: std::panic::Location::caller(),
        });
    }

    force_error_test_validate(run)
}

/// Second nested step: warns about a retry, then hands off.
#[tracing::instrument(skip_all, err(Debug))]
fn force_error_test_validate(
    run: ForceErrorTestRun,
) -> Result<Json<serde_json::Value>, ForceErrorTestStageError> {
    let attempts = 1 + run.salt(2);
    tracing::warn!(
        token = %run.token,
        stage = "validate",
        attempts,
        "force-error: validation retried a transient failure"
    );

    if run.fail == ForceErrorTestStage::Validate {
        return Err(ForceErrorTestStageError::Validate {
            attempts,
            location: std::panic::Location::caller(),
        });
    }

    force_error_test_dispatch(run)
}

/// Innermost step: logs an error event and returns the typed stage failure.
#[tracing::instrument(skip_all, err(Debug))]
fn force_error_test_dispatch(
    run: ForceErrorTestRun,
) -> Result<Json<serde_json::Value>, ForceErrorTestStageError> {
    let checksum = run.salt(3) % 4096;
    tracing::info!(
        token = %run.token,
        stage = "dispatch",
        checksum,
        "force-error: dispatching synthetic work"
    );

    // This error event is captured as a breadcrumb too; only debug and trace
    // levels are dropped by the breadcrumb layer.
    tracing::error!(
        token = %run.token,
        stage = "dispatch",
        checksum,
        "force-error: synthetic dispatch failed"
    );

    Err(ForceErrorTestStageError::Dispatch {
        checksum,
        location: std::panic::Location::caller(),
    })
}
