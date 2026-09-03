// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::time::Duration;

use aws_sdk_costexplorer::{
    Client,
    types::{DateInterval, Granularity, GroupDefinition, GroupDefinitionType, Metric, MetricValue},
};
use chrono::{Datelike as _, NaiveDate};
use dterror::{BoxError, CtxError, Location, ResultExt as _};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const METRIC: &str = "UnblendedCost";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CostLine {
    pub name: String,
    pub amount_micros: i64,
    pub currency: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct CostSnapshot {
    pub period: Option<String>,
    pub mtd_micros: Option<i64>,
    pub forecast_micros: Option<i64>,
    pub currency: String,
    pub services: Vec<CostLine>,
    pub managed_by: Vec<CostLine>,
    pub organizations: Vec<CostLine>,
    pub issues: Vec<String>,
    pub first_day: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CostWindow {
    pub start: NaiveDate,
    pub today: NaiveDate,
    pub next_month: NaiveDate,
}

pub(crate) fn cost_window(today: NaiveDate) -> CostWindow {
    let start = NaiveDate::from_ymd_opt(today.year(), today.month(), 1).expect("valid month");
    let (year, month) = if today.month() == 12 {
        (today.year() + 1, 1)
    } else {
        (today.year(), today.month() + 1)
    };
    let next_month = NaiveDate::from_ymd_opt(year, month, 1).expect("valid next month");
    CostWindow {
        start,
        today,
        next_month,
    }
}

pub(crate) async fn fetch_costs(client: &Client, today: NaiveDate) -> CostSnapshot {
    let window = cost_window(today);
    let mut snapshot = CostSnapshot {
        period: Some(format!(
            "{} through yesterday",
            window.start.format("%Y-%m-%d")
        )),
        currency: "USD".to_string(),
        ..CostSnapshot::default()
    };
    if window.start == window.today {
        snapshot.first_day = true;
        snapshot
            .issues
            .push("month-to-date is not available on the first day of the month".to_string());
        match fetch_forecast(client, window).await {
            Ok(forecast) => snapshot.forecast_micros = Some(forecast),
            Err(error) => snapshot.issues.push(cost_issue("forecast", &error)),
        }
    } else {
        let (services, managed_by, organizations, forecast) = tokio::join!(
            fetch_service_costs(client, window),
            fetch_tag_costs(client, window, "ManagedBy"),
            fetch_tag_costs(client, window, "org_id"),
            fetch_forecast(client, window),
        );
        match services {
            Ok(lines) => {
                snapshot.mtd_micros = Some(lines.iter().map(|line| line.amount_micros).sum());
                if let Some(currency) = lines.first().map(|line| line.currency.clone()) {
                    snapshot.currency = currency;
                }
                snapshot.services = lines;
            }
            Err(error) => snapshot.issues.push(cost_issue("service costs", &error)),
        }
        match managed_by {
            Ok(lines) => snapshot.managed_by = lines,
            Err(error) => snapshot
                .issues
                .push(cost_issue("ManagedBy attribution", &error)),
        }
        match organizations {
            Ok(lines) => snapshot.organizations = lines,
            Err(error) => snapshot
                .issues
                .push(cost_issue("org_id attribution", &error)),
        }
        match forecast {
            Ok(forecast) => snapshot.forecast_micros = Some(forecast),
            Err(error) => snapshot.issues.push(cost_issue("forecast", &error)),
        }
    }
    snapshot
}

async fn fetch_service_costs(
    client: &Client,
    window: CostWindow,
) -> Result<Vec<CostLine>, FetchServiceCostsError> {
    use FetchServiceCostsErrorCtx as Ctx;

    let interval = interval(window.start, window.today)
        .with_context(Ctx::new(FetchServiceCostsStage::BuildInterval))?;
    let group = GroupDefinition::builder()
        .r#type(GroupDefinitionType::Dimension)
        .key("SERVICE")
        .build();
    let mut token = None;
    let mut lines = Vec::new();
    loop {
        let result = tokio::time::timeout(
            REQUEST_TIMEOUT,
            client
                .get_cost_and_usage()
                .time_period(interval.clone())
                .granularity(Granularity::Monthly)
                .group_by(group.clone())
                .metrics(METRIC)
                .set_next_page_token(token)
                .send(),
        )
        .await
        .with_context(Ctx::new(FetchServiceCostsStage::Request))?
        .with_context(Ctx::new(FetchServiceCostsStage::Request))?;
        for result in result.results_by_time() {
            for group in result.groups() {
                let name = group.keys().first().map_or("Unknown", String::as_str);
                if let Some(metric) = group.metrics().and_then(|metrics| metrics.get(METRIC)) {
                    lines.push(
                        cost_line(name, metric)
                            .with_context(Ctx::new(FetchServiceCostsStage::Decode))?,
                    );
                }
            }
        }
        token = result.next_page_token().map(ToString::to_string);
        if token.is_none() {
            break;
        }
    }
    combine_lines(&mut lines);
    Ok(lines)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FetchServiceCostsStage {
    BuildInterval,
    Request,
    Decode,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to load AWS service costs while {stage:?} [{location:?}]")]
struct FetchServiceCostsError {
    stage: FetchServiceCostsStage,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

async fn fetch_tag_costs(
    client: &Client,
    window: CostWindow,
    tag_key: &str,
) -> Result<Vec<CostLine>, FetchTagCostsError> {
    use FetchTagCostsErrorCtx as Ctx;

    let interval = interval(window.start, window.today)
        .with_context(Ctx::new(tag_key, FetchTagCostsStage::BuildInterval))?;
    let tag = GroupDefinition::builder()
        .r#type(GroupDefinitionType::Tag)
        .key(tag_key)
        .build();
    let mut token = None;
    let mut lines = Vec::new();
    loop {
        let result = tokio::time::timeout(
            REQUEST_TIMEOUT,
            client
                .get_cost_and_usage()
                .time_period(interval.clone())
                .granularity(Granularity::Monthly)
                .group_by(tag.clone())
                .metrics(METRIC)
                .set_next_page_token(token)
                .send(),
        )
        .await
        .with_context(Ctx::new(tag_key, FetchTagCostsStage::Request))?
        .with_context(Ctx::new(tag_key, FetchTagCostsStage::Request))?;
        for result in result.results_by_time() {
            for group in result.groups() {
                let name = attribution_name(group.keys().first().map_or("", String::as_str));
                if let Some(metric) = group.metrics().and_then(|metrics| metrics.get(METRIC)) {
                    lines.push(
                        cost_line(&name, metric)
                            .with_context(Ctx::new(tag_key, FetchTagCostsStage::Decode))?,
                    );
                }
            }
        }
        token = result.next_page_token().map(ToString::to_string);
        if token.is_none() {
            break;
        }
    }
    combine_lines(&mut lines);
    Ok(lines)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FetchTagCostsStage {
    BuildInterval,
    Request,
    Decode,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to load AWS costs attributed by {tag_key} while {stage:?} [{location:?}]")]
struct FetchTagCostsError {
    #[context(borrow = str)]
    tag_key: String,
    stage: FetchTagCostsStage,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

async fn fetch_forecast(client: &Client, window: CostWindow) -> Result<i64, FetchForecastError> {
    use FetchForecastErrorCtx as Ctx;

    let interval = interval(window.today, window.next_month)
        .with_context(Ctx::new(FetchForecastStage::BuildInterval))?;
    let output = tokio::time::timeout(
        REQUEST_TIMEOUT,
        client
            .get_cost_forecast()
            .time_period(interval)
            .metric(Metric::UnblendedCost)
            .granularity(Granularity::Monthly)
            .send(),
    )
    .await
    .with_context(Ctx::new(FetchForecastStage::Request))?
    .with_context(Ctx::new(FetchForecastStage::Request))?;
    let amount =
        output
            .total()
            .and_then(MetricValue::amount)
            .ok_or(FetchForecastError::MissingTotal {
                location: std::panic::Location::caller(),
            })?;
    parse_micros(amount).with_context(Ctx::new(FetchForecastStage::Decode))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FetchForecastStage {
    BuildInterval,
    Request,
    Decode,
}

#[derive(Debug, thiserror::Error, CtxError)]
enum FetchForecastError {
    #[error("failed to load AWS cost forecast while {stage:?} [{location:?}]")]
    Wrapped {
        stage: FetchForecastStage,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("AWS cost forecast did not include a total [{location:?}]")]
    MissingTotal {
        #[location]
        location: Location,
    },
}

impl FetchForecastErrorCtx {
    fn new(stage: FetchForecastStage) -> Self {
        Self::wrapped(stage)
    }
}

fn interval(start: NaiveDate, end: NaiveDate) -> Result<DateInterval, BuildIntervalError> {
    use BuildIntervalErrorCtx as Ctx;

    DateInterval::builder()
        .start(start.format("%Y-%m-%d").to_string())
        .end(end.format("%Y-%m-%d").to_string())
        .build()
        .with_context(Ctx::build())
}

#[derive(Debug, thiserror::Error, CtxError)]
enum BuildIntervalError {
    #[error("failed to build AWS cost date interval [{location:?}]")]
    Build {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

fn cost_line(name: &str, metric: &MetricValue) -> Result<CostLine, CostLineError> {
    use CostLineErrorCtx as Ctx;

    let amount = metric.amount().ok_or(CostLineError::MissingAmount {
        name: name.to_string(),
        location: std::panic::Location::caller(),
    })?;
    let amount_micros = parse_micros(amount).with_context(Ctx::amount(name))?;
    Ok(CostLine {
        name: name.to_string(),
        amount_micros,
        currency: metric.unit().unwrap_or("USD").to_string(),
    })
}

#[derive(Debug, thiserror::Error, CtxError)]
enum CostLineError {
    #[error("failed to decode AWS cost amount for {name} [{location:?}]")]
    Amount {
        #[context(borrow = str)]
        name: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("AWS cost amount for {name} is missing [{location:?}]")]
    MissingAmount {
        name: String,
        #[location]
        location: Location,
    },
}

fn parse_micros(amount: &str) -> Result<i64, ParseMicrosError> {
    use ParseMicrosErrorCtx as Ctx;

    let value = amount.parse::<f64>().with_context(Ctx::parse())?;
    Ok((value * 1_000_000.0).round() as i64)
}

#[derive(Debug, thiserror::Error, CtxError)]
enum ParseMicrosError {
    #[error("invalid AWS cost amount [{location:?}]")]
    Parse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

fn attribution_name(value: &str) -> String {
    let value = tag_value(value);
    if value.is_empty() {
        "Unattributed".to_string()
    } else {
        value.to_string()
    }
}

fn tag_value(value: &str) -> &str {
    value.split_once('$').map_or(value, |(_, value)| value)
}

fn combine_lines(lines: &mut Vec<CostLine>) {
    lines.sort_by(|left, right| left.name.cmp(&right.name));
    let mut combined: Vec<CostLine> = Vec::new();
    for line in lines.drain(..) {
        if let Some(previous) = combined
            .last_mut()
            .filter(|previous| previous.name == line.name)
        {
            previous.amount_micros += line.amount_micros;
        } else {
            combined.push(line);
        }
    }
    combined.sort_by_key(|line| std::cmp::Reverse(line.amount_micros));
    *lines = combined;
}

fn cost_issue(component: &str, error: &dyn std::error::Error) -> String {
    if super::inventory::error_chain_contains(error, "accessdenied") {
        format!("{component} unavailable: access denied")
    } else if error.to_string().contains("timed out") {
        format!("{component} unavailable: timed out")
    } else {
        format!("{component} unavailable: request failed")
    }
}

pub(crate) fn money(micros: i64, currency: &str) -> String {
    format!("{currency} {:.2}", micros as f64 / 1_000_000.0)
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use chrono::NaiveDate;

    use super::{
        CostLine, attribution_name, combine_lines, cost_issue, cost_window, money, parse_micros,
    };

    #[test]
    fn windows_cover_current_month_and_year_boundary() {
        let window = cost_window(NaiveDate::from_ymd_opt(2026, 12, 31).unwrap());
        assert_eq!(window.start, NaiveDate::from_ymd_opt(2026, 12, 1).unwrap());
        assert_eq!(
            window.next_month,
            NaiveDate::from_ymd_opt(2027, 1, 1).unwrap()
        );
    }

    #[test]
    fn attribution_preserves_untagged_cost() {
        assert_eq!(attribution_name("ManagedBy$"), "Unattributed");
        assert_eq!(attribution_name("ManagedBy$caution+tofu"), "caution+tofu");
    }

    #[test]
    fn repeated_cost_groups_are_combined() {
        let mut lines = vec![
            CostLine {
                name: "EC2".into(),
                amount_micros: 1_000_000,
                currency: "USD".into(),
            },
            CostLine {
                name: "EC2".into(),
                amount_micros: 2_000_000,
                currency: "USD".into(),
            },
        ];
        combine_lines(&mut lines);
        assert_eq!(lines.len(), 1);
        assert_eq!(
            money(lines[0].amount_micros, &lines[0].currency),
            "USD 3.00"
        );
    }

    #[test]
    fn invalid_costs_keep_a_typed_source_and_call_site() {
        let error = parse_micros("not-a-number").expect_err("amount must fail");
        assert!(error.to_string().starts_with("invalid AWS cost amount ["));
        assert!(
            error
                .to_string()
                .contains("src/caution-admin/src/aws/cost.rs")
        );
        assert!(error.source().is_some());
    }

    #[test]
    fn denied_cost_components_are_explicitly_unavailable() {
        let error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "AccessDenied");
        assert_eq!(
            cost_issue("forecast", &error),
            "forecast unavailable: access denied"
        );
    }
}
