// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::cmp::Ordering;

use drift_detector::drift::DriftSeverity;

use super::{Row, Screen, Snapshot};
use crate::{
    aws::AwsSection,
    model::{Page, SortColumn},
};

const RESOURCE_SORTS: &[SortColumn] = &[SortColumn::Details, SortColumn::Name, SortColumn::Type];
const TYPED_RESOURCE_SORTS: &[SortColumn] = &[SortColumn::Details, SortColumn::Name];
const FINDING_SORTS: &[SortColumn] = &[SortColumn::Type, SortColumn::Name, SortColumn::Details];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageState {
    pub offset: u32,
    pub limit: u32,
    pub item_count: u32,
    pub has_more: bool,
}

impl PageState {
    pub fn from_page<T>(page: &Page<T>) -> Self {
        Self {
            offset: page.offset,
            limit: page.limit,
            item_count: u32::try_from(page.items.len()).unwrap_or(u32::MAX),
            has_more: page.has_more,
        }
    }

    pub const fn page_number(self) -> u32 {
        self.offset / self.limit + 1
    }

    pub const fn first_row(self) -> u32 {
        if self.item_count == 0 {
            0
        } else {
            self.offset + 1
        }
    }

    pub const fn last_row(self) -> u32 {
        self.offset + self.item_count
    }

    pub const fn has_previous(self) -> bool {
        self.offset > 0
    }
}

impl Snapshot {
    pub fn sort_columns(&self) -> &'static [SortColumn] {
        match self.screen {
            Screen::Search { kind: None, .. } => RESOURCE_SORTS,
            Screen::Apps { .. } | Screen::Search { kind: Some(_), .. } | Screen::Related { .. } => {
                TYPED_RESOURCE_SORTS
            }
            Screen::AwsSection(AwsSection::Findings) => FINDING_SORTS,
            Screen::AwsSection(AwsSection::Storage) => RESOURCE_SORTS,
            Screen::AwsSection(AwsSection::AppHosts | AwsSection::Builders | AwsSection::Byoc) => {
                TYPED_RESOURCE_SORTS
            }
            _ => &[],
        }
    }

    pub fn next_sort(&self) -> Option<SortColumn> {
        let columns = self.sort_columns();
        let current = self.sort?;
        let index = columns.iter().position(|column| *column == current)?;
        Some(columns[(index + 1) % columns.len()])
    }

    pub fn sort_rows(&mut self, column: SortColumn) {
        let selected = self.rows.get(self.selected).cloned();
        self.rows
            .sort_by(|left, right| compare_rows(left, right, column));
        self.sort = Some(column);
        self.selected = selected
            .as_ref()
            .and_then(|selected| self.rows.iter().position(|row| row.same_identity(selected)))
            .unwrap_or(0);
    }
}

fn compare_rows(left: &Row, right: &Row, column: SortColumn) -> Ordering {
    let primary = match column {
        SortColumn::Type => compare_types(left, right),
        SortColumn::Name => row_name(left).cmp(&row_name(right)),
        SortColumn::Details => status_rank(&row_details(left))
            .cmp(&status_rank(&row_details(right)))
            .then_with(|| row_details(left).cmp(&row_details(right))),
    };
    primary
        .then_with(|| row_name(left).cmp(&row_name(right)))
        .then_with(|| row_type(left).cmp(&row_type(right)))
}

fn compare_types(left: &Row, right: &Row) -> Ordering {
    match (left, right) {
        (Row::AwsFinding(left), Row::AwsFinding(right)) => finding_rank(left.severity)
            .cmp(&finding_rank(right.severity))
            .then_with(|| left.kind.label().cmp(right.kind.label())),
        _ => row_type(left).cmp(&row_type(right)),
    }
}

const fn finding_rank(severity: DriftSeverity) -> u8 {
    match severity {
        DriftSeverity::Critical => 0,
        DriftSeverity::Warning => 1,
        DriftSeverity::Info => 2,
    }
}

fn row_type(row: &Row) -> String {
    match row {
        Row::Aws(row) => row.kind.to_ascii_lowercase(),
        Row::AwsFinding(finding) => finding.severity.to_string().to_ascii_lowercase(),
        Row::AwsHost(_) => "host".to_string(),
        Row::Build(_) => "build".to_string(),
        Row::BuildHistory(_) => "destination".to_string(),
        Row::Resource(resource) => resource.kind.singular().to_string(),
        Row::Related(related) => related.resource.kind.singular().to_string(),
        Row::Relation(_) => "relationship".to_string(),
        Row::Browse(kind) => kind.singular().to_string(),
        Row::AwsRoot => "aws".to_string(),
    }
}

fn row_name(row: &Row) -> String {
    match row {
        Row::Aws(row) => row.name.to_ascii_lowercase(),
        Row::AwsFinding(finding) => finding.kind.label().to_ascii_lowercase(),
        Row::AwsHost(host) => host.instance.instance_id.to_ascii_lowercase(),
        Row::Build(build) => build.commit_sha.to_ascii_lowercase(),
        Row::BuildHistory(_) => "build history".to_string(),
        Row::Resource(resource) => resource.label.to_ascii_lowercase(),
        Row::Related(related) => related.resource.label.to_ascii_lowercase(),
        Row::Relation(relation) => relation.relation.label().to_ascii_lowercase(),
        Row::Browse(kind) => kind.plural().to_ascii_lowercase(),
        Row::AwsRoot => "aws".to_string(),
    }
}

fn row_details(row: &Row) -> String {
    match row {
        Row::Aws(row) => row.details.to_ascii_lowercase(),
        Row::AwsFinding(finding) => finding.subject.to_ascii_lowercase(),
        Row::AwsHost(host) => host.instance.state.to_ascii_lowercase(),
        Row::Build(build) => build.status.to_ascii_lowercase(),
        Row::BuildHistory(_) => String::new(),
        Row::Resource(resource) => resource
            .context
            .clone()
            .unwrap_or_default()
            .to_ascii_lowercase(),
        Row::Related(related) => related
            .resource
            .context
            .clone()
            .unwrap_or_default()
            .to_ascii_lowercase(),
        Row::Relation(relation) => relation.count.to_string(),
        Row::Browse(_) | Row::AwsRoot => String::new(),
    }
}

fn status_rank(details: &str) -> u8 {
    match details
        .split(|character: char| character.is_whitespace() || character == '·')
        .next()
        .unwrap_or("")
    {
        "active" | "running" | "ready" | "validated" | "clear" | "complete" => 0,
        "pending" | "initialized" | "trialing" | "reserved" | "publishing" | "withdrawing" => 1,
        "stopped" | "paused" => 2,
        "terminating" | "past_due" | "warning" | "reminder" | "partial" | "stale" => 3,
        "failed" | "critical" | "invalid" | "suspended" => 4,
        "terminated" | "canceled" | "inactive" => 5,
        _ => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::status_rank;

    #[test]
    fn status_ranking_covers_the_rendered_status_vocabulary() {
        for status in ["validated", "clear"] {
            assert_eq!(status_rank(status), 0);
        }
        for status in ["reserved", "publishing", "withdrawing"] {
            assert_eq!(status_rank(status), 1);
        }
        for status in ["past_due", "reminder"] {
            assert_eq!(status_rank(status), 3);
        }
    }
}
