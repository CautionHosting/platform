// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::{AppState, Row, Screen, Snapshot, StatusLevel, StatusMessage};
use crate::{
    aws::{AwsFinding, AwsHost, AwsSection, AwsSnapshot, is_cost_summary},
    model::SortColumn,
};

impl AppState {
    pub fn open_aws_overview(&mut self, snapshot: AwsSnapshot) {
        let rows = snapshot.overview.iter().cloned().map(Row::Aws).collect();
        let metadata = snapshot.metadata.clone();
        self.aws_cache = Some(snapshot);
        self.push(Snapshot {
            screen: Screen::AwsOverview(metadata),
            rows,
            selected: 0,
            query: String::new(),
            input_mode: false,
            status: None,
            page: None,
            sort: None,
        });
    }

    pub fn open_aws_section(&mut self, section: AwsSection) {
        let rows = self
            .aws_cache
            .as_ref()
            .map_or_else(Vec::new, |snapshot| aws_section_rows(snapshot, section));
        let sort = aws_section_sort(section);
        let mut next = Snapshot {
            screen: Screen::AwsSection(section),
            rows,
            selected: 0,
            query: String::new(),
            input_mode: false,
            status: None,
            page: None,
            sort,
        };
        if let Some(sort) = sort {
            next.sort_rows(sort);
            next.selected = 0;
        }
        self.push(next);
    }

    pub fn open_aws_finding(&mut self, finding: AwsFinding) {
        let rows = self.finding_rows(&finding);
        self.push(Snapshot {
            screen: Screen::AwsFinding(finding),
            rows,
            selected: 0,
            query: String::new(),
            input_mode: false,
            status: None,
            page: None,
            sort: None,
        });
    }

    pub fn open_aws_host(&mut self, host: AwsHost) {
        let rows = host
            .platform
            .as_ref()
            .map(|platform| vec![Row::Resource(platform.resource.clone())])
            .unwrap_or_default();
        self.push(Snapshot {
            screen: Screen::AwsHost(Box::new(host)),
            rows,
            selected: 0,
            query: String::new(),
            input_mode: false,
            status: None,
            page: None,
            sort: None,
        });
    }

    pub fn aws_host(&self, instance_id: &str) -> Option<AwsHost> {
        self.aws_cache
            .as_ref()?
            .hosts
            .iter()
            .find(|host| host.instance.instance_id == instance_id)
            .cloned()
    }

    pub fn replace_aws(&mut self, snapshot: AwsSnapshot) {
        for previous in &mut self.history {
            refresh_snapshot(previous, &snapshot);
        }
        refresh_snapshot(&mut self.current, &snapshot);
        self.aws_cache = Some(snapshot);
    }

    fn finding_rows(&self, finding: &AwsFinding) -> Vec<Row> {
        self.aws_cache.as_ref().map_or_else(
            || {
                finding
                    .resources
                    .iter()
                    .cloned()
                    .map(Row::Resource)
                    .collect()
            },
            |snapshot| finding_rows(snapshot, finding),
        )
    }
}

fn refresh_snapshot(view: &mut Snapshot, snapshot: &AwsSnapshot) {
    if !matches!(
        view.screen,
        Screen::AwsOverview(_) | Screen::AwsSection(_) | Screen::AwsFinding(_) | Screen::AwsHost(_)
    ) {
        return;
    }
    let selected = view.rows.get(view.selected).cloned();
    view.status = None;
    view.rows = match view.screen.clone() {
        Screen::AwsOverview(_) => {
            view.screen = Screen::AwsOverview(snapshot.metadata.clone());
            snapshot.overview.iter().cloned().map(Row::Aws).collect()
        }
        Screen::AwsSection(section) => aws_section_rows(snapshot, section),
        Screen::AwsFinding(current) => {
            let key = current.key();
            if let Some(finding) = snapshot
                .findings
                .iter()
                .find(|finding| finding.key() == key)
            {
                view.screen = Screen::AwsFinding(finding.clone());
                finding_rows(snapshot, finding)
            } else {
                view.screen = Screen::AwsSection(AwsSection::Findings);
                view.status = Some(StatusMessage {
                    level: StatusLevel::Info,
                    text: "Finding cleared by refresh".to_string(),
                });
                aws_section_rows(snapshot, AwsSection::Findings)
            }
        }
        Screen::AwsHost(current) => {
            if let Some(host) = snapshot
                .hosts
                .iter()
                .find(|host| host.instance.instance_id == current.instance.instance_id)
            {
                view.screen = Screen::AwsHost(Box::new(host.clone()));
                host.platform
                    .as_ref()
                    .map(|platform| vec![Row::Resource(platform.resource.clone())])
                    .unwrap_or_default()
            } else {
                view.screen = Screen::AwsSection(AwsSection::AppHosts);
                view.status = Some(StatusMessage {
                    level: StatusLevel::Info,
                    text: "AWS host no longer present".to_string(),
                });
                aws_section_rows(snapshot, AwsSection::AppHosts)
            }
        }
        _ => return,
    };
    if view.sort.is_none() {
        view.sort = match view.screen {
            Screen::AwsSection(section) => aws_section_sort(section),
            _ => None,
        };
    }
    view.selected = selected
        .as_ref()
        .and_then(|selected| view.rows.iter().position(|row| row.same_identity(selected)))
        .unwrap_or(0);
    if let Some(sort) = view.sort {
        view.sort_rows(sort);
    }
}

fn aws_section_rows(snapshot: &AwsSnapshot, section: AwsSection) -> Vec<Row> {
    if section == AwsSection::Findings {
        return snapshot
            .findings
            .iter()
            .cloned()
            .map(Row::AwsFinding)
            .collect();
    }
    snapshot
        .rows(section)
        .into_iter()
        .filter(|row| section != AwsSection::Costs || !is_cost_summary(row))
        .map(Row::Aws)
        .collect()
}

const fn aws_section_sort(section: AwsSection) -> Option<SortColumn> {
    match section {
        AwsSection::Findings => Some(SortColumn::Type),
        AwsSection::AppHosts | AwsSection::Builders | AwsSection::Storage | AwsSection::Byoc => {
            Some(SortColumn::Details)
        }
        AwsSection::Costs => None,
    }
}

fn finding_rows(snapshot: &AwsSnapshot, finding: &AwsFinding) -> Vec<Row> {
    let mut rows = finding
        .host_id
        .as_deref()
        .and_then(|id| {
            snapshot
                .hosts
                .iter()
                .find(|host| host.instance.instance_id == id)
        })
        .cloned()
        .map(|host| Row::AwsHost(Box::new(host)))
        .into_iter()
        .collect::<Vec<_>>();
    rows.extend(finding.resources.iter().cloned().map(Row::Resource));
    rows
}
