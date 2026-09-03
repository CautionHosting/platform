// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::aws::{
    AwsDisplayRow, AwsFinding, AwsHost, AwsOverviewMetadata, AwsSection, AwsSnapshot,
    is_cost_summary,
};
use crate::model::{
    Page, RelatedResource, Relation, RelationSummary, Resource, ResourceKind, ResourceSummary,
    SortColumn,
};

mod table;

pub use table::PageState;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Screen {
    Home,
    AwsOverview(AwsOverviewMetadata),
    AwsSection(AwsSection),
    AwsFinding(AwsFinding),
    AwsHost(Box<AwsHost>),
    Search {
        query: String,
        kind: Option<ResourceKind>,
    },
    Resource(Resource),
    Related {
        source: Resource,
        relation: Relation,
    },
}

impl Screen {
    fn breadcrumb(&self) -> Option<String> {
        match self {
            Self::Home => None,
            Self::AwsOverview(_) => Some("AWS".to_string()),
            Self::AwsSection(section) => Some(section.label().to_string()),
            Self::AwsFinding(finding) => Some(finding.kind.label().to_string()),
            Self::AwsHost(host) => Some(format!("Host {}", host.instance.instance_id)),
            Self::Search {
                query,
                kind: Some(kind),
            } if query.is_empty() => Some(["Browse ", kind.plural()].concat()),
            Self::Search { query, .. } => Some(["Search \u{201c}", query, "\u{201d}"].concat()),
            Self::Resource(resource) => {
                let kind = match resource.kind {
                    ResourceKind::User => "User",
                    ResourceKind::Organization => "Organization",
                    ResourceKind::App => "App",
                };
                Some([kind, " ", &resource.label].concat())
            }
            Self::Related { relation, .. } => Some(relation.label().to_string()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Row {
    Browse(ResourceKind),
    AwsRoot,
    Aws(AwsDisplayRow),
    AwsFinding(AwsFinding),
    AwsHost(Box<AwsHost>),
    Resource(ResourceSummary),
    Relation(RelationSummary),
    Related(RelatedResource),
}

impl Row {
    fn same_identity(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::AwsFinding(left), Self::AwsFinding(right)) => left.key() == right.key(),
            _ => self == other,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusLevel {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusMessage {
    pub level: StatusLevel,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub screen: Screen,
    pub rows: Vec<Row>,
    pub selected: usize,
    pub query: String,
    pub input_mode: bool,
    pub status: Option<StatusMessage>,
    pub page: Option<PageState>,
    pub sort: Option<SortColumn>,
}

impl Snapshot {
    fn home() -> Self {
        let mut rows = ResourceKind::ALL
            .into_iter()
            .map(Row::Browse)
            .collect::<Vec<_>>();
        rows.push(Row::AwsRoot);
        Self {
            screen: Screen::Home,
            rows,
            selected: 0,
            query: String::new(),
            input_mode: false,
            status: None,
            page: None,
            sort: None,
        }
    }
}

#[derive(Debug)]
pub struct AppState {
    pub current: Snapshot,
    history: Vec<Snapshot>,
    pub show_help: bool,
    pub should_quit: bool,
    pub aws_cache: Option<AwsSnapshot>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        Self {
            current: Snapshot::home(),
            history: Vec::new(),
            show_help: false,
            should_quit: false,
            aws_cache: None,
        }
    }

    pub fn selected_row(&self) -> Option<&Row> {
        self.current.rows.get(self.current.selected)
    }

    pub fn breadcrumbs(&self) -> Vec<String> {
        let snapshots = self
            .history
            .iter()
            .chain(std::iter::once(&self.current))
            .collect::<Vec<_>>();
        let branch_start = snapshots
            .iter()
            .rposition(|snapshot| matches!(snapshot.screen, Screen::Home))
            .map_or(0, |index| index + 1);
        let breadcrumbs = snapshots[branch_start..]
            .iter()
            .filter_map(|snapshot| snapshot.screen.breadcrumb())
            .collect::<Vec<_>>();

        if breadcrumbs.is_empty() {
            vec!["Home".to_string()]
        } else {
            breadcrumbs
        }
    }

    pub fn select_next(&mut self) {
        if !self.current.rows.is_empty() {
            self.current.selected =
                (self.current.selected + 1).min(self.current.rows.len().saturating_sub(1));
        }
    }

    pub fn select_previous(&mut self) {
        self.current.selected = self.current.selected.saturating_sub(1);
    }

    pub fn insert_query_char(&mut self, character: char) {
        if self.current.input_mode && !character.is_control() {
            self.current.query.push(character);
        }
    }

    pub fn delete_query_char(&mut self) -> bool {
        self.current.input_mode && self.current.query.pop().is_some()
    }

    pub fn begin_search(&mut self) {
        if matches!(self.current.screen, Screen::Home) {
            self.current.query.clear();
            self.current.input_mode = true;
            self.current.status = None;
        } else {
            let mut next = Snapshot::home();
            next.input_mode = true;
            self.push(next);
        }
    }

    pub fn cancel_input(&mut self) {
        if matches!(self.current.screen, Screen::Home)
            && self.current.input_mode
            && !self.history.is_empty()
        {
            self.back();
            return;
        }
        self.current.query.clear();
        self.current.input_mode = false;
    }

    pub fn open_search(
        &mut self,
        query: String,
        kind: Option<ResourceKind>,
        page: Page<ResourceSummary>,
    ) {
        let page_state = PageState::from_page(&page);
        self.push(Snapshot {
            screen: Screen::Search {
                query: query.clone(),
                kind,
            },
            rows: page.items.into_iter().map(Row::Resource).collect(),
            selected: 0,
            query,
            input_mode: false,
            status: None,
            page: Some(page_state),
            sort: Some(SortColumn::Details),
        });
    }

    pub fn open_resource(&mut self, resource: Resource, relations: Vec<RelationSummary>) {
        self.push(Snapshot {
            screen: Screen::Resource(resource),
            rows: relations.into_iter().map(Row::Relation).collect(),
            selected: 0,
            query: String::new(),
            input_mode: false,
            status: None,
            page: None,
            sort: None,
        });
    }

    pub fn open_related(
        &mut self,
        source: Resource,
        relation: Relation,
        page: Page<RelatedResource>,
    ) {
        let page_state = PageState::from_page(&page);
        self.push(Snapshot {
            screen: Screen::Related { source, relation },
            rows: page.items.into_iter().map(Row::Related).collect(),
            selected: 0,
            query: String::new(),
            input_mode: false,
            status: None,
            page: Some(page_state),
            sort: Some(SortColumn::Details),
        });
    }

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
        let overview = matches!(&self.current.screen, Screen::AwsOverview(_));
        let selected = self.selected_row().cloned();
        self.current.status = None;
        let rows = match &self.current.screen {
            Screen::AwsOverview(_) => snapshot.overview.iter().cloned().map(Row::Aws).collect(),
            Screen::AwsSection(section) => aws_section_rows(&snapshot, *section),
            Screen::AwsFinding(current) => {
                let key = current.key();
                if let Some(finding) = snapshot
                    .findings
                    .iter()
                    .find(|finding| finding.key() == key)
                {
                    self.current.screen = Screen::AwsFinding(finding.clone());
                    finding_rows(&snapshot, finding)
                } else {
                    self.current.screen = Screen::AwsSection(AwsSection::Findings);
                    self.current.status = Some(StatusMessage {
                        level: StatusLevel::Info,
                        text: "Finding cleared by refresh".to_string(),
                    });
                    snapshot
                        .findings
                        .iter()
                        .cloned()
                        .map(Row::AwsFinding)
                        .collect()
                }
            }
            Screen::AwsHost(current) => {
                if let Some(host) = snapshot
                    .hosts
                    .iter()
                    .find(|host| host.instance.instance_id == current.instance.instance_id)
                {
                    self.current.screen = Screen::AwsHost(Box::new(host.clone()));
                    host.platform
                        .as_ref()
                        .map(|platform| vec![Row::Resource(platform.resource.clone())])
                        .unwrap_or_default()
                } else {
                    self.current.screen = Screen::AwsSection(AwsSection::AppHosts);
                    self.current.status = Some(StatusMessage {
                        level: StatusLevel::Info,
                        text: "AWS host no longer present".to_string(),
                    });
                    snapshot.app_hosts.iter().cloned().map(Row::Aws).collect()
                }
            }
            _ => Vec::new(),
        };
        if overview {
            self.current.screen = Screen::AwsOverview(snapshot.metadata.clone());
        }
        if self.current.sort.is_none() {
            self.current.sort = match self.current.screen {
                Screen::AwsSection(section) => aws_section_sort(section),
                _ => None,
            };
        }
        self.aws_cache = Some(snapshot);
        self.current.rows = rows;
        self.current.selected = selected
            .as_ref()
            .and_then(|selected| {
                self.current
                    .rows
                    .iter()
                    .position(|row| row.same_identity(selected))
            })
            .unwrap_or(0);
        if let Some(sort) = self.current.sort {
            self.current.sort_rows(sort);
        }
    }

    pub fn replace_resources(
        &mut self,
        page: Page<ResourceSummary>,
        sort: SortColumn,
        reset_selection: bool,
    ) {
        self.current.page = Some(PageState::from_page(&page));
        self.current.sort = Some(sort);
        self.current.rows = page.items.into_iter().map(Row::Resource).collect();
        self.current.selected = if reset_selection {
            0
        } else {
            self.current
                .selected
                .min(self.current.rows.len().saturating_sub(1))
        };
        self.current.status = None;
    }

    pub fn replace_resource(&mut self, resource: Resource, relations: Vec<RelationSummary>) {
        self.current.screen = Screen::Resource(resource);
        self.current.rows = relations.into_iter().map(Row::Relation).collect();
        self.current.selected = self
            .current
            .selected
            .min(self.current.rows.len().saturating_sub(1));
        self.current.status = None;
    }

    pub fn replace_related(
        &mut self,
        page: Page<RelatedResource>,
        sort: SortColumn,
        reset_selection: bool,
    ) {
        self.current.page = Some(PageState::from_page(&page));
        self.current.sort = Some(sort);
        self.current.rows = page.items.into_iter().map(Row::Related).collect();
        self.current.selected = if reset_selection {
            0
        } else {
            self.current
                .selected
                .min(self.current.rows.len().saturating_sub(1))
        };
        self.current.status = None;
    }

    pub fn back(&mut self) -> bool {
        let Some(previous) = self.history.pop() else {
            return false;
        };
        self.current = previous;
        true
    }

    pub fn set_status(&mut self, status: impl Into<String>) {
        self.set_status_level(StatusLevel::Info, status);
    }

    pub fn set_warning(&mut self, status: impl Into<String>) {
        self.set_status_level(StatusLevel::Warning, status);
    }

    pub fn set_error(&mut self, status: impl Into<String>) {
        self.set_status_level(StatusLevel::Error, status);
    }

    fn set_status_level(&mut self, level: StatusLevel, status: impl Into<String>) {
        self.current.status = Some(StatusMessage {
            level,
            text: status.into(),
        });
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

    fn push(&mut self, next: Snapshot) {
        self.history.push(self.current.clone());
        self.current = next;
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

#[cfg(test)]
mod tests;
