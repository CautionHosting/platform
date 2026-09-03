// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::aws::{
    AwsAction, AwsDisplayRow, AwsFinding, AwsHost, AwsOverviewMetadata, AwsSection, AwsSnapshot,
};
use crate::model::{
    Page, RelatedResource, Relation, RelationSummary, Resource, ResourceKind, ResourceSummary,
    SortColumn,
};

mod aws;
mod loading;
mod table;

pub use loading::AwsLoadMode;
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
            (Self::Aws(left), Self::Aws(right)) => match (&left.action, &right.action) {
                (AwsAction::Section(left), AwsAction::Section(right)) => left == right,
                (AwsAction::Host(left), AwsAction::Host(right)) => left == right,
                (AwsAction::Resource(left), AwsAction::Resource(right)) => {
                    left.kind == right.kind && left.id == right.id
                }
                (AwsAction::None, AwsAction::None) => {
                    left.kind == right.kind && left.name == right.name
                }
                _ => false,
            },
            (Self::Resource(left), Self::Resource(right)) => {
                left.kind == right.kind && left.id == right.id
            }
            (Self::Related(left), Self::Related(right)) => {
                left.resource.kind == right.resource.kind && left.resource.id == right.resource.id
            }
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
    pub aws_loading: Option<AwsLoadMode>,
    pub aws_loading_frame: usize,
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
            aws_loading: None,
            aws_loading_frame: 0,
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

    pub fn replace_resources(
        &mut self,
        page: Page<ResourceSummary>,
        sort: SortColumn,
        reset_selection: bool,
    ) {
        let selected = (!reset_selection)
            .then(|| self.selected_row().cloned())
            .flatten();
        self.current.page = Some(PageState::from_page(&page));
        self.current.sort = Some(sort);
        self.current.rows = page.items.into_iter().map(Row::Resource).collect();
        self.current.selected = selected
            .as_ref()
            .and_then(|selected| {
                self.current
                    .rows
                    .iter()
                    .position(|row| row.same_identity(selected))
            })
            .unwrap_or(0);
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
        let selected = (!reset_selection)
            .then(|| self.selected_row().cloned())
            .flatten();
        self.current.page = Some(PageState::from_page(&page));
        self.current.sort = Some(sort);
        self.current.rows = page.items.into_iter().map(Row::Related).collect();
        self.current.selected = selected
            .as_ref()
            .and_then(|selected| {
                self.current
                    .rows
                    .iter()
                    .position(|row| row.same_identity(selected))
            })
            .unwrap_or(0);
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

    fn push(&mut self, next: Snapshot) {
        self.history.push(self.current.clone());
        self.current = next;
    }
}

#[cfg(test)]
mod tests;
