// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::model::{
    Page, RelatedResource, Relation, RelationSummary, Resource, ResourceKind, ResourceSummary,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Screen {
    Home,
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
    pub fn title(&self) -> String {
        match self {
            Self::Home => "Find anything".to_string(),
            Self::Search {
                query,
                kind: Some(kind),
            } => {
                let mut title = kind.plural().to_string();
                if !query.is_empty() {
                    title.push_str(" matching ");
                    title.push_str(query);
                }
                title
            }
            Self::Search { query, kind: None } => {
                let mut title = "Search: ".to_string();
                title.push_str(query);
                title
            }
            Self::Resource(resource) => resource.label.clone(),
            Self::Related { source, relation } => {
                let mut title = source.label.clone();
                title.push_str(" › ");
                title.push_str(relation.label());
                title
            }
        }
    }

    fn breadcrumb(&self) -> Option<String> {
        match self {
            Self::Home => None,
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
    Resource(ResourceSummary),
    Relation(RelationSummary),
    Related(RelatedResource),
}

impl Row {
    pub fn resource_summary(&self) -> Option<&ResourceSummary> {
        match self {
            Self::Resource(resource) => Some(resource),
            Self::Related(resource) => Some(&resource.resource),
            Self::Browse(_) | Self::Relation(_) => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub screen: Screen,
    pub rows: Vec<Row>,
    pub selected: usize,
    pub query: String,
    pub input_mode: bool,
    pub status: Option<String>,
}

impl Snapshot {
    fn home() -> Self {
        Self {
            screen: Screen::Home,
            rows: ResourceKind::ALL.into_iter().map(Row::Browse).collect(),
            selected: 0,
            query: String::new(),
            input_mode: false,
            status: None,
        }
    }
}

#[derive(Debug)]
pub struct AppState {
    pub current: Snapshot,
    history: Vec<Snapshot>,
    pub show_help: bool,
    pub should_quit: bool,
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
        self.current.query.clear();
        self.current.input_mode = false;
    }

    pub fn open_search(
        &mut self,
        query: String,
        kind: Option<ResourceKind>,
        resources: Vec<ResourceSummary>,
    ) {
        self.push(Snapshot {
            screen: Screen::Search {
                query: query.clone(),
                kind,
            },
            rows: resources.into_iter().map(Row::Resource).collect(),
            selected: 0,
            query,
            input_mode: false,
            status: None,
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
        });
    }

    pub fn open_related(
        &mut self,
        source: Resource,
        relation: Relation,
        page: Page<RelatedResource>,
    ) {
        let status = page.has_more.then(|| {
            "Showing the first 50 results; use headless commands for pagination".to_string()
        });
        self.push(Snapshot {
            screen: Screen::Related { source, relation },
            rows: page.items.into_iter().map(Row::Related).collect(),
            selected: 0,
            query: String::new(),
            input_mode: false,
            status,
        });
    }

    pub fn replace_resources(&mut self, resources: Vec<ResourceSummary>) {
        self.current.rows = resources.into_iter().map(Row::Resource).collect();
        self.current.selected = self
            .current
            .selected
            .min(self.current.rows.len().saturating_sub(1));
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

    pub fn replace_related(&mut self, page: Page<RelatedResource>) {
        self.current.rows = page.items.into_iter().map(Row::Related).collect();
        self.current.selected = self
            .current
            .selected
            .min(self.current.rows.len().saturating_sub(1));
        self.current.status = page.has_more.then(|| {
            "Showing the first 50 results; use headless commands for pagination".to_string()
        });
    }

    pub fn back(&mut self) -> bool {
        let Some(previous) = self.history.pop() else {
            return false;
        };
        self.current = previous;
        true
    }

    pub fn set_status(&mut self, status: impl Into<String>) {
        self.current.status = Some(status.into());
    }

    fn push(&mut self, next: Snapshot) {
        self.history.push(self.current.clone());
        self.current = next;
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::{AppState, Row, Screen};
    use crate::model::{
        Field, Page, RelatedResource, Relation, RelationSummary, Resource, ResourceKind,
        ResourceSummary,
    };

    fn summary(label: &str) -> ResourceSummary {
        ResourceSummary {
            kind: ResourceKind::User,
            id: Uuid::nil(),
            label: label.to_string(),
            context: None,
        }
    }

    fn resource(kind: ResourceKind, label: &str) -> Resource {
        Resource {
            kind,
            id: Uuid::nil(),
            label: label.to_string(),
            fields: vec![Field {
                label: "Status",
                value: "active".to_string(),
            }],
        }
    }

    #[test]
    fn back_restores_query_rows_and_selection() {
        let mut state = AppState::new();
        state.current.query = "alice".to_string();
        state.current.selected = 2;
        let previous = state.current.clone();

        state.open_search("alice".to_string(), None, vec![summary("alice")]);
        assert!(matches!(state.current.screen, Screen::Search { .. }));
        assert!(state.back());
        assert_eq!(state.current, previous);
    }

    #[test]
    fn selection_is_clamped_at_both_ends() {
        let mut state = AppState::new();
        state.select_previous();
        assert_eq!(state.current.selected, 0);
        for _ in 0..10 {
            state.select_next();
        }
        assert_eq!(state.current.selected, 2);
    }

    #[test]
    fn query_editing_is_limited_to_input_mode() {
        let mut state = AppState::new();
        state.begin_search();
        state.insert_query_char('a');
        assert_eq!(state.current.query, "a");
        state.open_search("alice".to_string(), None, vec![summary("alice")]);
        state.insert_query_char('b');
        assert_eq!(state.current.query, "alice");
    }

    #[test]
    fn home_contains_the_three_browse_roots() {
        let state = AppState::new();
        assert_eq!(state.current.rows.len(), 3);
        assert!(
            state
                .current
                .rows
                .iter()
                .all(|row| matches!(row, Row::Browse(_)))
        );
    }

    #[test]
    fn breadcrumbs_follow_the_opened_relationship_path_and_back() {
        let mut state = AppState::new();
        let user = resource(ResourceKind::User, "alice");
        let app = resource(ResourceKind::App, "api");

        state.open_search("alice".to_string(), None, vec![user.summary()]);
        state.open_resource(
            user.clone(),
            vec![RelationSummary {
                relation: Relation::UserApps,
                count: 1,
            }],
        );
        state.open_related(
            user,
            Relation::UserApps,
            Page {
                items: vec![RelatedResource {
                    resource: app.summary(),
                    role: Some("owner".to_string()),
                    via: None,
                }],
                offset: 0,
                limit: 50,
                has_more: false,
            },
        );
        state.open_resource(app, Vec::new());

        assert_eq!(
            state.breadcrumbs(),
            [
                "Search \u{201c}alice\u{201d}",
                "User alice",
                "Apps via organizations",
                "App api",
            ]
        );
        assert!(state.back());
        assert_eq!(
            state.breadcrumbs(),
            [
                "Search \u{201c}alice\u{201d}",
                "User alice",
                "Apps via organizations",
            ]
        );
    }
}
