// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::{env, error::Error, fmt, io, io::IsTerminal as _, io::Write as _, process::ExitCode};

use caution_admin::{
    db::Database,
    model::{RelatedResource, Relation, Resource, ResourceKind, ResourceSummary},
    tui,
};
use clap::{Parser, Subcommand};
use dterror::{BoxError, CtxError, Location, ResultExt as _};
use serde::Serialize;
use uuid::Uuid;

mod terminal;

use terminal::terminal_text as terminal_safe;

#[derive(Debug, Parser)]
#[command(
    name = "caution-admin",
    version,
    about = "Read-only Caution administration explorer (development pilot)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Launch the interactive terminal explorer.
    Browse,
    /// Search users, organizations, and apps.
    Search {
        query: String,
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long, default_value_t = 0)]
        offset: u32,
        #[arg(long)]
        json: bool,
    },
    /// List users, organizations, or apps.
    List {
        kind: ResourceKind,
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long, default_value_t = 0)]
        offset: u32,
        #[arg(long)]
        json: bool,
    },
    /// Show one user, organization, or app by UUID.
    Show {
        kind: ResourceKind,
        id: Uuid,
        #[arg(long)]
        json: bool,
    },
    /// Follow one named relationship from a resource.
    Follow {
        kind: ResourceKind,
        id: Uuid,
        relation: String,
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long, default_value_t = 0)]
        offset: u32,
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match run_admin().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report_error(&error);
            ExitCode::FAILURE
        }
    }
}

async fn run_admin() -> Result<(), RunAdminError> {
    use RunAdminErrorCtx as Ctx;

    let cli = Cli::parse();
    require_development().with_context(Ctx::new(RunAdminStage::CheckEnvironment))?;
    let database_url =
        env::var("DATABASE_URL").with_context(Ctx::new(RunAdminStage::ReadDatabaseUrl))?;
    let database = Database::connect_read_only(&database_url)
        .await
        .with_context(Ctx::new(RunAdminStage::ConnectDatabase))?;

    match cli.command {
        None | Some(Command::Browse) => {
            if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
                return Err(RunAdminError {
                    stage: RunAdminStage::RequireTty,
                    location: std::panic::Location::caller(),
                    source: None,
                });
            }
            tui::run(database, env::var("PLATFORM_GIT_SHA").ok())
                .await
                .with_context(Ctx::new(RunAdminStage::Browse))
        }
        Some(Command::Search {
            query,
            limit,
            offset,
            json,
        }) => {
            let page = database
                .search(&query, offset, limit, None)
                .await
                .with_context(Ctx::new(RunAdminStage::Search))?;
            // The JSON shape stays a bare array for compatibility, so the
            // next-page notice goes to stderr where it cannot corrupt it.
            if page.has_more {
                let stderr = io::stderr();
                print_search_warning(&mut stderr.lock(), page.offset, page.limit)
                    .with_context(Ctx::new(RunAdminStage::PrintSearchWarning))?;
            }
            if json {
                print_json(&page.items).with_context(Ctx::new(RunAdminStage::PrintJson))
            } else {
                let stdout = io::stdout();
                print_summaries(&mut stdout.lock(), &page.items)
                    .with_context(Ctx::new(RunAdminStage::PrintSummaries))
            }
        }
        Some(Command::List {
            kind,
            limit,
            offset,
            json,
        }) => {
            let page = database
                .list(kind, offset, limit, None)
                .await
                .with_context(Ctx::new(RunAdminStage::List))?;
            if json {
                print_json(&page).with_context(Ctx::new(RunAdminStage::PrintJson))
            } else {
                let stdout = io::stdout();
                print_summaries(&mut stdout.lock(), &page.items)
                    .with_context(Ctx::new(RunAdminStage::PrintSummaries))
            }
        }
        Some(Command::Show { kind, id, json }) => {
            let resource = database
                .show(caution_admin::model::ResourceRef { kind, id })
                .await
                .with_context(Ctx::new(RunAdminStage::Show))?;
            if json {
                print_json(&resource).with_context(Ctx::new(RunAdminStage::PrintJson))
            } else {
                let stdout = io::stdout();
                print_resource(&mut stdout.lock(), &resource)
                    .with_context(Ctx::new(RunAdminStage::PrintResource))
            }
        }
        Some(Command::Follow {
            kind,
            id,
            relation,
            limit,
            offset,
            json,
        }) => {
            let relation = Relation::parse(kind, &relation)
                .with_context(Ctx::new(RunAdminStage::ParseRelation))?;
            let page = database
                .follow(
                    caution_admin::model::ResourceRef { kind, id },
                    relation,
                    offset,
                    limit,
                    None,
                )
                .await
                .with_context(Ctx::new(RunAdminStage::Follow))?;
            if json {
                print_json(&page).with_context(Ctx::new(RunAdminStage::PrintJson))
            } else {
                let stdout = io::stdout();
                print_related(&mut stdout.lock(), &page.items)
                    .with_context(Ctx::new(RunAdminStage::PrintRelated))
            }
        }
    }
}

fn require_development() -> Result<(), RequireDevelopmentError> {
    use RequireDevelopmentErrorCtx as Ctx;

    let environment = env::var("ENVIRONMENT").with_context(Ctx::missing())?;
    if environment != "development" {
        return Err(RequireDevelopmentError::OutsideDevelopment {
            location: std::panic::Location::caller(),
        });
    }
    Ok(())
}

fn print_json(value: &impl Serialize) -> Result<(), PrintJsonError> {
    use PrintJsonErrorCtx as Ctx;

    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value)
        .with_context(Ctx::new(PrintJsonStage::Serialize))?;
    writeln!(output).with_context(Ctx::new(PrintJsonStage::WriteNewline))?;
    Ok(())
}

fn report_error(error: &dyn Error) {
    let stderr = io::stderr();
    let mut output = stderr.lock();
    let _ = writeln!(output, "Error: {}", terminal_safe(&error.to_string()));
    let mut source = error.source();
    while let Some(cause) = source {
        let _ = writeln!(output, "  caused by: {}", terminal_safe(&cause.to_string()));
        source = cause.source();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunAdminStage {
    CheckEnvironment,
    ReadDatabaseUrl,
    ConnectDatabase,
    RequireTty,
    Browse,
    Search,
    List,
    Show,
    ParseRelation,
    Follow,
    PrintJson,
    PrintSearchWarning,
    PrintSummaries,
    PrintResource,
    PrintRelated,
}

impl fmt::Display for RunAdminStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CheckEnvironment => "checking the environment",
            Self::ReadDatabaseUrl => "reading DATABASE_URL",
            Self::ConnectDatabase => "connecting to PostgreSQL",
            Self::RequireTty => {
                "requiring a TTY; use search, list, show, or follow for headless access"
            }
            Self::Browse => "running the terminal explorer",
            Self::Search => "searching resources",
            Self::List => "listing resources",
            Self::Show => "showing a resource",
            Self::ParseRelation => "parsing a relationship",
            Self::Follow => "following a relationship",
            Self::PrintJson => "writing JSON output",
            Self::PrintSearchWarning => "writing the search pagination notice",
            Self::PrintSummaries => "writing resource summaries",
            Self::PrintResource => "writing resource details",
            Self::PrintRelated => "writing related resources",
        })
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("caution-admin failed while {stage} [{location:?}]")]
struct RunAdminError {
    stage: RunAdminStage,
    #[location]
    location: Location,
    #[source]
    #[context(option)]
    source: Option<BoxError>,
}

#[derive(Debug, thiserror::Error, CtxError)]
enum RequireDevelopmentError {
    #[error("ENVIRONMENT must be set to development [{location:?}]")]
    Missing {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error(
        "caution-admin is a development pilot and refuses to run outside development [{location:?}]"
    )]
    OutsideDevelopment {
        #[location]
        location: Location,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrintJsonStage {
    Serialize,
    WriteNewline,
}

impl fmt::Display for PrintJsonStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Serialize => "serializing the value",
            Self::WriteNewline => "finishing the output",
        })
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("JSON output failed while {stage} [{location:?}]")]
struct PrintJsonError {
    stage: PrintJsonStage,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("resource summary output failed while {operation} [{location:?}]")]
struct PrintSummariesError {
    operation: &'static str,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("resource detail output failed while {operation} [{location:?}]")]
struct PrintResourceError {
    operation: &'static str,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("related resource output failed while {operation} [{location:?}]")]
struct PrintRelatedError {
    operation: &'static str,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("search warning output failed while {operation} [{location:?}]")]
struct PrintSearchWarningError {
    operation: &'static str,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

fn print_search_warning(
    output: &mut (impl io::Write + ?Sized),
    offset: u32,
    limit: u32,
) -> Result<(), PrintSearchWarningError> {
    use PrintSearchWarningErrorCtx as Ctx;

    writeln!(
        output,
        "more matches available; rerun with --offset {} --limit {limit}",
        offset.saturating_add(limit)
    )
    .with_context(Ctx::new("writing stderr"))
}

fn print_summaries(
    output: &mut (impl io::Write + ?Sized),
    resources: &[ResourceSummary],
) -> Result<(), PrintSummariesError> {
    use PrintSummariesErrorCtx as Ctx;

    writeln!(output, "TYPE\tID\tNAME\tDETAILS")
        .with_context(Ctx::new("writing the table header"))?;
    for resource in resources {
        writeln!(
            output,
            "{}\t{}\t{}\t{}",
            resource.kind,
            resource.id,
            terminal_safe(&resource.label),
            terminal_safe(resource.context.as_deref().unwrap_or(""))
        )
        .with_context(Ctx::new("writing a resource row"))?;
    }
    Ok(())
}

fn print_resource(
    output: &mut (impl io::Write + ?Sized),
    resource: &Resource,
) -> Result<(), PrintResourceError> {
    use PrintResourceErrorCtx as Ctx;

    writeln!(output, "{}\t{}", resource.kind, resource.id)
        .with_context(Ctx::new("writing the resource header"))?;
    for field in &resource.fields {
        writeln!(
            output,
            "{}\t{}",
            terminal_safe(field.label),
            terminal_safe(&field.value)
        )
        .with_context(Ctx::new("writing a resource field"))?;
    }
    Ok(())
}

fn print_related(
    output: &mut (impl io::Write + ?Sized),
    resources: &[RelatedResource],
) -> Result<(), PrintRelatedError> {
    use PrintRelatedErrorCtx as Ctx;

    writeln!(output, "TYPE\tID\tNAME\tDETAILS\tROLE\tVIA")
        .with_context(Ctx::new("writing the table header"))?;
    for related in resources {
        writeln!(
            output,
            "{}\t{}\t{}\t{}\t{}\t{}",
            related.resource.kind,
            related.resource.id,
            terminal_safe(&related.resource.label),
            terminal_safe(related.resource.context.as_deref().unwrap_or("")),
            terminal_safe(related.role.as_deref().unwrap_or("")),
            related
                .via
                .as_ref()
                .map(|resource| resource.label.as_str())
                .map(terminal_safe)
                .unwrap_or_default()
        )
        .with_context(Ctx::new("writing a related resource row"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{error::Error as _, io};

    use caution_admin::{
        db::{SearchError, SearchErrorCtx},
        model::{Resource, ResourceKind},
    };
    use clap::Parser as _;
    use dterror::ResultExt as _;

    use super::{
        Cli, Command, PrintRelatedError, PrintResourceError, PrintSummariesError, RunAdminError,
        RunAdminErrorCtx, RunAdminStage, print_related, print_resource, print_search_warning,
        print_summaries,
    };

    struct FailingWriter;

    impl io::Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("stdout failed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn no_arguments_selects_the_tui() {
        let cli = Cli::try_parse_from(["caution-admin"]).expect("parse no arguments");
        assert!(cli.command.is_none());
    }

    #[test]
    fn parses_headless_follow_command() {
        let cli = Cli::try_parse_from([
            "caution-admin",
            "follow",
            "user",
            "00000000-0000-0000-0000-000000000000",
            "apps",
            "--json",
        ])
        .expect("parse follow command");
        assert!(matches!(
            cli.command,
            Some(Command::Follow { json: true, .. })
        ));
    }

    #[test]
    fn typed_errors_preserve_the_source_chain() {
        let search_error: SearchError = Err::<(), _>(io::Error::other("query failed"))
            .with_context(SearchErrorCtx::new("querying PostgreSQL"))
            .expect_err("search must fail");
        let error: RunAdminError = Err::<(), _>(search_error)
            .with_context(RunAdminErrorCtx::new(RunAdminStage::Search))
            .expect_err("admin command must fail");

        let search_source = error.source().expect("search source");
        let message = search_source.to_string();
        assert!(message.starts_with("resource search failed while querying PostgreSQL ["));
        assert!(message.contains("src/caution-admin/src/main.rs"));
        assert_eq!(
            search_source.source().map(ToString::to_string).as_deref(),
            Some("query failed")
        );
    }

    #[test]
    fn human_output_functions_have_distinct_typed_errors() {
        let summary_error: PrintSummariesError =
            print_summaries(&mut FailingWriter, &[]).expect_err("summary output must fail");
        let resource_error: PrintResourceError = print_resource(
            &mut FailingWriter,
            &Resource {
                kind: ResourceKind::User,
                id: uuid::Uuid::nil(),
                label: "alice".to_string(),
                fields: Vec::new(),
            },
        )
        .expect_err("resource output must fail");
        let related_error: PrintRelatedError =
            print_related(&mut FailingWriter, &[]).expect_err("related output must fail");
        let warning_error =
            print_search_warning(&mut FailingWriter, 0, 50).expect_err("warning output must fail");

        for error in [
            summary_error.source(),
            resource_error.source(),
            related_error.source(),
        ] {
            assert_eq!(
                error.map(ToString::to_string).as_deref(),
                Some("stdout failed")
            );
        }
        assert_eq!(
            warning_error.source().map(ToString::to_string).as_deref(),
            Some("stdout failed")
        );
    }

    #[test]
    fn human_output_escapes_controls_but_preserves_unicode() {
        let mut output = Vec::new();
        print_summaries(
            &mut output,
            &[caution_admin::model::ResourceSummary {
                kind: ResourceKind::User,
                id: uuid::Uuid::nil(),
                label: "Alice 日本語\u{1b}[31m\u{202e}spoof".to_string(),
                context: Some("active\nadmin".to_string()),
            }],
        )
        .expect("summary output");
        let output = String::from_utf8(output).expect("UTF-8 output");
        assert!(output.contains("Alice 日本語\\u{1b}[31m\\u{202e}spoof"));
        assert!(output.contains("active\\nadmin"));
    }
}
