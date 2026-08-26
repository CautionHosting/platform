// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::{env, io, io::IsTerminal as _, io::Write as _};

use anyhow::{Context as _, Result, bail};
use caution_admin::{
    db::Database,
    model::{RelatedResource, Relation, Resource, ResourceKind, ResourceSummary},
    tui,
};
use clap::{Parser, Subcommand};
use serde::Serialize;
use uuid::Uuid;

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
async fn main() -> Result<()> {
    let cli = Cli::parse();
    require_development()?;
    let database_url = env::var("DATABASE_URL").context("DATABASE_URL must be set")?;
    let database = Database::connect_read_only(&database_url).await?;

    match cli.command {
        None | Some(Command::Browse) => {
            if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
                bail!(
                    "the terminal explorer requires a TTY; use list, show, or follow for headless access"
                );
            }
            tui::run(database, env::var("PLATFORM_GIT_SHA").ok()).await
        }
        Some(Command::Search { query, json }) => {
            let resources = database.search(&query).await?;
            if json {
                print_json(&resources)
            } else {
                print_summaries(&resources);
                Ok(())
            }
        }
        Some(Command::List {
            kind,
            limit,
            offset,
            json,
        }) => {
            let page = database.list(kind, offset, limit).await?;
            if json {
                print_json(&page)
            } else {
                print_summaries(&page.items);
                Ok(())
            }
        }
        Some(Command::Show { kind, id, json }) => {
            let resource = database
                .show(caution_admin::model::ResourceRef { kind, id })
                .await?;
            if json {
                print_json(&resource)
            } else {
                print_resource(&resource);
                Ok(())
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
            let relation = Relation::parse(kind, &relation)?;
            let page = database
                .follow(
                    caution_admin::model::ResourceRef { kind, id },
                    relation,
                    offset,
                    limit,
                )
                .await?;
            if json {
                print_json(&page)
            } else {
                print_related(&page.items);
                Ok(())
            }
        }
    }
}

fn require_development() -> Result<()> {
    let environment = env::var("ENVIRONMENT").context("ENVIRONMENT must be set to development")?;
    if environment != "development" {
        bail!("caution-admin is a development pilot and refuses to run outside development");
    }
    Ok(())
}

fn print_json(value: &impl Serialize) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value)?;
    writeln!(output)?;
    Ok(())
}

fn print_summaries(resources: &[ResourceSummary]) {
    println!("TYPE\tID\tNAME\tCONTEXT");
    for resource in resources {
        println!(
            "{}\t{}\t{}\t{}",
            resource.kind,
            resource.id,
            resource.label,
            resource.context.as_deref().unwrap_or("")
        );
    }
}

fn print_resource(resource: &Resource) {
    println!("{}\t{}", resource.kind, resource.id);
    for field in &resource.fields {
        println!("{}\t{}", field.label, field.value);
    }
}

fn print_related(resources: &[RelatedResource]) {
    println!("TYPE\tID\tNAME\tCONTEXT\tROLE\tVIA");
    for related in resources {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            related.resource.kind,
            related.resource.id,
            related.resource.label,
            related.resource.context.as_deref().unwrap_or(""),
            related.role.as_deref().unwrap_or(""),
            related
                .via
                .as_ref()
                .map(|resource| resource.label.as_str())
                .unwrap_or("")
        );
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::{Cli, Command};

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
}
