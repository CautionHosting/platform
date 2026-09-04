// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::{fmt, io};

use caution_admin::{
    aws::{FindingReport, FindingsReport, load_findings_report},
    db::Database,
};
use clap::Args as ClapArgs;
use dterror::{BoxError, CtxError, Location, ResultExt as _};

use crate::{print_json, terminal_safe};

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    /// Emit the complete findings report as JSON.
    #[arg(long)]
    pub(crate) json: bool,
}

pub(crate) async fn run(database: &Database, args: Args) -> Result<(), RunFindingsError> {
    use RunFindingsErrorCtx as Ctx;

    let report = load_findings_report(database)
        .await
        .with_context(Ctx::new(RunFindingsStage::Load))?;
    if args.json {
        print_json(&report).with_context(Ctx::new(RunFindingsStage::PrintJson))
    } else {
        let stdout = io::stdout();
        print_findings(&mut stdout.lock(), &report)
            .with_context(Ctx::new(RunFindingsStage::PrintHuman))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunFindingsStage {
    Load,
    PrintJson,
    PrintHuman,
}

impl fmt::Display for RunFindingsStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Load => "loading AWS findings",
            Self::PrintJson => "writing JSON output",
            Self::PrintHuman => "writing human-readable output",
        })
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("AWS findings command failed while {stage} [{location:?}]")]
pub(crate) struct RunFindingsError {
    stage: RunFindingsStage,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

fn print_findings(
    output: &mut impl io::Write,
    report: &FindingsReport,
) -> Result<(), PrintFindingsError> {
    use PrintFindingsErrorCtx as Ctx;

    writeln!(
        output,
        "AWS account: {}",
        safe_option(report.account.as_deref())
    )
    .with_context(Ctx::new("writing the account"))?;
    if let Some(principal) = &report.principal {
        writeln!(output, "Principal: {}", terminal_safe(principal))
            .with_context(Ctx::new("writing the principal"))?;
    }
    if let Some(error) = &report.identity_error {
        writeln!(output, "Identity: unavailable ({})", terminal_safe(error))
            .with_context(Ctx::new("writing the identity error"))?;
    }
    writeln!(output, "Coverage: {}", report.coverage)
        .with_context(Ctx::new("writing the coverage"))?;
    writeln!(
        output,
        "Coverage details: {}",
        terminal_safe(&report.coverage_details)
    )
    .with_context(Ctx::new("writing the coverage details"))?;
    writeln!(output, "Updated: {}", terminal_safe(&report.updated_at))
        .with_context(Ctx::new("writing the update time"))?;
    writeln!(output, "Findings: {}", finding_count(report))
        .with_context(Ctx::new("writing the finding count"))?;

    if report.findings.is_empty() {
        writeln!(output, "{}", empty_result(report.coverage))
            .with_context(Ctx::new("writing the empty result"))?;
        return Ok(());
    }

    for finding in &report.findings {
        print_finding(output, finding).with_context(Ctx::new("writing a finding"))?;
    }
    Ok(())
}

fn finding_count(report: &FindingsReport) -> String {
    match report.coverage {
        caution_admin::aws::FindingsCoverage::Complete => report.findings.len().to_string(),
        caution_admin::aws::FindingsCoverage::Partial => {
            format!("{}+ confirmed", report.findings.len())
        }
        caution_admin::aws::FindingsCoverage::Unavailable if report.findings.is_empty() => {
            "unavailable".to_string()
        }
        caution_admin::aws::FindingsCoverage::Unavailable => {
            format!("{} confirmed · EC2 unavailable", report.findings.len())
        }
    }
}

fn empty_result(coverage: caution_admin::aws::FindingsCoverage) -> &'static str {
    match coverage {
        caution_admin::aws::FindingsCoverage::Complete => "No findings",
        caution_admin::aws::FindingsCoverage::Partial => "No confirmed findings in scanned regions",
        caution_admin::aws::FindingsCoverage::Unavailable => "No regional instance scan succeeded",
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("AWS findings output failed while {operation} [{location:?}]")]
struct PrintFindingsError {
    operation: &'static str,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

fn print_finding(
    output: &mut impl io::Write,
    finding: &FindingReport,
) -> Result<(), PrintFindingError> {
    use PrintFindingErrorCtx as Ctx;

    writeln!(output).with_context(Ctx::new("separating findings"))?;
    writeln!(
        output,
        "{}  {}  {}",
        finding.severity,
        terminal_safe(&finding.issue),
        terminal_safe(&finding.subject)
    )
    .with_context(Ctx::new("writing the heading"))?;
    writeln!(output, "  Kind: {}", terminal_safe(&finding.kind))
        .with_context(Ctx::new("writing the finding kind"))?;
    writeln!(
        output,
        "  Platform expected: {}",
        terminal_safe(&finding.platform_expected)
    )
    .with_context(Ctx::new("writing the Platform expectation"))?;
    writeln!(
        output,
        "  AWS observed: {}",
        terminal_safe(&finding.aws_observed)
    )
    .with_context(Ctx::new("writing the AWS observation"))?;
    if let Some(scope) = &finding.scope {
        writeln!(output, "  Scope: {}", terminal_safe(scope))
            .with_context(Ctx::new("writing the scope"))?;
    }
    if let Some(host_id) = &finding.host_id {
        writeln!(output, "  Host: {}", terminal_safe(host_id))
            .with_context(Ctx::new("writing the host"))?;
    }
    for resource in &finding.linked_resources {
        writeln!(
            output,
            "  Linked resource: {} {} {}{}",
            resource.kind,
            resource.id,
            terminal_safe(&resource.label),
            resource
                .context
                .as_deref()
                .map(|context| format!(" · {}", terminal_safe(context)))
                .unwrap_or_default()
        )
        .with_context(Ctx::new("writing a linked resource"))?;
    }
    writeln!(output, "  Next step: {}", terminal_safe(&finding.next_step))
        .with_context(Ctx::new("writing the next step"))?;
    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("AWS finding output failed while {operation} [{location:?}]")]
struct PrintFindingError {
    operation: &'static str,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

fn safe_option(value: Option<&str>) -> String {
    value.map_or_else(|| "unavailable".to_string(), terminal_safe)
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use caution_admin::aws::{FindingSeverity, FindingsCoverage};
    use clap::Parser as _;

    use super::*;
    use crate::{Cli, Command};

    struct FailingWriter;

    impl io::Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("stdout failed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn report(findings: Vec<FindingReport>) -> FindingsReport {
        FindingsReport {
            account: Some("123456789012".into()),
            principal: Some("admin".into()),
            identity_error: None,
            coverage: FindingsCoverage::Complete,
            coverage_details: "17 scanned".into(),
            updated_at: "2026-09-03T12:00:00Z".into(),
            findings,
        }
    }

    fn report_with_coverage(
        coverage: FindingsCoverage,
        findings: Vec<FindingReport>,
    ) -> FindingsReport {
        FindingsReport {
            coverage,
            ..report(findings)
        }
    }

    fn finding(subject: &str) -> FindingReport {
        FindingReport {
            severity: FindingSeverity::Critical,
            kind: "expected_host_absent".into(),
            issue: "App expects EC2; none observed".into(),
            subject: subject.into(),
            platform_expected: "running app".into(),
            aws_observed: "EC2 not observed".into(),
            scope: None,
            host_id: Some("i-123".into()),
            linked_resources: Vec::new(),
            next_step: "Verify it.".into(),
        }
    }

    #[test]
    fn human_output_prints_every_finding_and_escapes_controls() {
        let mut output = Vec::new();
        print_findings(
            &mut output,
            &report(vec![finding("first\napp"), finding("second\u{202e}app")]),
        )
        .expect("print findings");
        let output = String::from_utf8(output).expect("UTF-8 output");
        assert_eq!(output.matches("App expects EC2; none observed").count(), 2);
        assert!(output.contains("first\\napp"));
        assert!(output.contains("second\\u{202e}app"));
    }

    #[test]
    fn human_output_calls_out_an_empty_report() {
        let mut output = Vec::new();
        print_findings(&mut output, &report(Vec::new())).expect("print findings");
        assert!(
            String::from_utf8(output)
                .unwrap()
                .ends_with("No findings\n")
        );
    }

    #[test]
    fn human_output_does_not_present_incomplete_scans_as_clean() {
        for (coverage, count, message) in [
            (
                FindingsCoverage::Partial,
                "Findings: 0+ confirmed",
                "No confirmed findings in scanned regions",
            ),
            (
                FindingsCoverage::Unavailable,
                "Findings: unavailable",
                "No regional instance scan succeeded",
            ),
        ] {
            let mut output = Vec::new();
            print_findings(&mut output, &report_with_coverage(coverage, Vec::new()))
                .expect("print findings");
            let output = String::from_utf8(output).unwrap();
            assert!(output.contains(count));
            assert!(output.ends_with(&format!("{message}\n")));
            assert!(!output.ends_with("No findings\n"));
        }
    }

    #[test]
    fn human_output_retains_findings_when_ec2_is_unavailable() {
        let mut output = Vec::new();
        print_findings(
            &mut output,
            &report_with_coverage(FindingsCoverage::Unavailable, vec![finding("demo")]),
        )
        .expect("print findings");
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Findings: 1 confirmed · EC2 unavailable"));
        assert!(output.contains("App expects EC2; none observed"));
    }

    #[test]
    fn human_output_preserves_the_writer_error() {
        let error =
            print_findings(&mut FailingWriter, &report(Vec::new())).expect_err("output must fail");
        assert_eq!(
            error.source().map(ToString::to_string).as_deref(),
            Some("stdout failed")
        );
    }

    #[test]
    fn command_parser_accepts_json_findings() {
        let cli = Cli::try_parse_from(["caution-admin", "findings", "--json"])
            .expect("parse findings command");
        assert!(matches!(
            cli.command,
            Some(Command::Findings(args)) if args.json
        ));
    }

    #[test]
    fn command_parser_accepts_human_findings_without_pagination() {
        let cli =
            Cli::try_parse_from(["caution-admin", "findings"]).expect("parse findings command");
        assert!(matches!(
            cli.command,
            Some(Command::Findings(args)) if !args.json
        ));
        assert!(Cli::try_parse_from(["caution-admin", "findings", "--limit", "5"]).is_err());
    }
}
