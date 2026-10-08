// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::process::{Command, Output};

const SUCCESS: &str = "Component startup preflight succeeded";

fn api() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_api"));
    command
        .env_clear()
        .env("ENVIRONMENT", "test")
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
        .env("AWS_CONFIG_FILE", "/dev/null")
        .env("BUILDER_AMI_ID", "ami-preflight-test")
        .env("BUILDER_SECURITY_GROUP_ID", "sg-preflight-test")
        .env("BUILDER_SUBNET_ID", "subnet-preflight-test")
        .env("BUILDER_INSTANCE_PROFILE", "preflight-test")
        .env("COMPONENT_BUILD_MODE", "source")
        .env("DATABASE_URL", "deliberately-invalid-database-url");
    command
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_component_error(output: Output, expected: &str) {
    let text = output_text(&output);
    assert!(!output.status.success(), "{text}");
    assert!(text.contains("ComponentStartup"), "{text}");
    assert!(text.contains(expected), "{text}");
    assert!(!text.contains("DatabaseConnect"), "{text}");
    assert!(!text.contains("api::provisioning"), "{text}");
    assert!(!text.contains(SUCCESS), "{text}");
}

#[test]
fn no_arguments_preserves_normal_database_startup() {
    let output = api().output().unwrap();
    let text = output_text(&output);
    assert!(!output.status.success(), "{text}");
    assert!(text.contains("DatabaseConnect"), "{text}");
    assert!(!text.contains(SUCCESS), "{text}");
}

#[test]
fn preflight_requires_normal_builder_configuration() {
    for (variable, expected) in [
        ("BUILDER_AMI_ID", "MissingAmiId"),
        ("BUILDER_SECURITY_GROUP_ID", "MissingSecurityGroupId"),
        ("BUILDER_SUBNET_ID", "MissingSubnetId"),
        ("BUILDER_INSTANCE_PROFILE", "MissingInstanceProfile"),
    ] {
        let output = api()
            .arg("--check-components")
            .env_remove(variable)
            .output()
            .unwrap();
        let text = output_text(&output);
        assert!(!output.status.success(), "{text}");
        assert!(text.contains("BuilderConfigFromEnv"), "{text}");
        assert!(text.contains(expected), "{text}");
        assert!(!text.contains("ComponentStartup"), "{text}");
        assert!(!text.contains(SUCCESS), "{text}");
    }
}

#[test]
fn prebuilt_requires_selection_in_explicit_and_default_mode() {
    for mode in [None, Some("prebuilt")] {
        let mut command = api();
        command.arg("--check-components");
        match mode {
            Some(mode) => command.env("COMPONENT_BUILD_MODE", mode),
            None => command.env_remove("COMPONENT_BUILD_MODE"),
        };
        assert_component_error(command.output().unwrap(), "MissingDigest");
    }
}

#[test]
fn invalid_prebuilt_digest_or_bucket_is_rejected() {
    for (digest, bucket, expected) in [
        ("not-a-digest".to_owned(), "preflight-test", "InvalidDigest"),
        ("a".repeat(64), "invalid/bucket", "InvalidBucket"),
    ] {
        assert_component_error(
            api()
                .arg("--check-components")
                .env("COMPONENT_BUILD_MODE", "prebuilt")
                .env("COMPONENT_SET_SHA256", digest)
                .env("COMPONENTS_S3_BUCKET", bucket)
                .output()
                .unwrap(),
            expected,
        );
    }
}

#[test]
fn invalid_mode_or_conflicting_source_selection_is_rejected() {
    for (mode, digest, expected) in [
        ("invalid", "", "InvalidMode"),
        ("source", "selected", "SourceSelectionConflict"),
    ] {
        assert_component_error(
            api()
                .arg("--check-components")
                .env("COMPONENT_BUILD_MODE", mode)
                .env("COMPONENT_SET_SHA256", digest)
                .output()
                .unwrap(),
            expected,
        );
    }
}

#[test]
fn prebuilt_load_failure_does_not_fall_back_to_success_or_database() {
    assert_component_error(
        api()
            .arg("--check-components")
            .env("COMPONENT_BUILD_MODE", "prebuilt")
            .env("COMPONENT_SET_SHA256", "a".repeat(64))
            .env("COMPONENTS_S3_BUCKET", "preflight-test")
            .env("AWS_REGION", "us-west-2")
            .env("AWS_ENDPOINT_URL", "http://127.0.0.1:9")
            .env("AWS_MAX_ATTEMPTS", "1")
            .output()
            .unwrap(),
        "load pinned set",
    );
}

#[test]
fn source_preflight_succeeds_without_database_or_provisioning() {
    let output = api().arg("--check-components").output().unwrap();
    let text = output_text(&output);
    assert!(output.status.success(), "{text}");
    assert!(text.contains(SUCCESS), "{text}");
    assert!(!text.contains("Provisioning validation"), "{text}");
    assert!(!text.contains("DatabaseConnect"), "{text}");
    assert!(!text.contains("api::provisioning"), "{text}");
}

fn assert_argument_error(output: Output) {
    let text = output_text(&output);
    assert!(!output.status.success(), "{text}");
    assert!(text.contains("InvalidArguments"), "{text}");
    assert!(!text.contains("BuilderConfigFromEnv"), "{text}");
    assert!(!text.contains("ComponentStartup"), "{text}");
    assert!(!text.contains("panicked"), "{text}");
    assert!(!text.contains(SUCCESS), "{text}");
}

#[test]
fn unknown_arguments_are_rejected_before_configuration() {
    for argument in ["--unknown", "--check-component", "serve", ""] {
        assert_argument_error(
            api()
                .env_remove("BUILDER_AMI_ID")
                .arg(argument)
                .output()
                .unwrap(),
        );
    }
}

#[test]
fn duplicate_or_extra_arguments_are_rejected_before_configuration() {
    for arguments in [
        ["--check-components", "--check-components"],
        ["--check-components", "--unknown"],
        ["--unknown", "--check-components"],
    ] {
        assert_argument_error(
            api()
                .env_remove("BUILDER_AMI_ID")
                .args(arguments)
                .output()
                .unwrap(),
        );
    }
}

#[cfg(unix)]
#[test]
fn non_utf8_argument_is_rejected_without_panicking() {
    use std::os::unix::ffi::OsStringExt;

    assert_argument_error(
        api()
            .env_remove("BUILDER_AMI_ID")
            .arg(std::ffi::OsString::from_vec(vec![0xff]))
            .output()
            .unwrap(),
    );
}
