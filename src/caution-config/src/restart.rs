use serde::{Deserialize, Serialize};

/// Host supervision policy; failure classification depends on the provider.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    Never,
    #[default]
    OnFailure,
    Always,
}

impl RestartPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::OnFailure => "on-failure",
            Self::Always => "always",
        }
    }
}

/// The enclave-level `restart { }` block.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RestartConfig {
    pub policy: RestartPolicy,
    pub delay_seconds: u32,
}

impl Default for RestartConfig {
    fn default() -> Self {
        Self {
            policy: RestartPolicy::OnFailure,
            delay_seconds: 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConfigurationFile;

    fn parse(block: &str) -> RestartConfig {
        let input = ["enclave \"main\" {\n", block, "\n}"].concat();
        ConfigurationFile::from_str(&input)
            .unwrap()
            .enclave
            .unwrap()["main"]
            .restart
            .unwrap_or_default()
    }

    #[test]
    fn omitted_and_partial_blocks_preserve_defaults() {
        assert_eq!(parse(""), RestartConfig::default());
        assert_eq!(parse("restart {}"), RestartConfig::default());
        assert_eq!(parse("restart { policy = \"always\" }").delay_seconds, 10);
        assert_eq!(
            parse("restart { delay_seconds = 0 }").policy,
            RestartPolicy::OnFailure
        );
    }

    #[test]
    fn policies_round_trip_and_accept_zero_delay() {
        for policy in [
            RestartPolicy::Never,
            RestartPolicy::OnFailure,
            RestartPolicy::Always,
        ] {
            let block = [
                "restart {\npolicy = \"",
                policy.as_str(),
                "\"\ndelay_seconds = 0\n}",
            ]
            .concat();
            let parsed = parse(&block);
            assert_eq!(
                parsed,
                RestartConfig {
                    policy,
                    delay_seconds: 0
                }
            );
            let json = serde_json::to_string(&parsed).unwrap();
            assert_eq!(
                serde_json::from_str::<RestartConfig>(&json).unwrap(),
                parsed
            );
        }
    }

    #[test]
    fn rejects_invalid_configuration() {
        for block in [
            "restart { policy = \"sometimes\" }",
            "restart { policy = \"no\" }",
            "restart { delay_seconds = -1 }",
            "restart { delay_seconds = 0.5 }",
            "restart { delay_seconds = 4294967296 }",
            "restart { delay_seconds = \"0\" }",
            "restart { typo = true }",
        ] {
            let input = ["enclave \"main\" {\n", block, "\n}"].concat();
            assert!(ConfigurationFile::from_str(&input).is_err(), "{block}");
        }
    }

    #[test]
    fn legacy_procfile_keeps_restart_default() {
        let config = ConfigurationFile::from_procfile("run: /app/server\n").unwrap();
        assert_eq!(
            config.enclave.unwrap()["default"]
                .restart
                .unwrap_or_default(),
            RestartConfig::default()
        );
    }
}
