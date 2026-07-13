// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use serde::{Deserialize, Deserializer, de::MapAccess, de::Visitor};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

#[derive(Clone, Debug, Deserialize)]
pub struct PricingConfig {
    pub compute_margin_percent: f64,
    #[serde(default)]
    pub subscription_tiers: DuplicateCheckedTiers,
    #[serde(default)]
    pub credit_packages: HashMap<String, CreditPackagePricing>,
    #[serde(default)]
    pub paddle_catalog: Option<PaddleCatalog>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreditPackagePricing {
    pub bonus_percent: f64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaddleCatalog {
    pub version: u32,
    pub product_id: Option<String>,
    pub tax_category: String,
    pub currency_code: String,
    pub billing_cycle: BillingCycle,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BillingCycle {
    pub interval: String,
    pub frequency: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierPricing {
    #[serde(default)]
    monthly_cents: Option<i64>,
    #[serde(default, rename = "annual_cents")]
    legacy_annual_cents: Option<i64>,
    pub enclaves: i32,
    #[serde(default)]
    pub paddle_price_id: Option<String>,
    #[serde(skip)]
    annual_cents: i64,
}

impl TierPricing {
    pub fn monthly_cents(&self) -> i64 {
        self.annual_cents / 12
    }

    /// Retained for the legacy credit-backed subscription ledger.
    pub fn annual_cents(&self) -> i64 {
        self.annual_cents
    }
}

#[derive(Clone, Debug, Default)]
pub struct DuplicateCheckedTiers(pub BTreeMap<String, TierPricing>);

impl std::ops::Deref for DuplicateCheckedTiers {
    type Target = BTreeMap<String, TierPricing>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for DuplicateCheckedTiers {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'de> Deserialize<'de> for DuplicateCheckedTiers {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TiersVisitor;
        impl<'de> Visitor<'de> for TiersVisitor {
            type Value = DuplicateCheckedTiers;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a tier map with unique keys")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut tiers = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, TierPricing>()? {
                    if tiers.insert(key.clone(), value).is_some() {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate tier key `{key}`"
                        )));
                    }
                }
                Ok(DuplicateCheckedTiers(tiers))
            }
        }
        deserializer.deserialize_map(TiersVisitor)
    }
}

impl PricingConfig {
    pub fn parse(contents: &str, paddle_enabled: bool) -> Result<Self, PricingConfigError> {
        let mut config: Self = serde_json::from_str(contents).map_err(PricingConfigError::Json)?;
        normalize_tiers(&mut config.subscription_tiers)?;

        if let Some(catalog) = &config.paddle_catalog {
            validate_catalog(catalog, &config.subscription_tiers, paddle_enabled)?;
        } else if paddle_enabled {
            return invalid(
                "paddle_catalog is required when BYOC_PADDLE_SUBSCRIPTIONS_ENABLED is true",
            );
        }
        Ok(config)
    }
}

fn normalize_tiers(tiers: &mut DuplicateCheckedTiers) -> Result<(), PricingConfigError> {
    for (key, tier) in &mut tiers.0 {
        match (tier.monthly_cents, tier.legacy_annual_cents) {
            (Some(_), Some(_)) => {
                return invalid(format!(
                    "tier `{key}` has both monthly_cents and annual_cents"
                ));
            }
            (Some(monthly), None) if monthly > 0 => {
                tier.annual_cents = monthly.checked_mul(12).ok_or_else(|| {
                    PricingConfigError::Validation(format!("tier `{key}` monthly_cents overflows"))
                })?
            }
            (None, Some(annual)) if annual > 0 && annual % 12 == 0 => {
                tracing::warn!(tier = %key, "annual_cents is deprecated; converted deterministically to monthly_cents");
                tier.annual_cents = annual;
            }
            (None, Some(_)) => {
                return invalid(format!(
                    "tier `{key}` annual_cents must be positive and divisible by 12"
                ));
            }
            _ => {
                return invalid(format!(
                    "tier `{key}` requires a positive monthly_cents or annual_cents"
                ));
            }
        }
    }
    Ok(())
}

fn validate_catalog(
    catalog: &PaddleCatalog,
    tiers: &DuplicateCheckedTiers,
    paddle_enabled: bool,
) -> Result<(), PricingConfigError> {
    if catalog.version == 0 {
        return invalid("paddle_catalog.version must be positive");
    }
    if catalog.currency_code != "USD" {
        return invalid("paddle_catalog.currency_code must be USD");
    }
    if catalog.billing_cycle.interval != "month" || catalog.billing_cycle.frequency != 1 {
        return invalid("paddle_catalog.billing_cycle must be month with frequency 1");
    }
    if catalog.tax_category.trim().is_empty() {
        return invalid("paddle_catalog.tax_category must not be empty");
    }
    validate_optional_id(
        catalog.product_id.as_deref(),
        "pro_",
        "product",
        paddle_enabled,
    )?;

    let expected = [
        ("1_enclave", 1, 25000),
        ("2_enclaves", 2, 37500),
        ("3_enclaves", 3, 50000),
        ("4_enclaves", 4, 62500),
        ("5_enclaves", 5, 75000),
    ];
    if tiers.len() != expected.len() {
        return invalid("subscription_tiers must contain exactly five self-service tiers");
    }

    let uses_monthly = tiers.values().any(|tier| tier.monthly_cents.is_some());
    let uses_annual = tiers
        .values()
        .any(|tier| tier.legacy_annual_cents.is_some());
    if uses_monthly && uses_annual {
        return invalid("subscription_tiers must not mix monthly_cents and annual_cents");
    }

    let mut limits = HashSet::new();
    let mut ids = HashSet::new();
    for (key, expected_enclaves, expected_monthly) in expected {
        let tier = tiers.get(key).ok_or_else(|| {
            PricingConfigError::Validation(format!("subscription_tiers missing tier `{key}`"))
        })?;
        if !(1..=5).contains(&tier.enclaves) {
            return invalid(format!("tier `{key}` enclave limit must be in 1..=5"));
        }
        if !limits.insert(tier.enclaves) {
            return invalid("duplicate enclave limit");
        }
        if tier.enclaves != expected_enclaves {
            return invalid(format!("tier `{key}` has an invalid enclave limit"));
        }
        if tier.monthly_cents() != expected_monthly {
            return invalid(format!("tier `{key}` has an invalid monthly amount"));
        }

        validate_optional_id(
            tier.paddle_price_id.as_deref(),
            "pri_",
            &format!("price for tier `{key}`"),
            paddle_enabled,
        )?;
        if let Some(id) = tier.paddle_price_id.as_deref() {
            if !ids.insert(id) {
                return invalid("duplicate nonempty Paddle price ID");
            }
        }
    }
    Ok(())
}

fn validate_optional_id(
    id: Option<&str>,
    prefix: &str,
    kind: &str,
    required: bool,
) -> Result<(), PricingConfigError> {
    match id {
        None if required => invalid(format!("Paddle {kind} ID is required")),
        Some(id) if !valid_id(id, prefix) => invalid(format!("malformed Paddle {kind} ID")),
        _ => Ok(()),
    }
}

fn valid_id(id: &str, prefix: &str) -> bool {
    id.strip_prefix(prefix).is_some_and(|tail| {
        tail.len() >= 3
            && tail
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

fn invalid<T>(message: impl Into<String>) -> Result<T, PricingConfigError> {
    Err(PricingConfigError::Validation(message.into()))
}

#[derive(Debug, thiserror::Error)]
pub enum PricingConfigError {
    #[error("invalid pricing JSON")]
    Json(#[source] serde_json::Error),
    #[error("invalid pricing configuration: {0}")]
    Validation(String),
}

#[cfg(test)]
mod tests {
    use super::{PricingConfig, PricingConfigError};
    use serde_json::{Value, json};

    fn tiers(ids: bool) -> Value {
        let mut tiers = serde_json::Map::new();
        for (key, enclaves, monthly, id) in [
            ("1_enclave", 1, 25000, "pri_one"),
            ("2_enclaves", 2, 37500, "pri_two"),
            ("3_enclaves", 3, 50000, "pri_three"),
            ("4_enclaves", 4, 62500, "pri_four"),
            ("5_enclaves", 5, 75000, "pri_five"),
        ] {
            tiers.insert(
                key.into(),
                json!({"monthly_cents": monthly, "enclaves": enclaves,
                       "paddle_price_id": if ids { Some(id) } else { None }}),
            );
        }
        Value::Object(tiers)
    }

    fn catalog(ids: bool) -> Value {
        json!({
            "compute_margin_percent": 0,
            "paddle_catalog": {"version": 1, "product_id": if ids { Some("pro_product") } else { None },
                "tax_category": "saas", "currency_code": "USD",
                "billing_cycle": {"interval": "month", "frequency": 1}},
            "subscription_tiers": tiers(ids),
            "credit_packages": {"1000": {"bonus_percent": 2.5}}
        })
    }

    fn error(value: &Value, enabled: bool) -> String {
        PricingConfig::parse(&value.to_string(), enabled)
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn parses_documented_shape_with_exact_values() {
        let parsed = PricingConfig::parse(&catalog(true).to_string(), true).unwrap();
        assert_eq!(parsed.subscription_tiers["3_enclaves"].monthly_cents(), 50000);
        assert_eq!(parsed.subscription_tiers["3_enclaves"].annual_cents(), 600000);
        assert_eq!(parsed.credit_packages["1000"].bonus_percent, 2.5);
    }

    #[test]
    fn disabled_preserves_legacy_configuration() {
        let legacy = r#"{"compute_margin_percent":0,"subscription_tiers":{"legacy":{"annual_cents":1200,"enclaves":9}},"credit_packages":{}}"#;
        let parsed = PricingConfig::parse(legacy, false).unwrap();
        assert_eq!(parsed.subscription_tiers["legacy"].monthly_cents(), 100);
    }

    #[test]
    fn null_ids_are_allowed_disabled_and_required_enabled() {
        assert!(PricingConfig::parse(&catalog(false).to_string(), false).is_ok());
        assert!(error(&catalog(false), true).contains("product ID is required"));
    }

    #[test]
    fn malformed_catalog_is_rejected_even_disabled() {
        for (pointer, replacement) in [
            ("/paddle_catalog/version", json!(0)),
            ("/paddle_catalog/currency_code", json!("EUR")),
            ("/paddle_catalog/billing_cycle/interval", json!("year")),
            ("/paddle_catalog/billing_cycle/frequency", json!(12)),
            ("/subscription_tiers/3_enclaves/monthly_cents", json!(50001)),
            ("/subscription_tiers/3_enclaves/enclaves", json!(4)),
            (
                "/subscription_tiers/3_enclaves/paddle_price_id",
                json!("bad"),
            ),
        ] {
            let mut value = catalog(true);
            *value.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                PricingConfig::parse(&value.to_string(), false).is_err(),
                "accepted {pointer}"
            );
        }
    }

    #[test]
    fn rejects_missing_catalog_when_enabled() {
        let value = json!({"compute_margin_percent": 0, "subscription_tiers": {}});
        assert!(error(&value, true).contains("paddle_catalog is required"));
    }

    #[test]
    fn accepts_future_positive_catalog_versions() {
        let mut value = catalog(true);
        value["paddle_catalog"]["version"] = json!(2);
        assert!(PricingConfig::parse(&value.to_string(), true).is_ok());
    }

    #[test]
    fn rejects_duplicate_limits_and_ids() {
        let mut duplicate_limit = catalog(true);
        duplicate_limit["subscription_tiers"]["2_enclaves"]["enclaves"] = json!(1);
        assert!(error(&duplicate_limit, false).contains("duplicate enclave limit"));
        let mut duplicate_id = catalog(true);
        duplicate_id["subscription_tiers"]["2_enclaves"]["paddle_price_id"] = json!("pri_one");
        assert!(error(&duplicate_id, false).contains("duplicate nonempty Paddle price ID"));
    }

    #[test]
    fn rejects_duplicate_keys_as_json_error() {
        let raw = r#"{"compute_margin_percent":0,"subscription_tiers":{"x":{"monthly_cents":1,"enclaves":1},"x":{"monthly_cents":1,"enclaves":1}}}"#;
        assert!(matches!(
            PricingConfig::parse(raw, false),
            Err(PricingConfigError::Json(_))
        ));
    }

    #[test]
    fn validates_legacy_amounts_overflow_and_mixed_cycles() {
        for raw in [
            r#"{"compute_margin_percent":0,"subscription_tiers":{"x":{"annual_cents":13,"enclaves":1}}}"#,
            r#"{"compute_margin_percent":0,"subscription_tiers":{"x":{"monthly_cents":0,"enclaves":1}}}"#,
            r#"{"compute_margin_percent":0,"subscription_tiers":{"x":{"monthly_cents":9223372036854775807,"enclaves":1}}}"#,
            r#"{"compute_margin_percent":0,"subscription_tiers":{"x":{"monthly_cents":1,"annual_cents":12,"enclaves":1}}}"#,
        ] {
            assert!(PricingConfig::parse(raw, false).is_err());
        }

        let mut mixed = catalog(true);
        let tier = &mut mixed["subscription_tiers"]["5_enclaves"];
        tier.as_object_mut().unwrap().remove("monthly_cents");
        tier["annual_cents"] = json!(900000);
        assert!(error(&mixed, false).contains("must not mix"));
    }

    #[test]
    fn rejects_nested_tiers_and_accepts_divisible_all_annual_catalog() {
        let mut nested = catalog(false);
        nested["paddle_catalog"]["tiers"] = nested["subscription_tiers"].clone();
        assert!(PricingConfig::parse(&nested.to_string(), false).is_err());

        let mut annual = catalog(false);
        for tier in annual["subscription_tiers"]
            .as_object_mut()
            .unwrap()
            .values_mut()
        {
            let monthly = tier["monthly_cents"].as_i64().unwrap();
            tier.as_object_mut().unwrap().remove("monthly_cents");
            tier["annual_cents"] = json!(monthly * 12);
        }
        assert!(PricingConfig::parse(&annual.to_string(), false).is_ok());
    }
}
