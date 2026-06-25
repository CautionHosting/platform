use hcl_edit::expr::Expression;
use hcl_edit::structure::Body;
use hcl_edit::Number;

use crate::error::PatcherError;
use crate::xpath::{parse_xpath, XPathSegment};

pub(crate) fn patch_hcl_value(
    hcl: &str,
    xpath: &str,
    value: &str,
    type_name: &str,
) -> Result<String, PatcherError> {
    let segments = parse_xpath(xpath).map_err(PatcherError::XPathParse)?;
    let mut body: Body = hcl.parse::<Body>().map_err(|e| {
        PatcherError::ParseHcl(e.to_string())
    })?;

    let new_expr = build_expression(value, type_name)?;
    set_value(&mut body, &segments, new_expr)
        .ok_or_else(|| PatcherError::XPathNotFound(xpath.to_string()))?;

    Ok(body.to_string())
}

fn set_value(
    body: &mut Body,
    segments: &[XPathSegment],
    new_expr: Expression,
) -> Option<()> {
    let attr_segment = segments.last()?;
    let block_count = segments.len() - 1;

    let mut current_body = body;
    for seg in segments.iter().take(block_count) {
        let (ident, label) = match seg {
            XPathSegment::Block { ident, label } => (ident.as_str(), label.as_deref()),
            XPathSegment::Attribute(_) => return None,
        };
        let block = if let Some(label_str) = label {
            current_body
                .get_blocks_mut(ident)
                .find(|b| b.labels.iter().any(|l| l.as_str() == label_str))?
        } else {
            current_body.get_blocks_mut(ident).next()?
        };
        current_body = &mut block.body;
    }

    let key = match attr_segment {
        XPathSegment::Attribute(k) => k.as_str(),
        XPathSegment::Block { .. } => return None,
    };

    let pos = current_body
        .iter()
        .position(|s| s.as_attribute().is_some_and(|a| a.has_key(key)))?;
    let structure = current_body.get_mut(pos)?;
    let attr = structure.as_attribute_mut()?;
    attr.value = new_expr;
    Some(())
}

pub(crate) fn build_expression(value: &str, type_name: &str) -> Result<Expression, PatcherError> {
    match type_name {
        "string" => Ok(Expression::from(value)),
        "bool" => match value {
            "true" => Ok(Expression::from(true)),
            "false" => Ok(Expression::from(false)),
            other => Err(PatcherError::InvalidValue {
                type_name: "bool".to_string(),
                raw: other.to_string(),
            }),
        },
        "number" => {
            let n = parse_number(value).ok_or_else(|| PatcherError::InvalidValue {
                type_name: "number".to_string(),
                raw: value.to_string(),
            })?;
            Ok(Expression::from(n))
        }
        other => Err(PatcherError::InvalidType(other.to_string())),
    }
}

fn parse_number(s: &str) -> Option<Number> {
    if let Ok(i) = s.parse::<i64>() {
        Some(Number::from(i))
    } else if let Ok(u) = s.parse::<u64>() {
        Some(Number::from(u))
    } else if let Ok(f) = s.parse::<f64>() {
        Number::from_f64(f)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_build_expression_string() {
        let expr = build_expression("hello", "string").unwrap();
        assert_eq!(expr, Expression::from("hello"));
    }

    #[test]
    fn test_build_expression_bool_true() {
        let expr = build_expression("true", "bool").unwrap();
        assert_eq!(expr, Expression::from(true));
    }

    #[test]
    fn test_build_expression_bool_false() {
        let expr = build_expression("false", "bool").unwrap();
        assert_eq!(expr, Expression::from(false));
    }

    #[test]
    fn test_build_expression_number_int() {
        let expr = build_expression("42", "number").unwrap();
        assert_eq!(expr, Expression::from(42i64));
    }

    #[test]
    fn test_build_expression_number_float() {
        let expr = build_expression("3.14", "number").unwrap();
        assert!(matches!(expr, Expression::Number(_)));
    }

    #[test]
    fn test_build_expression_invalid_bool() {
        assert!(build_expression("notabool", "bool").is_err());
    }

    #[test]
    fn test_build_expression_invalid_number() {
        assert!(build_expression("notanumber", "number").is_err());
    }

    #[test]
    fn test_build_expression_invalid_type() {
        assert!(build_expression("x", "unknown").is_err());
    }

    const TEST_HCL: &str = r#"
caution {
  managed_credentials = "credentials.pgp"
  machine_type = "c5.xlarge"
  provider {
    type = "aws"
  }
}

enclave "main" {
  build {
    containerfile = "Containerfile"
    cache = false
  }
  resources {
    cpu = 2
    memory_mb = 2000
  }
}
"#;

    #[test]
    fn test_patch_string_value() {
        let result = patch_hcl_value(TEST_HCL, "/caution/managed_credentials", "new-creds.pgp", "string").unwrap();
        assert!(result.contains(r#""new-creds.pgp""#));
    }

    #[test]
    fn test_patch_bool_value() {
        let result = patch_hcl_value(TEST_HCL, "/enclave.main/build/cache", "true", "bool").unwrap();
        assert!(result.contains("cache = true"));
    }

    #[test]
    fn test_patch_number_value() {
        let result = patch_hcl_value(TEST_HCL, "/enclave.main/resources/cpu", "4", "number").unwrap();
        assert!(result.contains("cpu = 4"));
    }

    #[test]
    fn test_patch_top_level_attribute() {
        let hcl = r#"foo = "bar"
baz = 1
"#;
        let result = patch_hcl_value(hcl, "/foo", "new-bar", "string").unwrap();
        assert!(result.contains(r#""new-bar""#));
    }

    #[test]
    fn test_xpath_not_found() {
        let result = patch_hcl_value(TEST_HCL, "/caution/nonexistent", "val", "string");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PatcherError::XPathNotFound(_)));
    }

    #[test]
    fn test_invalid_hcl() {
        let result = patch_hcl_value("not valid hcl {{{}", "/foo", "val", "string");
        assert!(result.is_err());
    }
}
