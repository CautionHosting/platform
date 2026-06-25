#[derive(Debug, Clone, PartialEq)]
pub(crate) enum XPathSegment {
    Block { ident: String, label: Option<String> },
    Attribute(String),
}

/// Parses a slash-delimited XPath.
///
/// The last segment is always an attribute; all preceding segments are blocks.
/// A leading `/` is optional. Block segments may carry a `.label` suffix.
pub(crate) fn parse_xpath(input: &str) -> Result<Vec<XPathSegment>, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("empty xpath".to_string());
    }
    let stripped = trimmed.strip_prefix('/').unwrap_or(trimmed);
    if stripped.is_empty() {
        return Err("empty xpath".to_string());
    }

    let parts: Vec<&str> = stripped.split('/').collect();
    if parts.is_empty() || parts.iter().any(|p| p.is_empty()) {
        return Err(format!("invalid xpath: {input}"));
    }

    let mut segments = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        let is_last = i == parts.len() - 1;
        if let Some((ident, label)) = part.split_once('.') {
            if ident.is_empty() || label.is_empty() {
                return Err(format!("invalid segment in xpath: {part}"));
            }
            if is_last {
                return Err(format!(
                    "last segment {part} has a label suffix; cannot be an attribute"
                ));
            }
            segments.push(XPathSegment::Block {
                ident: ident.to_string(),
                label: Some(label.to_string()),
            });
        } else if is_last {
            segments.push(XPathSegment::Attribute(part.to_string()));
        } else {
            segments.push(XPathSegment::Block {
                ident: part.to_string(),
                label: None,
            });
        }
    }

    Ok(segments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_path() {
        let segments = parse_xpath("/caution/provider/type").unwrap();
        assert_eq!(segments.len(), 3);
        assert_eq!(
            segments[0],
            XPathSegment::Block { ident: "caution".into(), label: None }
        );
        assert_eq!(
            segments[1],
            XPathSegment::Block { ident: "provider".into(), label: None }
        );
        assert_eq!(segments[2], XPathSegment::Attribute("type".into()));
    }

    #[test]
    fn parse_without_leading_slash() {
        let segments = parse_xpath("caution/provider/type").unwrap();
        assert_eq!(segments.len(), 3);
        assert_eq!(
            segments[0],
            XPathSegment::Block { ident: "caution".into(), label: None }
        );
    }

    #[test]
    fn parse_top_level_attribute() {
        let segments = parse_xpath("/managed_credentials").unwrap();
        assert_eq!(segments.len(), 1);
        assert_eq!(
            segments[0],
            XPathSegment::Attribute("managed_credentials".into())
        );
    }

    #[test]
    fn parse_with_label() {
        let segments = parse_xpath("/enclave.main/resources/cpu").unwrap();
        assert_eq!(segments.len(), 3);
        assert_eq!(
            segments[0],
            XPathSegment::Block {
                ident: "enclave".into(),
                label: Some("main".into()),
            }
        );
        assert_eq!(
            segments[1],
            XPathSegment::Block { ident: "resources".into(), label: None }
        );
        assert_eq!(segments[2], XPathSegment::Attribute("cpu".into()));
    }

    #[test]
    fn empty_path_errors() {
        assert!(parse_xpath("").is_err());
    }

    #[test]
    fn only_slash_errors() {
        assert!(parse_xpath("/").is_err());
    }

    #[test]
    fn trailing_slash_errors() {
        assert!(parse_xpath("/caution/").is_err());
    }

    #[test]
    fn empty_segment_in_middle_errors() {
        assert!(parse_xpath("/caution//type").is_err());
    }

    #[test]
    fn label_on_last_segment_errors() {
        assert!(parse_xpath("/caution/thing.label").is_err());
    }
}
