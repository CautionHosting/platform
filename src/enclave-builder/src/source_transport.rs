// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
//! Preserve the transport selected for source retrieval across redirects.
use reqwest::{Url, redirect::Policy};

fn permits_redirect(previous: &[Url], next: &Url) -> bool {
    matches!(next.scheme(), "http" | "https")
        && (next.scheme() == "https" || previous.iter().all(|url| url.scheme() != "https"))
        && next.username().is_empty()
        && next.password().is_none()
}

/// Allow bounded HTTPS forge redirects, never an HTTPS-to-HTTP downgrade.
/// Explicit HTTP development sources remain supported until they upgrade to HTTPS.
pub fn redirect_policy() -> Policy {
    Policy::custom(|attempt| {
        if !permits_redirect(attempt.previous(), attempt.url()) {
            attempt.error("source redirect would downgrade HTTPS or change to an unsafe URL")
        } else {
            Policy::limited(10).redirect(attempt)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_redirects_preserve_https_across_the_entire_chain() {
        let https = Url::parse("https://forge.example/repo/archive/commit.tar.gz").unwrap();
        let http = Url::parse("http://development.example/source").unwrap();
        let cdn = Url::parse("https://cdn.example/source").unwrap();
        assert!(permits_redirect(&[https.clone()], &cdn));
        assert!(!permits_redirect(&[https.clone()], &http));
        assert!(permits_redirect(&[http.clone()], &http));
        assert!(permits_redirect(&[http.clone()], &https));
        assert!(!permits_redirect(&[http.clone(), https.clone()], &http));
        for target in [
            "file:///tmp/source",
            "https://user:password@cdn.example/source",
        ] {
            assert!(!permits_redirect(
                &[https.clone()],
                &Url::parse(target).unwrap()
            ));
        }
    }
}
