use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathRoots {
    home: Option<PathBuf>,
    workspace: Option<PathBuf>,
    temp: Option<PathBuf>,
}

impl PathRoots {
    pub fn new(home: Option<PathBuf>, workspace: Option<PathBuf>, temp: Option<PathBuf>) -> Self {
        Self {
            home,
            workspace,
            temp,
        }
    }

    pub fn normalize(&self, path: &Path) -> String {
        let roots = [
            ("$WORKSPACE", self.workspace.as_deref()),
            ("$TMP", self.temp.as_deref()),
            ("$HOME", self.home.as_deref()),
        ];

        for (label, root) in roots {
            if let Some(suffix) = root.and_then(|root| path.strip_prefix(root).ok()) {
                return render_normalized_path(label, suffix);
            }
        }

        path.to_string_lossy().into_owned()
    }
}

pub fn sanitize_http_url(input: &str) -> Option<String> {
    if input
        .chars()
        .any(|character| character.is_control() || character.is_whitespace() || character == '\\')
    {
        return None;
    }

    let (scheme, remainder) = if let Some(remainder) = input.strip_prefix("https://") {
        ("https://", remainder)
    } else if let Some(remainder) = input.strip_prefix("http://") {
        ("http://", remainder)
    } else {
        return None;
    };

    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);

    if host.is_empty() {
        return None;
    }

    let suffix = &remainder[authority_end..];
    let path_end = suffix.find(['?', '#']).unwrap_or(suffix.len());
    let path = &suffix[..path_end];

    Some(format!("{scheme}{host}{path}"))
}

pub fn is_valid_environment_name(name: &str) -> bool {
    !name.is_empty() && !name.contains(['=', '\0'])
}

fn render_normalized_path(label: &str, suffix: &Path) -> String {
    if suffix.as_os_str().is_empty() {
        label.to_owned()
    } else {
        format!("{label}/{}", suffix.to_string_lossy())
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{is_valid_environment_name, sanitize_http_url, PathRoots};

    #[test]
    fn workspace_paths_take_precedence_over_home_paths() {
        let roots = PathRoots::new(
            Some(PathBuf::from("/Users/example")),
            Some(PathBuf::from("/Users/example/project")),
            Some(PathBuf::from("/tmp")),
        );

        assert_eq!(
            roots.normalize(Path::new("/Users/example/project/src/main.rs")),
            "$WORKSPACE/src/main.rs"
        );
        assert_eq!(
            roots.normalize(Path::new("/Users/example/.ssh/config")),
            "$HOME/.ssh/config"
        );
    }

    #[test]
    fn temp_paths_are_normalized_independently() {
        let roots = PathRoots::new(
            Some(PathBuf::from("/Users/example")),
            None,
            Some(PathBuf::from("/tmp")),
        );

        assert_eq!(
            roots.normalize(Path::new("/tmp/build/output")),
            "$TMP/build/output"
        );
    }

    #[test]
    fn unrelated_paths_are_left_unchanged() {
        let roots = PathRoots::new(None, Some(PathBuf::from("/work/project")), None);

        assert_eq!(roots.normalize(Path::new("/usr/bin/git")), "/usr/bin/git");
    }

    #[test]
    fn url_sanitization_removes_credentials_query_and_fragment() {
        assert_eq!(
            sanitize_http_url("https://user:secret@example.com/events?token=value#result"),
            Some("https://example.com/events".to_owned())
        );
    }

    #[test]
    fn url_sanitization_preserves_ports_and_ipv6_hosts() {
        assert_eq!(
            sanitize_http_url("http://[::1]:7319/session?id=1"),
            Some("http://[::1]:7319/session".to_owned())
        );
    }

    #[test]
    fn url_sanitization_rejects_unsupported_or_ambiguous_inputs() {
        assert_eq!(sanitize_http_url("file:///Users/example/.ssh/config"), None);
        assert_eq!(sanitize_http_url("https://example.com\\@other.test"), None);
        assert_eq!(sanitize_http_url("https://"), None);
    }

    #[test]
    fn environment_names_cannot_contain_values() {
        assert!(is_valid_environment_name("PATH"));
        assert!(is_valid_environment_name("npm_config_registry"));
        assert!(!is_valid_environment_name("TOKEN=secret"));
        assert!(!is_valid_environment_name(""));
    }
}
