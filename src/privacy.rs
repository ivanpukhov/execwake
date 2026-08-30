use std::net::Ipv6Addr;
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathRoots {
    home: Option<PathBuf>,
    workspace: Option<PathBuf>,
    temp: Option<PathBuf>,
}

impl PathRoots {
    pub fn new(home: Option<PathBuf>, workspace: Option<PathBuf>, temp: Option<PathBuf>) -> Self {
        Self {
            home: home.and_then(prepare_root),
            workspace: workspace.and_then(prepare_root),
            temp: temp.and_then(prepare_root),
        }
    }

    pub fn normalize(&self, path: &Path) -> String {
        let path = normalize_lexically(path);
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

    if !is_valid_http_authority(host) {
        return None;
    }

    let suffix = &remainder[authority_end..];
    let path_end = suffix.find(['?', '#']).unwrap_or(suffix.len());
    let path = &suffix[..path_end];

    Some(format!("{scheme}{host}{path}"))
}

pub fn is_valid_environment_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('=') && !name.chars().any(|character| character.is_control())
}

fn is_valid_http_authority(authority: &str) -> bool {
    if let Some(remainder) = authority.strip_prefix('[') {
        let Some((address, suffix)) = remainder.split_once(']') else {
            return false;
        };

        return address.parse::<Ipv6Addr>().is_ok()
            && (suffix.is_empty() || suffix.strip_prefix(':').map_or(false, is_valid_port));
    }

    if authority.contains(['[', ']', '@']) {
        return false;
    }

    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));

    !host.is_empty() && !host.contains(':') && port.map_or(true, is_valid_port)
}

fn is_valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok()
}

fn prepare_root(path: PathBuf) -> Option<PathBuf> {
    let path = normalize_lexically(&path);
    path.is_absolute().then_some(path)
}

fn normalize_lexically(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => match normalized.components().next_back() {
                Some(Component::Normal(_)) => {
                    normalized.pop();
                }
                Some(Component::ParentDir) | None => normalized.push(component.as_os_str()),
                Some(Component::Prefix(_)) if !path.has_root() => {
                    normalized.push(component.as_os_str());
                }
                Some(Component::Prefix(_) | Component::RootDir) => {}
                Some(Component::CurDir) => unreachable!(),
            },
        }
    }

    normalized
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
    fn parent_components_cannot_escape_a_normalized_root() {
        let roots = PathRoots::new(
            Some(PathBuf::from("/Users/example")),
            Some(PathBuf::from("/Users/example/project")),
            None,
        );

        assert_eq!(
            roots.normalize(Path::new("/Users/example/project/../.ssh/config")),
            "$HOME/.ssh/config"
        );
    }

    #[test]
    fn relative_parent_components_are_preserved() {
        let roots = PathRoots::new(None, None, None);

        assert_eq!(
            roots.normalize(Path::new("../../project/./file")),
            "../../project/file"
        );
    }

    #[test]
    fn relative_or_empty_roots_cannot_match_unrelated_paths() {
        let roots = PathRoots::new(Some(PathBuf::new()), Some(PathBuf::from("project")), None);

        assert_eq!(roots.normalize(Path::new("/etc/hosts")), "/etc/hosts");
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
        assert_eq!(sanitize_http_url("https://[::1/path"), None);
        assert_eq!(sanitize_http_url("https://::1/path"), None);
        assert_eq!(sanitize_http_url("https://example.com:invalid/path"), None);
        assert_eq!(sanitize_http_url("https://example.com:65536/path"), None);
    }

    #[test]
    fn environment_names_cannot_contain_values() {
        assert!(is_valid_environment_name("PATH"));
        assert!(is_valid_environment_name("npm_config_registry"));
        assert!(!is_valid_environment_name("TOKEN=secret"));
        assert!(!is_valid_environment_name("TOKEN\n"));
        assert!(!is_valid_environment_name(""));
    }
}
