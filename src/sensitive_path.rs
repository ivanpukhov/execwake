#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SensitivePathClass {
    Credential,
    PrivateConfiguration,
}

pub(crate) fn classify(path: &str) -> Option<SensitivePathClass> {
    if credential_path(path) {
        Some(SensitivePathClass::Credential)
    } else if private_configuration_path(path) {
        Some(SensitivePathClass::PrivateConfiguration)
    } else {
        None
    }
}

fn credential_path(path: &str) -> bool {
    matches!(
        path,
        "$HOME/.aws/credentials"
            | "$HOME/.docker/config.json"
            | "$HOME/.kube/config"
            | "$HOME/.netrc"
            | "$HOME/.npmrc"
            | "$HOME/.config/gh/hosts.yml"
            | "$HOME/.config/gcloud/credentials.db"
    ) || path.strip_prefix("$HOME/.ssh/").map_or(false, |name| {
        name.starts_with("id_") && !name.ends_with(".pub")
    })
}

fn private_configuration_path(path: &str) -> bool {
    matches!(
        path,
        "$HOME/.gitconfig"
            | "$HOME/.ssh"
            | "$HOME/.ssh/authorized_keys"
            | "$HOME/.ssh/config"
            | "$HOME/.ssh/known_hosts"
    )
}

#[cfg(test)]
mod tests {
    use super::{classify, SensitivePathClass};

    #[test]
    fn classifies_home_credentials_and_private_configuration() {
        assert_eq!(
            classify("$HOME/.ssh/id_ed25519"),
            Some(SensitivePathClass::Credential)
        );
        assert_eq!(
            classify("$HOME/.gitconfig"),
            Some(SensitivePathClass::PrivateConfiguration)
        );
        assert_eq!(classify("$HOME/.ssh/id_ed25519.pub"), None);
        assert_eq!(classify("$WORKSPACE/.gitconfig"), None);
    }
}
