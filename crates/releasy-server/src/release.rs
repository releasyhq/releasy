#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseStatus {
    Draft,
    Published,
}

impl ReleaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ReleaseStatus::Draft => "draft",
            ReleaseStatus::Published => "published",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "draft" => Some(ReleaseStatus::Draft),
            "published" => Some(ReleaseStatus::Published),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseAction {
    Publish,
    Unpublish,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseTransitionError {
    AlreadyPublished,
    AlreadyDraft,
}

pub fn apply_release_action(
    current: ReleaseStatus,
    action: ReleaseAction,
) -> Result<ReleaseStatus, ReleaseTransitionError> {
    match (current, action) {
        (ReleaseStatus::Draft, ReleaseAction::Publish) => Ok(ReleaseStatus::Published),
        (ReleaseStatus::Published, ReleaseAction::Unpublish) => Ok(ReleaseStatus::Draft),
        (ReleaseStatus::Published, ReleaseAction::Publish) => {
            Err(ReleaseTransitionError::AlreadyPublished)
        }
        (ReleaseStatus::Draft, ReleaseAction::Unpublish) => {
            Err(ReleaseTransitionError::AlreadyDraft)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_release_action_allows_publish() {
        let next = apply_release_action(ReleaseStatus::Draft, ReleaseAction::Publish);
        assert_eq!(next, Ok(ReleaseStatus::Published));
    }

    #[test]
    fn apply_release_action_rejects_publish_when_published() {
        let next = apply_release_action(ReleaseStatus::Published, ReleaseAction::Publish);
        assert_eq!(next, Err(ReleaseTransitionError::AlreadyPublished));
    }

    #[test]
    fn parse_rejects_unknown_status() {
        assert_eq!(ReleaseStatus::parse("other"), None);
    }
}
