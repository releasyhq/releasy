#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlugError {
    Empty,
    TooShort { min: usize },
    TooLong { max: usize },
    LeadingHyphen,
    TrailingHyphen,
    InvalidChar { ch: char, index: usize },
}

const MIN_SLUG_LEN: usize = 3;
const MAX_SLUG_LEN: usize = 64;

pub fn validate_slug(value: &str) -> Result<(), SlugError> {
    if value.is_empty() {
        return Err(SlugError::Empty);
    }

    if value.len() < MIN_SLUG_LEN {
        return Err(SlugError::TooShort { min: MIN_SLUG_LEN });
    }

    if value.len() > MAX_SLUG_LEN {
        return Err(SlugError::TooLong { max: MAX_SLUG_LEN });
    }

    if value.starts_with('-') {
        return Err(SlugError::LeadingHyphen);
    }

    if value.ends_with('-') {
        return Err(SlugError::TrailingHyphen);
    }

    for (index, ch) in value.chars().enumerate() {
        if !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-') {
            return Err(SlugError::InvalidChar { ch, index });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_slug_accepts_valid() {
        assert_eq!(validate_slug("release-1"), Ok(()));
    }

    #[test]
    fn validate_slug_rejects_uppercase() {
        assert!(matches!(
            validate_slug("Release-1"),
            Err(SlugError::InvalidChar { ch: 'R', index: 0 })
        ));
    }

    #[test]
    fn validate_slug_rejects_trailing_hyphen() {
        assert_eq!(validate_slug("release-"), Err(SlugError::TrailingHyphen));
    }
}
