use std::env;

#[derive(Debug, Clone, PartialEq, Eq)]
enum PortError {
    Empty,
    NotANumber,
    OutOfRange,
}

fn parse_port(value: &str) -> Result<u16, PortError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PortError::Empty);
    }

    let parsed: u16 = trimmed.parse().map_err(|_| PortError::NotANumber)?;
    if parsed == 0 {
        return Err(PortError::OutOfRange);
    }

    Ok(parsed)
}

fn port_from_env() -> Result<u16, PortError> {
    let raw = env::var("RELEASY_PORT").unwrap_or_else(|_| "8080".to_string());
    parse_port(&raw)
}

fn main() {
    let port = match port_from_env() {
        Ok(port) => port,
        Err(error) => {
            eprintln!("invalid RELEASY_PORT: {:?}", error);
            std::process::exit(1);
        }
    };

    println!("releasy-server starting on port {port}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_port_accepts_valid() {
        assert_eq!(parse_port("8080"), Ok(8080));
    }

    #[test]
    fn parse_port_rejects_zero() {
        assert_eq!(parse_port("0"), Err(PortError::OutOfRange));
    }

    #[test]
    fn parse_port_rejects_non_numeric() {
        assert_eq!(parse_port("nope"), Err(PortError::NotANumber));
    }
}
