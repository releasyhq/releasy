use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let json = releasy_server::openapi::openapi_json_pretty()?;
    io::stdout().write_all(json.as_bytes())?;
    io::stdout().write_all(b"\n")?;
    Ok(())
}
