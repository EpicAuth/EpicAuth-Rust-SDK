use chrono::Utc;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

pub fn log_event(message: &str) {
    println!("{message}");

    let exe_name = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "unknown".to_string());

    let home_dir = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());

    let log_dir = PathBuf::from(home_dir)
        .join(".epicauth")
        .join("logs")
        .join(&exe_name);

    if create_dir_all(&log_dir).is_err() {
        return;
    }

    let now = Utc::now();
    let file_name = format!("{}_logs.txt", now.format("%b_%d_%Y"));
    let log_file_path = log_dir.join(file_name);

    let mut redacted = message.to_string();
    let sensitive_fields = [
        "sessionid",
        "ownerid",
        "app",
        "version",
        "fileid",
        "webhooks",
        "nonce",
    ];

    for field in &sensitive_fields {
        redacted = redact_field(&redacted, field);
    }

    let log_line = format!("[{}] [{}] {}\n", now.to_rfc3339(), exe_name, redacted);

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file_path)
    {
        let _ = file.write_all(log_line.as_bytes());
    }
}

fn redact_field(content: &str, field: &str) -> String {
    let pattern = format!("\"{}\":", field);
    let mut result = String::new();
    let mut remainder = content;

    while let Some(pos) = remainder.find(&pattern) {
        result.push_str(&remainder[..pos]);
        result.push_str(&pattern);

        let after_key = &remainder[pos + pattern.len()..];
        let trimmed = after_key.trim_start();
        if let Some(stripped) = trimmed.strip_prefix('\"') {
            if let Some(close_quote) = stripped.find('\"') {
                result.push_str(" \"[REDACTED]\"");
                remainder = &stripped[close_quote + 1..];
                continue;
            }
        }
        remainder = after_key;
    }

    result.push_str(remainder);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_field() {
        let input = r#"{"sessionid": "secret_123", "name": "app"}"#;
        let out = redact_field(input, "sessionid");
        assert!(out.contains(r#""sessionid": "[REDACTED]""#));
        assert!(out.contains(r#""name": "app""#));
    }
}
