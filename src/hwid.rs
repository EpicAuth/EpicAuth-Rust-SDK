use sha2::{Digest, Sha256};

pub fn get_hwid() -> String {
    #[cfg(target_os = "windows")]
    {
        if let Some(hwid) = get_windows_hwid() {
            return hwid;
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(hwid) = get_linux_hwid() {
            return hwid;
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(hwid) = get_macos_hwid() {
            return hwid;
        }
    }

    get_fallback_hwid()
}

#[cfg(target_os = "windows")]
fn get_windows_hwid() -> Option<String> {
    if let Ok(output) = std::process::Command::new("reg")
        .args([
            "query",
            "HKLM\\SOFTWARE\\Microsoft\\Cryptography",
            "/v",
            "MachineGuid",
        ])
        .output()
    {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                if line.contains("MachineGuid") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let guid = parts[2].trim();
                        if !guid.is_empty() {
                            return Some(guid.to_string());
                        }
                    }
                }
            }
        }
    }

    let user = std::env::var("USERNAME").unwrap_or_default();
    if !user.is_empty() {
        if let Ok(output) = std::process::Command::new("wmic")
            .args([
                "useraccount",
                "where",
                &format!("name='{}'", user),
                "get",
                "sid",
            ])
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                let lines: Vec<&str> = text
                    .lines()
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty())
                    .collect();
                if lines.len() >= 2 && lines[1].len() > 10 {
                    return Some(lines[1].to_string());
                }
            }
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn get_linux_hwid() -> Option<String> {
    if let Ok(content) = std::fs::read_to_string("/etc/machine-id") {
        let trimmed = content.trim();
        if trimmed.len() > 10 {
            return Some(trimmed.to_string());
        }
    }

    if let Ok(content) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
        let trimmed = content.trim();
        if trimmed.len() > 10 {
            return Some(trimmed.to_string());
        }
    }

    None
}

#[cfg(target_os = "macos")]
fn get_macos_hwid() -> Option<String> {
    if let Ok(output) = std::process::Command::new("sh")
        .args([
            "-c",
            "ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformSerialNumber",
        ])
        .output()
    {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            if let Some(pos) = text.find('=') {
                let serial = text[pos + 1..].replace('\"', "").trim().to_string();
                if !serial.is_empty() {
                    return Some(serial);
                }
            }
        }
    }

    None
}

fn get_fallback_hwid() -> String {
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown_host".to_string());
    let user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown_user".to_string());
    let arch = std::env::consts::ARCH;

    let payload = format!("{}|{}|{}", hostname, user, arch);
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    let hex_digest = hex::encode(hasher.finalize());
    hex_digest[..32.min(hex_digest.len())].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hwid_generation() {
        let hwid = get_hwid();
        assert!(!hwid.is_empty());
        assert!(hwid.len() >= 10);
    }
}
