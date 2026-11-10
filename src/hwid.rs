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
    // 1. Primary: Direct Win32 API registry query (instantaneous, zero child processes, no console window)
    if let Some(guid) = get_registry_machine_guid() {
        return Some(guid);
    }

    // 2. Secondary fallback: Query reg.exe using CREATE_NO_WINDOW (0x08000000) so GUI apps never flash a CMD window
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    if let Ok(output) = std::process::Command::new("reg")
        .args([
            "query",
            "HKLM\\SOFTWARE\\Microsoft\\Cryptography",
            "/v",
            "MachineGuid",
        ])
        .creation_flags(CREATE_NO_WINDOW)
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

    // 3. Tertiary fallback: Query user SID via wmic with CREATE_NO_WINDOW
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
            .creation_flags(CREATE_NO_WINDOW)
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

#[cfg(target_os = "windows")]
fn get_registry_machine_guid() -> Option<String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let subkey: Vec<u16> = OsStr::new("SOFTWARE\\Microsoft\\Cryptography")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let value_name: Vec<u16> = OsStr::new("MachineGuid")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    const HKEY_LOCAL_MACHINE: isize = -2147483646; // 0x80000002
    const KEY_READ: u32 = 0x20019;
    const KEY_WOW64_64KEY: u32 = 0x0100;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            hkey: isize,
            lp_sub_key: *const u16,
            ul_options: u32,
            sam_desired: u32,
            phk_result: *mut isize,
        ) -> i32;

        fn RegQueryValueExW(
            hkey: isize,
            lp_value_name: *const u16,
            lp_reserved: *mut u32,
            lp_type: *mut u32,
            lp_data: *mut u8,
            lpcb_data: *mut u32,
        ) -> i32;

        fn RegCloseKey(hkey: isize) -> i32;
    }

    unsafe {
        let mut hkey: isize = 0;
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut hkey,
        );

        if status != 0 {
            return None;
        }

        let mut buf = [0u8; 256];
        let mut buf_len = buf.len() as u32;
        let mut val_type = 0u32;

        let query_status = RegQueryValueExW(
            hkey,
            value_name.as_ptr(),
            std::ptr::null_mut(),
            &mut val_type,
            buf.as_mut_ptr(),
            &mut buf_len,
        );

        RegCloseKey(hkey);

        if query_status == 0 && buf_len > 0 {
            let u16_slice = std::slice::from_raw_parts(
                buf.as_ptr() as *const u16,
                (buf_len as usize) / std::mem::size_of::<u16>(),
            );
            let s = String::from_utf16_lossy(u16_slice)
                .trim_matches('\0')
                .trim()
                .to_string();
            if !s.is_empty() {
                return Some(s);
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
