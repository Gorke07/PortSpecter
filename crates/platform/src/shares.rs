//! Share enumeration only: never mount a share or read its contents.
use chrono::Utc;
use portspecter_domain::{NetworkShare, ShareDiscovery, ShareStatus};
use std::{net::IpAddr, process::Stdio, time::Duration};
use tokio::{io::AsyncReadExt, process::Command};

fn result(status: ShareStatus, detail: Option<String>) -> ShareDiscovery {
    ShareDiscovery {
        status,
        shares: vec![],
        source: if cfg!(windows) {
            "Windows NetShareEnum (current identity)"
        } else {
            "smbclient (anonymous)"
        }
        .into(),
        detail,
        observed_at: Utc::now(),
    }
}

pub async fn enumerate(ip: IpAddr) -> ShareDiscovery {
    let mut command;
    #[cfg(windows)]
    {
        let Ok(exe) = std::env::current_exe() else {
            return result(ShareStatus::Unavailable, None);
        };
        command = Command::new(exe);
        command.args(["--internal-smb-shares", &ip.to_string()]);
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    #[cfg(not(windows))]
    {
        let executable = if cfg!(target_os = "macos") {
            ["/opt/homebrew/bin/smbclient", "/usr/local/bin/smbclient"]
                .into_iter()
                .find(|p| std::path::Path::new(p).is_file())
                .unwrap_or("smbclient")
        } else {
            "smbclient"
        };
        command = Command::new(executable);
        command.args([
            "-g",
            "-L",
            &ip.to_string(),
            "-N",
            "-U",
            "%",
            "-p",
            "445",
            "-t",
            "3",
            "--option=client min protocol=SMB2",
            "--option=client max protocol=SMB3",
        ]);
        command.env("LC_ALL", "C");
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => return result(ShareStatus::Unavailable, Some(error.to_string())),
    };
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let operation = async {
        let read = async |stream: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>| {
            let mut bytes = vec![];
            stream
                .take(1_048_577)
                .read_to_end(&mut bytes)
                .await
                .map(|_| bytes)
        };
        let (out, err) = tokio::try_join!(read(Box::pin(stdout)), read(Box::pin(stderr)))?;
        if out.len() > 1_048_576 || err.len() > 1_048_576 {
            return Err(std::io::Error::other("SMB output exceeded limit"));
        }
        let status = child.wait().await?;
        Ok::<_, std::io::Error>((status.success(), out, err))
    };
    let output = tokio::time::timeout(Duration::from_secs(8), operation).await;
    // Also reap timed out helpers. Cancellation drops child and kills it via kill_on_drop.
    if !matches!(output, Ok(Ok(_))) {
        let _ = child.kill().await;
    }
    match output {
        Err(_) => result(ShareStatus::TimedOut, None),
        Ok(Err(error)) => result(ShareStatus::Failed, Some(error.to_string())),
        Ok(Ok((success, out, err))) => {
            #[cfg(windows)]
            {
                if success {
                    return serde_json::from_slice(&out).unwrap_or_else(|_| {
                        result(
                            ShareStatus::Failed,
                            Some("Invalid share-helper response".into()),
                        )
                    });
                }
            }
            #[cfg(not(windows))]
            {
                parse_smbclient(
                    success,
                    &String::from_utf8_lossy(&out),
                    &String::from_utf8_lossy(&err),
                )
            }
            #[cfg(windows)]
            result(
                ShareStatus::Failed,
                Some(String::from_utf8_lossy(&err).chars().take(400).collect()),
            )
        }
    }
}

#[cfg(any(not(windows), test))]
fn parse_smbclient(success: bool, stdout: &str, stderr: &str) -> ShareDiscovery {
    let diagnostic = format!("{stdout}\n{stderr}");
    let denied = [
        "NT_STATUS_ACCESS_DENIED",
        "NT_STATUS_LOGON_FAILURE",
        "NT_STATUS_ACCOUNT_DISABLED",
    ]
    .iter()
    .any(|s| diagnostic.contains(s));
    if denied {
        return result(ShareStatus::AccessDenied, None);
    }
    if !success {
        return result(
            ShareStatus::Failed,
            Some(
                diagnostic
                    .chars()
                    .filter(|c| !c.is_control() || *c == '\n')
                    .take(400)
                    .collect(),
            ),
        );
    }
    let mut value = result(ShareStatus::Complete, None);
    for line in stdout.lines() {
        let mut fields = line.splitn(3, '|');
        if fields.next() != Some("Disk") {
            continue;
        }
        let Some(name) = fields.next().filter(|v| !v.is_empty()) else {
            continue;
        };
        if value.shares.len() >= 4096 {
            value.status = ShareStatus::Failed;
            value.detail = Some("Share count limit reached".into());
            break;
        }
        value.shares.push(NetworkShare {
            name: name.into(),
            hidden: name.ends_with('$'),
            comment: fields.next().unwrap_or("").into(),
        });
    }
    value.shares.sort_by(|a, b| a.name.cmp(&b.name));
    value.shares.dedup_by(|a, b| a.name == b.name);
    value
}

/// Called before GUI/runtime initialization in a disposable Windows helper process.
#[cfg(windows)]
pub fn helper_main() -> bool {
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some("--internal-smb-shares") {
        return false;
    }
    let value = match args.get(2).and_then(|s| s.parse::<IpAddr>().ok()) {
        Some(ip) if args.len() == 3 => native(ip),
        _ => result(
            ShareStatus::Failed,
            Some("Expected a literal IP address".into()),
        ),
    };
    let _ = serde_json::to_writer(std::io::stdout(), &value);
    true
}

#[cfg(windows)]
fn native(ip: IpAddr) -> ShareDiscovery {
    #[repr(C)]
    struct ShareInfo {
        name: *const u16,
        kind: u32,
        comment: *const u16,
    }
    #[link(name = "Netapi32")]
    unsafe extern "system" {
        fn NetShareEnum(
            server: *const u16,
            level: u32,
            buffer: *mut *mut u8,
            max: u32,
            read: *mut u32,
            total: *mut u32,
            resume: *mut u32,
        ) -> u32;
        fn NetApiBufferFree(buffer: *mut u8) -> u32;
    }
    struct Buffer(*mut u8);
    impl Drop for Buffer {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    NetApiBufferFree(self.0);
                }
            }
        }
    }
    unsafe fn string(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        // NetAPI owns null-terminated UTF-16 strings until the buffer is freed.
        let mut len = 0;
        while len < 32768 && unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, len) })
            .chars()
            .filter(|c| !c.is_control())
            .take(2048)
            .collect()
    }
    let name = match ip {
        IpAddr::V4(_) => ip.to_string(),
        IpAddr::V6(v) => format!("{}.ipv6-literal.net", v.to_string().replace(':', "-")),
    };
    let server: Vec<u16> = format!("\\\\{name}\0").encode_utf16().collect();
    let mut value = result(ShareStatus::Complete, None);
    let mut resume = 0;
    for _ in 0..64 {
        let mut buffer = Buffer(std::ptr::null_mut());
        let (mut read, mut total) = (0, 0);
        let previous = resume;
        // Level 1 exposes names/types/comments without requesting privileged server paths.
        let status = unsafe {
            NetShareEnum(
                server.as_ptr(),
                1,
                &mut buffer.0,
                65536,
                &mut read,
                &mut total,
                &mut resume,
            )
        };
        if !matches!(status, 0 | 234) {
            value.status = if matches!(status, 5 | 86 | 1326 | 1909) {
                ShareStatus::AccessDenied
            } else {
                ShareStatus::Failed
            };
            value.detail = Some(format!("NetShareEnum: {status}"));
            return value;
        }
        if read > 4096 || (read > 0 && buffer.0.is_null()) {
            break;
        }
        if read > 0 {
            for entry in
                unsafe { std::slice::from_raw_parts(buffer.0.cast::<ShareInfo>(), read as usize) }
            {
                if entry.kind & 0xFFFF != 0 {
                    continue;
                } // disk shares only; excludes IPC/printers
                let name = unsafe { string(entry.name) };
                value.shares.push(NetworkShare {
                    hidden: name.ends_with('$'),
                    name,
                    comment: unsafe { string(entry.comment) },
                });
            }
        }
        if status == 0 {
            value.shares.sort_by(|a, b| a.name.cmp(&b.name));
            value.shares.dedup_by(|a, b| a.name == b.name);
            return value;
        }
        if resume == previous || value.shares.len() >= 4096 {
            break;
        }
    }
    value.status = ShareStatus::Failed;
    value.detail = Some("Share enumeration limit reached; partial list".into());
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disk_shares_include_hidden_but_not_ipc_or_printers() {
        let value = parse_smbclient(
            true,
            "Disk|Public|Team\nDisk|C$|System\nDisk|Secret$|Private\nIPC|IPC$|IPC\nPrinter|Laser|Office\n",
            "",
        );
        assert_eq!(value.status, ShareStatus::Complete);
        assert_eq!(value.shares.len(), 3);
        assert_eq!(value.shares.iter().filter(|s| s.hidden).count(), 2);
        assert_eq!(
            parse_smbclient(false, "", "NT_STATUS_ACCESS_DENIED").status,
            ShareStatus::AccessDenied
        );
        assert_eq!(parse_smbclient(true, "", "").status, ShareStatus::Complete);
    }
}
