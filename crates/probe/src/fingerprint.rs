use portspecter_domain::ServiceObservation;

pub fn classify(bytes: &[u8]) -> Option<ServiceObservation> {
    let value = String::from_utf8_lossy(bytes);
    let mut result = ServiceObservation {
        evidence: value
            .chars()
            .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
            .take(4096)
            .collect(),
        detection: Some("protocol-response".into()),
        verified: true,
        ..Default::default()
    };
    if let Some(line) = value.split_inclusive('\n').find(|l| {
        l.ends_with('\n')
            && l.len() <= 255
            && (l.starts_with("SSH-2.0-") || l.starts_with("SSH-1.99-"))
    }) {
        result.name = "SSH".into();
        let software = line.splitn(3, '-').nth(2)?.split_whitespace().next()?;
        let (product, version) = software.split_once('_').unwrap_or((software, ""));
        result.product = Some(product.into());
        result.version = (!version.is_empty()).then(|| version.into());
    } else if value.starts_with("HTTP/1.0 ") || value.starts_with("HTTP/1.1 ") {
        if !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
            return None;
        }
        let status = value.lines().next()?.split_whitespace().nth(1)?;
        if status.len() != 3 || !status.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        result.name = "HTTP".into();
        for line in value.lines().skip(1) {
            if line.trim().is_empty() {
                break;
            }
            if let Some((key, server)) = line.split_once(':')
                && key.eq_ignore_ascii_case("server")
            {
                let token = server.split_whitespace().next().unwrap_or("");
                let (product, version) = token.split_once('/').unwrap_or((token, ""));
                result.product = (!product.is_empty()).then(|| product.into());
                result.version = (!version.is_empty()).then(|| version.into());
                break;
            }
        }
    } else if bytes.len() >= 12
        && value.starts_with("RFB ")
        && bytes[4..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'.'
        && bytes[8..11].iter().all(u8::is_ascii_digit)
        && bytes[11] == b'\n'
    {
        result.name = "VNC".into();
        // RFB is a protocol version, not the VNC product version.
        result.detection = Some(format!("RFB protocol {}", &value[4..11]));
    } else if bytes.len() > 6 && bytes[3] == 0 && bytes[4] == 10 {
        let length = bytes[0] as usize | ((bytes[1] as usize) << 8) | ((bytes[2] as usize) << 16);
        let end = bytes[5..].iter().position(|b| *b == 0)? + 5;
        if length < 20 || bytes.len() < length + 4 || end <= 5 || end > 128 || end >= length + 4 {
            return None;
        }
        let version = std::str::from_utf8(&bytes[5..end]).ok()?;
        if !version.starts_with(|c: char| c.is_ascii_digit())
            || version.chars().any(char::is_control)
        {
            return None;
        }
        result.name = "MySQL".into();
        result.product = Some(
            if version.contains("MariaDB") {
                "MariaDB"
            } else {
                "MySQL-compatible"
            }
            .into(),
        );
        result.version = Some(version.into());
    } else {
        let first = value.lines().next().unwrap_or("");
        let lower = first.to_ascii_lowercase();
        result.name = if (first.starts_with("220 ") || first.starts_with("220-"))
            && (lower.contains("smtp") || lower.contains("esmtp"))
        {
            "SMTP"
        } else if (first.starts_with("220 ") || first.starts_with("220-")) && lower.contains("ftp")
        {
            "FTP"
        } else if first.starts_with("* OK") && lower.contains("imap") {
            "IMAP"
        } else if first.starts_with("+OK") && lower.contains("pop3") {
            "POP3"
        } else {
            return None;
        }
        .into();
        // Only extract product versions from explicit product tokens, not arbitrary numbers.
        for product in ["vsFTPd", "ProFTPD", "FileZilla", "Exim", "Dovecot"] {
            if let Some(pos) = lower.find(&product.to_ascii_lowercase()) {
                result.product = Some(product.into());
                let tail = first[pos + product.len()..].trim_start_matches([' ', '/', '-', '(']);
                let token = tail
                    .split(|c: char| c.is_whitespace() || c == ')')
                    .next()
                    .unwrap_or("");
                result.version = token
                    .starts_with(|c: char| c.is_ascii_digit())
                    .then(|| token.into());
                break;
            }
        }
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_evidence_without_inventing_products() {
        let ssh = classify(b"Welcome\r\nSSH-2.0-OpenSSH_9.9p2 Ubuntu\r\n").unwrap();
        assert_eq!(ssh.version.as_deref(), Some("9.9p2"));
        let http = classify(b"HTTP/1.1 200 OK\r\nsErVeR: nginx/1.28.0\r\n\r\n").unwrap();
        assert_eq!(http.product.as_deref(), Some("nginx"));
        assert!(classify(b"220 ambiguous greeting\r\n").is_none());
        assert!(classify(b"HTTP/something").is_none());
        assert!(classify(b"HTTP/1.1 200 OK\r\nServer: nginx/1.").is_none());
        assert!(classify(b"Welcome\nSSH-2.0-Open").is_none());
        let vnc = classify(b"RFB 003.008\n").unwrap();
        assert_eq!(vnc.name, "VNC");
        assert!(vnc.version.is_none());
        assert_eq!(
            classify(b"220 (vsFTPd 3.0.5)\r\n")
                .unwrap()
                .version
                .as_deref(),
            Some("3.0.5")
        );
    }
}
