use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VendorRecord {
    mac_prefix: String,
    vendor_name: String,
    private: bool,
}

#[derive(Default)]
pub struct VendorDatabase {
    prefixes: HashMap<(u8, u64), String>,
}

pub fn parse_mac(value: &str) -> Option<[u8; 6]> {
    let clean: String = value
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.'))
        .collect();
    if clean.len() != 12 || !clean.is_ascii() {
        return None;
    }
    let mut mac = [0; 6];
    for (i, byte) in mac.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(mac)
}

impl VendorDatabase {
    pub fn from_json(bytes: &[u8]) -> anyhow::Result<Self> {
        let records: Vec<VendorRecord> = serde_json::from_slice(bytes)?;
        let mut prefixes = HashMap::new();
        for record in records {
            if record.private {
                continue;
            }
            let hex: String = record
                .mac_prefix
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .collect();
            if !matches!(hex.len(), 6 | 7 | 9) {
                continue;
            }
            if let Ok(value) = u64::from_str_radix(&hex, 16) {
                prefixes.insert(((hex.len() * 4) as u8, value), record.vendor_name);
            }
        }
        anyhow::ensure!(!prefixes.is_empty(), "Vendor database is empty");
        Ok(Self { prefixes })
    }
    pub fn len(&self) -> usize {
        self.prefixes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.prefixes.is_empty()
    }
    pub fn lookup(&self, mac: &[u8; 6]) -> Option<&str> {
        if mac[0] & 3 != 0 {
            return None;
        }
        let value = mac.iter().fold(0u64, |v, b| (v << 8) | *b as u64);
        [36u8, 28, 24].into_iter().find_map(|bits| {
            self.prefixes
                .get(&(bits, value >> (48 - bits)))
                .map(String::as_str)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn longest_prefix_and_private_mac() {
        let db=VendorDatabase::from_json(br#"[{"macPrefix":"00:11:22","vendorName":"Broad","private":false},{"macPrefix":"00:11:22:3","vendorName":"Specific","private":false},{"macPrefix":"00:11:22:33:4","vendorName":"Exact","private":false}]"#).unwrap();
        assert_eq!(
            db.lookup(&parse_mac("00:11:22:33:44:55").unwrap()),
            Some("Exact")
        );
        assert_eq!(db.lookup(&parse_mac("02:11:22:33:44:55").unwrap()), None);
        assert!(parse_mac("☃☃☃☃").is_none());
    }
}
