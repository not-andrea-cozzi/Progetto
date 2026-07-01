use goblin::elf::Elf;
use regex::Regex;
use std::sync::OnceLock;

#[derive(Debug, Default)]
pub struct StringFeature {
    pub string_count: usize,
    pub avg_string_length: f64,
    pub network_indicators_count: usize,
    pub suspicious_paths_count: usize,
}

fn ip_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap())
}

fn url_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"https?://").unwrap())
}

impl StringFeature {
    pub fn extract(elf: &Elf, raw_data: &[u8]) -> Result<Self, String> {
        let mut strings: Vec<String> = Vec::new();

        for s in elf.strtab.to_vec().map_err(|e| e.to_string())? {
            if !s.is_empty() {
                strings.push(s.to_string());
            }
        }

        for s in elf.dynstrtab.to_vec().map_err(|e| e.to_string())? {
            if !s.is_empty() {
                strings.push(s.to_string());
            }
        }

        if let Some(sh) = elf
            .section_headers
            .iter()
            .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".rodata"))
        {
            let offset = sh.sh_offset as usize;
            let size = sh.sh_size as usize;
            let end = offset.saturating_add(size).min(raw_data.len());
            if offset < end {
                let rodata_bytes = &raw_data[offset..end];
                let mut current = String::new();
                for &b in rodata_bytes {
                    if b.is_ascii_graphic() || b == b' ' {
                        current.push(b as char);
                    } else if current.len() > 3 {
                        strings.push(std::mem::take(&mut current));
                    } else {
                        current.clear();
                    }
                }
                if current.len() > 3 {
                    strings.push(current);
                }
            }
        }

        // cap a 2000, stesso limite del Python, per evitare costo quadratico
        // su regex applicate a corpus enormi
        let capped: Vec<&String> = strings.iter().take(2000).collect();

        Ok(Self::classify(&capped, strings.len()))
    }

    fn classify(strings: &[&String], total_count: usize) -> Self {
        let mut feature = Self::default();
        feature.string_count = total_count;

        if strings.is_empty() {
            return feature;
        }

        let total_len: usize = strings.iter().map(|s| s.len()).sum();
        feature.avg_string_length = total_len as f64 / strings.len() as f64;

        let ip_re = ip_regex();
        let url_re = url_regex();
        let suspicious_paths = ["/usr", "/bin", "/etc", "/tmp", "/opt"];

        for s in strings {
            if ip_re.is_match(s) || url_re.is_match(s) {
                feature.network_indicators_count += 1;
            }
            if suspicious_paths.iter().any(|p| s.contains(p)) {
                feature.suspicious_paths_count += 1;
            }
        }

        feature
    }
}
