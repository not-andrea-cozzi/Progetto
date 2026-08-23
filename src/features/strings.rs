use goblin::elf::Elf;
use regex::Regex;
use std::sync::OnceLock;

use super::extraction_warnings::WarningLog;

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
    /// Non ritorna mai Err: string table corrotta o assente produce feature
    /// default con un warning registrato in `log`, non abortisce il sample.
    /// strtab/dynstrtab sono trattate come fonti indipendenti: se una fallisce
    /// si continua con l'altra invece di perdere entrambe.
    pub fn extract(elf: &Elf, raw_data: &[u8], log: &mut WarningLog) -> Self {
        let mut strings: Vec<String> = Vec::new();

        match elf.strtab.to_vec() {
            Ok(v) => strings.extend(v.into_iter().filter(|s| !s.is_empty()).map(String::from)),
            Err(e) => log.push("strings", format!("strtab illeggibile, saltata: {}", e)),
        }

        match elf.dynstrtab.to_vec() {
            Ok(v) => strings.extend(v.into_iter().filter(|s| !s.is_empty()).map(String::from)),
            Err(e) => log.push("strings", format!("dynstrtab illeggibile, saltata: {}", e)),
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
            } else {
                log.push(
                    "strings",
                    format!(".rodata offset/size fuori dai limiti del file (offset={}, size={}, filelen={})",
                        offset, size, raw_data.len()),
                );
            }
        }

        if strings.is_empty() {
            log.push(
                "strings",
                "nessuna stringa estratta da strtab/dynstrtab/.rodata",
            );
        }

        // cap a 2000, stesso limite del Python, per evitare costo quadratico
        // su regex applicate a corpus enormi
        let capped: Vec<&String> = strings.iter().take(2000).collect();

        Self::classify(&capped, strings.len())
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
