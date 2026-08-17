use goblin::elf::Elf;
use goblin::elf::program_header::{PF_W, PF_X};
use goblin::elf::section_header::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS};

#[derive(Debug, Default)]
pub struct StructuralFeature {
    pub section_count: usize,
    pub segment_count: usize,
    pub rwx_section_count: usize,
    pub wx_segment_count: usize,
    pub max_section_entropy: f64,
    pub avg_section_entropy: f64,
    pub empty_section_count: usize,
    pub code_to_data_ratio: f64,
}

impl StructuralFeature {
    pub fn extract(raw_data: &[u8], elf: &Elf) -> Result<Self, String> {
        let mut feature: StructuralFeature = Self::default();

        feature.segment_count = elf.program_headers.len();
        for ph in &elf.program_headers {
            if (ph.p_flags & (PF_W | PF_X)) == (PF_W | PF_X) {
                feature.wx_segment_count += 1;
            }
        }

        // 2. Analisi delle Sezioni (Section Headers)
        feature.section_count = elf.section_headers.len();

        let mut total_entropy: f64 = 0.0;
        let mut valid_sections_for_entropy: i32 = 0;
        let mut code_size: f64 = 0.0;
        let mut data_size: f64 = 0.0;

        for sh in &elf.section_headers {
            let flags = sh.sh_flags;

            if sh.sh_size == 0 || sh.sh_type == SHT_NOBITS {
                feature.empty_section_count += 1;
                continue;
            }

            // Verifica permessi RWX (Lettura è implicita, controlliamo Scrittura ed Esecuzione)
            let is_writable = (flags & u64::from(SHF_WRITE)) != 0;
            let is_executable = (flags & u64::from(SHF_EXECINSTR)) != 0;

            if is_writable && is_executable {
                feature.rwx_section_count += 1;
            }

            if (flags & u64::from(SHF_ALLOC)) != 0 {
                if is_executable {
                    code_size += sh.sh_size as f64;
                } else {
                    data_size += sh.sh_size as f64;
                }
            }

            let offset: usize = sh.sh_offset as usize;
            let size: usize = sh.sh_size as usize;

            if offset.saturating_add(size) <= raw_data.len() {
                let section_data = &raw_data[offset..offset + size];
                let entropy = Self::calculate_shannon_entropy(section_data);

                if entropy > feature.max_section_entropy {
                    feature.max_section_entropy = entropy;
                }

                total_entropy += entropy;
                valid_sections_for_entropy += 1;
            }
        }

        if valid_sections_for_entropy > 0 {
            feature.avg_section_entropy = total_entropy / (valid_sections_for_entropy as f64);
        }

        feature.code_to_data_ratio = code_size / (data_size + 1.0);

        Ok(feature)
    }

    fn calculate_shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts: [usize; 256] = [0usize; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let total_bytes: f64 = data.len() as f64;
        let mut entropy: f64 = 0.0;

        for &count in &counts {
            if count > 0 {
                let p: f64 = count as f64 / total_bytes;
                entropy -= p * p.log2();
            }
        }

        entropy
    }
}
