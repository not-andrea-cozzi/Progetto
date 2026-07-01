// src/features/metadata.rs
use goblin::elf::{Elf, header::ET_DYN};

#[derive(Debug, Default)]
pub struct MetadataFeature {
    pub file_size: usize,
    pub is_64_bit: bool,
    pub is_shared_object: bool,
    pub entry_point_addr: u64,
    pub entry_point_last_section: bool,
    pub is_stripped: bool,
}

impl MetadataFeature {
    pub fn extract(elf: &Elf, file_size: usize) -> Self {
        let mut feature = Self::default();
        feature.file_size = file_size;
        feature.is_64_bit = elf.is_64;
        feature.is_shared_object = elf.header.e_type == ET_DYN;
        feature.is_stripped = elf.syms.is_empty();
        feature.entry_point_addr = elf.header.e_entry;
        feature.entry_point_last_section = Self::check_last_section_entry_point(elf);
        feature
    }

    fn check_last_section_entry_point(elf: &Elf) -> bool {
        let entry = elf.header.e_entry;
        let mut last_section_addr_start: u64 = 0;
        let mut last_section_addr_end: u64 = 0;
        let mut last_section_file_offset: u64 = 0;
        for section in &elf.section_headers {
            if section.sh_flags & 2 != 0
                && section.sh_size > 0
                && section.sh_offset >= last_section_file_offset
            {
                last_section_file_offset = section.sh_offset;
                last_section_addr_start = section.sh_addr;
                last_section_addr_end = section.sh_addr.saturating_add(section.sh_size);
            }
        }
        if last_section_addr_end == 0 {
            return false;
        }
        entry >= last_section_addr_start && entry < last_section_addr_end
    }
}
