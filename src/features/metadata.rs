// src/features/metadata.rs
use goblin::elf::{Elf, header::ET_DYN};

use super::architecture::ArchKind;

#[derive(Debug, Default)]
pub struct MetadataFeature {
    pub file_size: usize,
    pub is_64_bit: bool,
    pub is_shared_object: bool,
    pub entry_point_offset_ratio: f64,
    pub entry_point_last_section: bool,
    pub is_stripped: bool,
    pub arch: ArchKind,
}

impl MetadataFeature {
    pub fn extract(elf: &Elf, file_size: usize) -> Self {
        let mut feature: MetadataFeature = Self::default();
        feature.file_size = file_size;
        feature.is_64_bit = elf.is_64;
        feature.is_shared_object = elf.header.e_type == ET_DYN;
        feature.is_stripped = elf.syms.is_empty() && elf.dynsyms.is_empty();
        feature.entry_point_offset_ratio = Self::entry_point_offset_ratio(elf);
        feature.entry_point_last_section = Self::check_last_section_entry_point(elf);
        feature.arch = ArchKind::from_e_machine(elf.header.e_machine);
        feature
    }

    /// Posizione dell'entry point come frazione [0,1] all'interno della sezione che lo
    /// contiene, invece dell'indirizzo assoluto: con ASLR/PIE l'indirizzo grezzo varia
    /// tra binari altrimenti identici e non generalizza. 0.0 se nessuna sezione lo contiene.
    fn entry_point_offset_ratio(elf: &Elf) -> f64 {
        let entry: u64 = elf.header.e_entry;
        for section in &elf.section_headers {
            if section.sh_size == 0 {
                continue;
            }
            let start = section.sh_addr;
            let end = start.saturating_add(section.sh_size);
            if entry >= start && entry < end {
                return (entry - start) as f64 / section.sh_size as f64;
            }
        }
        0.0
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
