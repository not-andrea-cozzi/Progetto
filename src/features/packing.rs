// src/features/packing.rs
use goblin::elf::Elf;
use goblin::elf::section_header::SHF_ALLOC;

#[derive(Debug, Default)]
pub struct PackingFeature {
    /// filesize / somma(sh_size sezioni allocate). Un packer spesso comprime
    /// il payload in una sezione unica: rapporto file/sezioni-dichiarate anomalo
    /// rispetto a binari compilati normalmente.
    pub file_to_section_size_ratio: f64,
    /// true se e_shoff (offset section header table) e' oltre la fine del file,
    /// o se il numero di sezioni dichiarato non e' consistente con la dimensione
    /// file: molti packer troncano/corrompono la section table dopo il packing
    /// pur lasciando validi i program header (necessari al loader).
    pub section_table_inconsistent: bool,
    /// entry point in una sezione diversa dall'ultima per indirizzo E diversa
    /// da .text: pattern tipico di stub di unpacking iniettato.
    pub entry_point_outside_text: bool,
    /// numero di sezioni con nome non in whitelist standard (non .text/.data/
    /// .bss/.rodata/...). Cross-arch: i nomi sezione sono convenzione ELF/toolchain,
    /// non dipendono da e_machine.
    pub nonstandard_section_name_count: usize,
    /// match di firme testuali note di packer comuni, cercate nei bytes grezzi.
    /// Segnale forte quando presente, ma la sua assenza non esclude packing
    /// (packer custom non lascia firme).
    pub known_packer_signature_found: bool,
}

const STANDARD_SECTION_NAMES: &[&str] = &[
    ".text",
    ".data",
    ".bss",
    ".rodata",
    ".init",
    ".fini",
    ".plt",
    ".got",
    ".got.plt",
    ".dynamic",
    ".dynsym",
    ".dynstr",
    ".symtab",
    ".strtab",
    ".shstrtab",
    ".interp",
    ".hash",
    ".gnu.hash",
    ".comment",
    ".note",
    ".eh_frame",
    ".eh_frame_hdr",
    ".init_array",
    ".fini_array",
    ".rela.dyn",
    ".rela.plt",
    ".tbss",
    ".tdata",
    ".gnu.version",
    ".gnu.version_r",
    ".gnu.version_d",
    ".ctors",
    ".dtors",
    ".jcr",
    ".rodata1",
    ".data1",
];

// firme testuali di packer/protector comuni. Ricerca substring sui raw bytes,
// non richiede parsing sezioni (funziona anche su section table corrotta).
const KNOWN_PACKER_SIGNATURES: &[&[u8]] = &[
    b"UPX!",
    b".upx0",
    b".upx1",
    b".upx2",
    b"$Info: This file is packed",
    b"ASPack",
    b"PECompact",
    b"FSG!",
    b"MPRESS",
];

impl PackingFeature {
    pub fn extract(raw_data: &[u8], elf: &Elf) -> Self {
        let mut f = Self::default();

        f.file_to_section_size_ratio = Self::file_to_section_ratio(raw_data, elf);
        f.section_table_inconsistent = Self::check_section_table_consistency(raw_data, elf);
        f.entry_point_outside_text = Self::check_entry_point_outside_text(elf);
        f.nonstandard_section_name_count = Self::count_nonstandard_names(elf);
        f.known_packer_signature_found = Self::scan_known_signatures(raw_data);

        f
    }

    fn file_to_section_ratio(raw_data: &[u8], elf: &Elf) -> f64 {
        let allocated_size: u64 = elf
            .section_headers
            .iter()
            .filter(|sh| (sh.sh_flags & u64::from(SHF_ALLOC)) != 0)
            .map(|sh| sh.sh_size)
            .sum();

        if allocated_size == 0 {
            return 0.0;
        }
        raw_data.len() as f64 / allocated_size as f64
    }

    /// Verifica che la section header table dichiarata nell'header ELF sia
    /// effettivamente contenuta nel file. e_shoff + e_shnum*e_shentsize oltre
    /// la fine del file e' il pattern classico di section table azzerata/rimossa
    /// da un packer (il loader OS ignora le section header, solo i program
    /// header contano a runtime, quindi il binario resta eseguibile).
    fn check_section_table_consistency(raw_data: &[u8], elf: &Elf) -> bool {
        let shoff = elf.header.e_shoff;
        let shnum = elf.header.e_shnum as u64;
        let shentsize = elf.header.e_shentsize as u64;

        if shnum == 0 {
            // nessuna sezione dichiarata: legittimo solo se anche program
            // header sono coerenti, ma qui segnaliamo comunque come
            // inconsistente perche' un binario compilato normalmente ha
            // sempre sezioni.
            return true;
        }

        let table_end = shoff.saturating_add(shnum.saturating_mul(shentsize));
        table_end > raw_data.len() as u64
    }

    fn check_entry_point_outside_text(elf: &Elf) -> bool {
        let entry = elf.header.e_entry;

        let text_section = elf
            .section_headers
            .iter()
            .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".text"));

        let Some(text) = text_section else {
            // niente .text (binario stripped/section-less): non possiamo
            // affermare "fuori da .text", quindi non e' un segnale valido.
            return false;
        };

        let start = text.sh_addr;
        let end = start.saturating_add(text.sh_size);
        !(entry >= start && entry < end)
    }

    fn count_nonstandard_names(elf: &Elf) -> usize {
        elf.section_headers
            .iter()
            .filter(|sh| {
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
                !name.is_empty() && !STANDARD_SECTION_NAMES.contains(&name)
            })
            .count()
    }

    fn scan_known_signatures(raw_data: &[u8]) -> bool {
        KNOWN_PACKER_SIGNATURES
            .iter()
            .any(|sig| Self::contains_bytes(raw_data, sig))
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || haystack.len() < needle.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
