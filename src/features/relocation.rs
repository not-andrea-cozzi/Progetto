// src/features/relocation.rs
use super::architecture::ArchKind;
use goblin::elf::Elf;

#[derive(Debug, Default)]
pub struct RelocationFeature {
    pub reloc_dyn_count: usize,
    pub reloc_plt_count: usize,
    pub nonstandard_reloc_type_count: usize,
    pub reloc_total_to_filesize_ratio: f64,
}

impl RelocationFeature {
    pub fn extract(elf: &Elf, raw_data: &[u8], arch: ArchKind) -> Self {
        let mut f = Self::default();

        // dynrelas (RELA) e dynrels (REL) sono entrambi Vec<Reloc>/RelocSection
        // su Elf<'_> in goblin 0.8: il parser sceglie quale popolare in base
        // al formato usato dal linker per quel binario. pltrelocs e' sempre
        // popolato correttamente indipendentemente da RELA/REL, il parser
        // interno lo risolve gia' in base a DT_PLTREL.
        f.reloc_dyn_count = elf.dynrelas.len() + elf.dynrels.len();
        f.reloc_plt_count = elf.pltrelocs.len();

        let standard_types = Self::standard_reloc_types(arch);

        f.nonstandard_reloc_type_count = elf
            .dynrelas
            .iter()
            .chain(elf.dynrels.iter())
            .chain(elf.pltrelocs.iter())
            .filter(|r| !standard_types.contains(&r.r_type))
            .count();

        let total_relocs = f.reloc_dyn_count + f.reloc_plt_count;
        if !raw_data.is_empty() {
            f.reloc_total_to_filesize_ratio = total_relocs as f64 / raw_data.len() as f64;
        }

        f
    }

    fn standard_reloc_types(arch: ArchKind) -> &'static [u32] {
        match arch {
            // R_X86_64_RELATIVE=8, GLOB_DAT=6, JUMP_SLOT=7, 64=1, PC32=2
            ArchKind::X86_64 => &[1, 2, 6, 7, 8],
            // R_386_32=1, PC32=2, GLOB_DAT=6, JMP_SLOT=7, RELATIVE=8
            ArchKind::X86 => &[1, 2, 6, 7, 8],
            // R_AARCH64_RELATIVE=1027, GLOB_DAT=1025, JUMP_SLOT=1026, ABS64=257
            ArchKind::Arm64 => &[257, 1025, 1026, 1027],
            // R_ARM_ABS32=2, GLOB_DAT=21, JUMP_SLOT=22, RELATIVE=23
            ArchKind::Arm => &[2, 21, 22, 23],
            ArchKind::Unsupported => &[],
        }
    }
}
