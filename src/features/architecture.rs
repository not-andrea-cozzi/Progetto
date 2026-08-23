use goblin::elf::header::{EM_386, EM_AARCH64, EM_ARM, EM_X86_64};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ArchKind {
    X86,
    X86_64,
    Arm,
    Arm64,
    #[default]
    Unsupported,
}

impl ArchKind {
    pub fn from_e_machine(e_machine: u16) -> Self {
        match e_machine {
            EM_X86_64 => Self::X86_64,
            EM_386 => Self::X86,
            EM_AARCH64 => Self::Arm64,
            EM_ARM => Self::Arm,
            _ => Self::Unsupported,
        }
    }

    // ordine fisso per allineamento colonne CSV
    pub fn one_hot(&self) -> [u8; 5] {
        let mut v = [0u8; 5];
        v[match self {
            Self::X86 => 0,
            Self::X86_64 => 1,
            Self::Arm => 2,
            Self::Arm64 => 3,
            Self::Unsupported => 4,
        }] = 1;
        v
    }

    pub const CSV_COLS: [&'static str; 5] = [
        "arch_x86",
        "arch_x86_64",
        "arch_arm",
        "arch_arm64",
        "arch_unsupported",
    ];
}
