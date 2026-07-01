use capstone::prelude::*;
use goblin::elf::Elf;
use goblin::elf::header::{EM_386, EM_AARCH64, EM_ARM, EM_X86_64};

#[derive(Debug, Default)]
pub struct InstructionFeature {
    pub instruction_density: f64,
    pub mov_ops_ratio: f64,
    pub arithmetic_ops_ratio: f64,
    pub logic_ops_ratio: f64,
    pub control_flow_ratio: f64,
    pub system_ops_ratio: f64,
}

enum Category {
    Mov,
    Arithmetic,
    Logic,
    ControlFlow,
    System,
    Other,
}

impl InstructionFeature {
    pub fn extract(elf: &Elf, raw_data: &[u8]) -> Result<Self, String> {
        let cs = Self::build_capstone(elf.header.e_machine)?;

        let (
            mut mov_count,
            mut arith_count,
            mut logic_count,
            mut control_count,
            mut system_count,
            mut total,
        ) = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);

        for section in &elf.section_headers {
            if section.sh_flags & 0x4 == 0 || section.sh_size == 0 {
                continue;
            }
            let start = section.sh_offset as usize;
            let end = start
                .saturating_add(section.sh_size as usize)
                .min(raw_data.len());
            if start >= end {
                continue;
            }
            let code = &raw_data[start..end];
            let Ok(instructions) = cs.disasm_all(code, section.sh_addr) else {
                continue;
            };

            for insn in instructions.iter() {
                total += 1;
                let mnemonic = insn.mnemonic().unwrap_or("").to_lowercase();
                match Self::categorize(&mnemonic) {
                    Category::Mov => mov_count += 1,
                    Category::Arithmetic => arith_count += 1,
                    Category::Logic => logic_count += 1,
                    Category::ControlFlow => control_count += 1,
                    Category::System => system_count += 1,
                    Category::Other => {}
                }
            }
        }

        let mut f = Self::default();
        if total > 0 {
            f.mov_ops_ratio = mov_count as f64 / total as f64;
            f.arithmetic_ops_ratio = arith_count as f64 / total as f64;
            f.logic_ops_ratio = logic_count as f64 / total as f64;
            f.control_flow_ratio = control_count as f64 / total as f64;
            f.system_ops_ratio = system_count as f64 / total as f64;
        }
        f.instruction_density = total as f64 / raw_data.len().max(1) as f64;
        Ok(f)
    }

    fn build_capstone(e_machine: u16) -> Result<Capstone, String> {
        let cs = match e_machine {
            EM_X86_64 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .build(),
            EM_386 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .build(),
            EM_AARCH64 => Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .build(),
            EM_ARM => Capstone::new().arm().mode(arch::arm::ArchMode::Arm).build(),
            other => return Err(format!("Architettura non supportata: e_machine={}", other)),
        };
        cs.map_err(|e| e.to_string())
    }

    fn categorize(mnemonic: &str) -> Category {
        match mnemonic {
            "mov" | "movzx" | "movsx" | "lea" | "push" | "pop" => Category::Mov,
            "add" | "sub" | "mul" | "imul" | "div" | "idiv" | "inc" | "dec" => Category::Arithmetic,
            "and" | "or" | "xor" | "not" | "shl" | "shr" | "sar" | "rol" | "ror" => Category::Logic,
            "jmp" | "je" | "jne" | "jz" | "jnz" | "jg" | "jl" | "jge" | "jle" | "call" | "ret"
            | "loop" => Category::ControlFlow,
            "syscall" | "sysenter" | "int" | "in" | "out" => Category::System,
            _ => Category::Other,
        }
    }
}
