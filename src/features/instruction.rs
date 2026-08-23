use capstone::prelude::*;
use goblin::elf::Elf;

use super::architecture::ArchKind;
use super::extraction_warnings::WarningLog;

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
    /// Non ritorna mai Err: arch non supportata da capstone o disasm fallito
    /// su una sezione producono feature azzerate con un warning, mai
    /// l'abort dell'intero sample.
    pub fn extract(elf: &Elf, raw_data: &[u8], arch: ArchKind, log: &mut WarningLog) -> Self {
        let mut f = Self::default();

        let cs = match Self::build_capstone(arch) {
            Some(cs) => cs,
            None => {
                log.push(
                    "instruction",
                    format!("nessun supporto capstone per {:?}, feature azzerate", arch),
                );
                return f;
            }
        };

        let (mut mov_c, mut arith_c, mut logic_c, mut ctrl_c, mut sys_c, mut total) =
            (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
        let mut sections_failed = 0usize;

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

            match cs.disasm_all(&raw_data[start..end], section.sh_addr) {
                Ok(instructions) => {
                    for insn in instructions.iter() {
                        total += 1;
                        let mnemonic = insn.mnemonic().unwrap_or("").to_lowercase();
                        match Self::categorize(&mnemonic, arch) {
                            Category::Mov => mov_c += 1,
                            Category::Arithmetic => arith_c += 1,
                            Category::Logic => logic_c += 1,
                            Category::ControlFlow => ctrl_c += 1,
                            Category::System => sys_c += 1,
                            Category::Other => {}
                        }
                    }
                }
                Err(_) => sections_failed += 1,
            }
        }

        if sections_failed > 0 {
            log.push(
                "instruction",
                format!(
                    "{} sezioni eseguibili non disassemblabili, saltate",
                    sections_failed
                ),
            );
        }

        if total > 0 {
            f.mov_ops_ratio = mov_c as f64 / total as f64;
            f.arithmetic_ops_ratio = arith_c as f64 / total as f64;
            f.logic_ops_ratio = logic_c as f64 / total as f64;
            f.control_flow_ratio = ctrl_c as f64 / total as f64;
            f.system_ops_ratio = sys_c as f64 / total as f64;
        }
        f.instruction_density = total as f64 / raw_data.len().max(1) as f64;
        f
    }

    fn build_capstone(arch: ArchKind) -> Option<Capstone> {
        let cs = match arch {
            ArchKind::X86_64 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .build(),
            ArchKind::X86 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .build(),
            ArchKind::Arm64 => Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .build(),
            ArchKind::Arm => Capstone::new().arm().mode(arch::arm::ArchMode::Arm).build(),
            ArchKind::Unsupported => return None,
        };
        cs.ok()
    }

    fn categorize(mnemonic: &str, arch: ArchKind) -> Category {
        match arch {
            ArchKind::X86 | ArchKind::X86_64 => Self::categorize_x86(mnemonic),
            ArchKind::Arm => Self::categorize_arm(mnemonic),
            ArchKind::Arm64 => Self::categorize_arm64(mnemonic),
            ArchKind::Unsupported => Category::Other,
        }
    }

    fn categorize_x86(m: &str) -> Category {
        match m {
            "mov" | "movzx" | "movsx" | "lea" | "push" | "pop" => Category::Mov,
            "add" | "sub" | "mul" | "imul" | "div" | "idiv" | "inc" | "dec" => Category::Arithmetic,
            "and" | "or" | "xor" | "not" | "shl" | "shr" | "sar" | "rol" | "ror" => Category::Logic,
            "jmp" | "je" | "jne" | "jz" | "jnz" | "jg" | "jl" | "jge" | "jle" | "call" | "ret"
            | "loop" => Category::ControlFlow,
            "syscall" | "sysenter" | "int" | "in" | "out" => Category::System,
            _ => Category::Other,
        }
    }

    fn categorize_arm(m: &str) -> Category {
        match m {
            "mov" | "movw" | "movt" | "mvn" | "ldr" | "str" | "ldm" | "stm" | "push" | "pop"
            | "ldrb" | "strb" | "ldrh" | "strh" => Category::Mov,
            "add" | "sub" | "mul" | "mla" | "sdiv" | "udiv" | "adc" | "sbc" | "rsb" => {
                Category::Arithmetic
            }
            "and" | "orr" | "eor" | "bic" | "lsl" | "lsr" | "asr" | "ror" => Category::Logic,
            "b" | "bl" | "bx" | "blx" | "cbz" | "cbnz" => Category::ControlFlow,
            "svc" | "swi" | "mrc" | "mcr" => Category::System,
            _ => Category::Other,
        }
    }

    fn categorize_arm64(m: &str) -> Category {
        if m.starts_with("b.") {
            return Category::ControlFlow;
        }
        match m {
            "mov" | "movz" | "movn" | "movk" | "ldr" | "str" | "ldp" | "stp" | "ldur" | "stur"
            | "adr" | "adrp" | "ldrb" | "strb" | "ldrh" | "strh" => Category::Mov,
            "add" | "sub" | "mul" | "madd" | "msub" | "sdiv" | "udiv" | "adc" | "sbc" => {
                Category::Arithmetic
            }
            "and" | "orr" | "eor" | "mvn" | "bic" | "lsl" | "lsr" | "asr" | "ror" => {
                Category::Logic
            }
            "b" | "bl" | "br" | "blr" | "ret" | "cbz" | "cbnz" | "tbz" | "tbnz" => {
                Category::ControlFlow
            }
            "svc" | "hvc" | "smc" | "brk" => Category::System,
            _ => Category::Other,
        }
    }
}
