#[derive(Debug, Clone)]
pub struct ExtractionWarning {
    pub module: &'static str,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct WarningLog {
    pub warnings: Vec<ExtractionWarning>,
}

impl WarningLog {
    pub fn push(&mut self, module: &'static str, message: impl Into<String>) {
        self.warnings.push(ExtractionWarning {
            module,
            message: message.into(),
        });
    }

    pub fn is_empty(&self) -> bool {
        self.warnings.is_empty()
    }

    pub fn eprint_all(&self, filename: &str) {
        for w in &self.warnings {
            eprintln!("[warn] {} :: {}: {}", filename, w.module, w.message);
        }
    }
}
