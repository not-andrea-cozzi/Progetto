use goblin::elf::Elf;
use std::collections::HashSet;

#[derive(Debug, Default)]
pub struct ApiImportFeature {
    pub dynamic_library_count: usize,
    pub total_import_count: usize,
    pub network_api_count: usize,
    pub process_api_count: usize,
    pub file_io_api_count: usize,
}

impl ApiImportFeature {
    pub fn extract(elf: &Elf) -> Self {
        let imported: HashSet<&str> = elf
            .dynsyms
            .iter()
            .filter(|s| s.st_name != 0)
            .filter_map(|s| elf.dynstrtab.get_at(s.st_name))
            .filter(|n| !n.is_empty())
            .collect();

        let file_io: HashSet<&str> = ["open", "read", "write", "close", "unlink", "stat", "fstat"]
            .into_iter()
            .collect();
        let network: HashSet<&str> = [
            "socket", "connect", "bind", "listen", "accept", "send", "recv",
        ]
        .into_iter()
        .collect();
        let process: HashSet<&str> = ["fork", "exec", "execve", "kill", "waitpid", "getpid"]
            .into_iter()
            .collect();

        Self {
            dynamic_library_count: elf.libraries.len(),
            total_import_count: imported.len(),
            file_io_api_count: imported.intersection(&file_io).count(),
            network_api_count: imported.intersection(&network).count(),
            process_api_count: imported.intersection(&process).count(),
        }
    }
}
