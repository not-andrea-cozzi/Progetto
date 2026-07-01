use Progetto::sample::Sample;
use std::fs;
use std::io::Write;

struct Pipeline {
    directory_malware: String,
    directory_goodware: String,
    file_output: String,
}

impl Pipeline {
    fn run(&self) -> Result<(), String> {
        let mut out = fs::File::create(&self.file_output).map_err(|e| e.to_string())?;
        writeln!(out, "filename,label,{}", Self::header()).map_err(|e| e.to_string())?;

        self.process_dir(&self.directory_malware, 1, &mut out)?;
        self.process_dir(&self.directory_goodware, 0, &mut out)?;
        Ok(())
    }

    fn process_dir(&self, dir: &str, label: u8, out: &mut fs::File) -> Result<(), String> {
        let entries = fs::read_dir(dir).map_err(|e| format!("{}: {}", dir, e))?;

        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let filename = entry.file_name().to_string_lossy().to_string();

            let mut sample = match Sample::new(filename.clone(), dir.to_string()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("skip {}: {}", filename, e);
                    continue;
                }
            };

            if let Err(e) = sample.extract() {
                eprintln!("skip {}: {}", filename, e);
                continue;
            }

            let row = Self::feature_row(&sample);
            writeln!(out, "{},{},{}", filename, label, row).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn header() -> String {
        let mut cols = vec!["global_entropy".to_string()];
        cols.extend((0..256).map(|i| format!("byte_{}", i)));
        cols.extend(
            [
                "is_64_bit",
                "is_shared_object",
                "entry_point_addr",
                "is_stripped",
                "mov_ratio",
                "arith_ratio",
                "logic_ratio",
                "control_flow_ratio",
                "system_ratio",
                "instr_density",
                "dyn_lib_count",
                "total_import_count",
                "file_io_api",
                "network_api",
                "process_api",
                "block_entropy_mean",
                "block_entropy_std",
                "edge_density",
                "glcm_contrast",
                "glcm_homogeneity",
                "glcm_energy",
            ]
            .iter()
            .map(|s| s.to_string()),
        );
        cols.extend((0..256).map(|i| format!("lbp_{}", i)));
        cols.join(",")
    }

    fn feature_row(sample: &Sample) -> String {
        let f = &sample.features;
        let mut vals: Vec<String> = vec![f.byte_level.global_entropy.to_string()];
        vals.extend(f.byte_level.bytes.iter().map(|v| v.to_string()));
        vals.extend([
            (f.metadata.is_64_bit as u8).to_string(),
            (f.metadata.is_shared_object as u8).to_string(),
            f.metadata.entry_point_addr.to_string(),
            (f.metadata.is_stripped as u8).to_string(),
            f.instruction.mov_ops_ratio.to_string(),
            f.instruction.arithmetic_ops_ratio.to_string(),
            f.instruction.logic_ops_ratio.to_string(),
            f.instruction.control_flow_ratio.to_string(),
            f.instruction.system_ops_ratio.to_string(),
            f.instruction.instruction_density.to_string(),
            f.api_imports.dynamic_library_count.to_string(),
            f.api_imports.total_import_count.to_string(),
            f.api_imports.file_io_api_count.to_string(),
            f.api_imports.network_api_count.to_string(),
            f.api_imports.process_api_count.to_string(),
            f.texture.block_entropy_mean.to_string(),
            f.texture.block_entropy_std.to_string(),
            f.texture.edge_density.to_string(),
            f.texture.glcm_contrast.to_string(),
            f.texture.glcm_homogeneity.to_string(),
            f.texture.glcm_energy.to_string(),
        ]);
        vals.extend(f.texture.lbp_histogram.iter().map(|v| v.to_string()));
        vals.join(",")
    }
}

fn main() {
    let pipeline = Pipeline {
        directory_malware: "samples/goodware".to_string(),
        directory_goodware: "samples/malware/Linux-Malware-Samples".to_string(),
        file_output: "dataset.csv".to_string(),
    };

    if let Err(e) = pipeline.run() {
        eprintln!("pipeline error: {}", e);
        std::process::exit(1);
    }

    println!("dataset scritto");
}
