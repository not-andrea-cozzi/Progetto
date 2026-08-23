use Progetto::sample::Sample;
use rand::seq::SliceRandom;
use std::sync::Arc;
use tokio::fs;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

const CONCURRENCY: usize = 8;
const TRAIN_FRAC: f64 = 0.70;
const VAL_FRAC: f64 = 0.15;
// TEST_FRAC = resto (0.15)

struct Row {
    filename: String,
    image_name: String,
    label: u8,
    feature_line: String,
}

struct Pipeline {
    directory_malware: String,
    directory_goodware: String,
    directory_images: String,
    file_train: String,
    file_val: String,
    file_test: String,
}

impl Pipeline {
    async fn run(&self) -> Result<(), String> {
        fs::create_dir_all(&self.directory_images)
            .await
            .map_err(|e| e.to_string())?;

        let malware = self.process_dir(&self.directory_malware, 1).await?;
        let goodware = self.process_dir(&self.directory_goodware, 0).await?;

        eprintln!(
            "Estratti {} campioni malware, {} campioni goodware.",
            malware.len(),
            goodware.len()
        );

        let (train, val, test) = Self::stratified_split(malware, goodware);

        self.write_csv(&self.file_train, &train).await?;
        self.write_csv(&self.file_val, &val).await?;
        self.write_csv(&self.file_test, &test).await?;

        println!(
            "Split completato -> train: {}, val: {}, test: {}",
            train.len(),
            val.len(),
            test.len()
        );
        Ok(())
    }

    async fn process_dir(&self, dir: &str, label: u8) -> Result<Vec<Row>, String> {
        let mut entries = fs::read_dir(dir)
            .await
            .map_err(|e| format!("{}: {}", dir, e))?;

        let mut filenames = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(|e| e.to_string())? {
            if entry.path().is_dir() {
                continue;
            }
            filenames.push(entry.file_name().to_string_lossy().to_string());
        }

        let semaphore = Arc::new(Semaphore::new(CONCURRENCY));
        let mut tasks: JoinSet<Option<Row>> = JoinSet::new();

        for filename in filenames {
            let sem = Arc::clone(&semaphore);
            let dir = dir.to_string();
            let images_dir = self.directory_images.clone();

            tasks.spawn(async move {
                // Il permesso resta acquisito per tutta la durata del task:
                // limita a CONCURRENCY il numero di file lavorati in parallelo.
                let _permit = sem.acquire_owned().await.expect("semaforo chiuso");

                tokio::task::spawn_blocking(move || {
                    Self::process_one(filename, dir, images_dir, label)
                })
                .await
                .unwrap_or_else(|e| {
                    eprintln!("Task terminato in panic: {}", e);
                    None
                })
            });
        }

        let mut rows = Vec::new();
        while let Some(result) = tasks.join_next().await {
            if let Ok(Some(row)) = result {
                rows.push(row);
            }
        }
        Ok(rows)
    }

    /// Lavoro sincrono/CPU-bound: invariato rispetto all'originale,
    /// eseguito dentro spawn_blocking. Sample non attraversa mai un .await.
    fn process_one(filename: String, dir: String, images_dir: String, label: u8) -> Option<Row> {
        let mut sample = match Sample::new(filename.clone(), dir) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Errore inizializzazione {}: {}", filename, e);
                return None;
            }
        };

        if let Err(e) = sample.extract() {
            eprintln!("Errore estrazione {}: {}", filename, e);
            return None;
        }

        let sample_tag = if label == 1 { "malware" } else { "goodware" };
        let image_name = format!("{}_{}.png", filename, sample_tag);

        if let Err(e) = sample.save_image(&images_dir, 224, 224, &image_name) {
            eprintln!("Errore creazione immagine per {}: {}", image_name, e);
        }

        let feature_line = Self::feature_row(&sample);

        Some(Row {
            filename,
            image_name,
            label,
            feature_line,
        })
    }

    /// Shuffle indipendente per classe, poi taglio 70/15/15 per ciascuna
    /// (split stratificato: mantiene il rapporto malware/goodware in ogni set).
    /// Il resto dell'arrotondamento finisce sempre nel test set, quindi la
    /// somma dei tre set combacia esattamente con il totale per classe.
    fn stratified_split(malware: Vec<Row>, goodware: Vec<Row>) -> (Vec<Row>, Vec<Row>, Vec<Row>) {
        let mut rng = rand::rng();

        let mut malware = malware;
        let mut goodware = goodware;
        malware.shuffle(&mut rng);
        goodware.shuffle(&mut rng);

        let mut train = Vec::new();
        let mut val = Vec::new();
        let mut test = Vec::new();

        for mut class in [malware, goodware] {
            let n = class.len();
            let n_train = ((n as f64) * TRAIN_FRAC).round() as usize;
            let n_val = ((n as f64) * VAL_FRAC).round() as usize;

            // split_off SPOSTA gli elementi (nessun bound Clone necessario)
            let mut rest = class.split_off(n_train.min(n));
            let test_part = rest.split_off(n_val.min(rest.len()));

            train.extend(class);
            val.extend(rest);
            test.extend(test_part);
        }

        train.shuffle(&mut rng);
        val.shuffle(&mut rng);
        test.shuffle(&mut rng);

        (train, val, test)
    }

    async fn write_csv(&self, path: &str, rows: &[Row]) -> Result<(), String> {
        let file = fs::File::create(path).await.map_err(|e| e.to_string())?;
        let mut out = BufWriter::new(file);

        let header = format!("filename,image_name,label,{}\n", Self::header());
        out.write_all(header.as_bytes())
            .await
            .map_err(|e| e.to_string())?;

        for row in rows {
            let line = format!(
                "{},{},{},{}\n",
                row.filename, row.image_name, row.label, row.feature_line
            );
            out.write_all(line.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
        }

        out.flush().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    // --- Invariate rispetto all'originale, salvo aggiunte in coda ---

    fn header() -> String {
        let mut cols = vec!["global_entropy".to_string()];
        cols.extend((0..256).map(|i| format!("byte_{}", i)));
        cols.extend(
            [
                "is_64_bit",
                "is_shared_object",
                "entry_point_offset_ratio",
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
                "string_count",
                "avg_string_length",
                "net_indicators",
                "susp_paths",
                "section_count",
                "segment_count",
                "rwx_sections",
                "wx_segments",
                "max_sect_entropy",
                "avg_sect_entropy",
                "empty_sect_count",
                "code_data_ratio",
            ]
            .iter()
            .map(|s| s.to_string()),
        );
        cols.extend((0..256).map(|i| format!("lbp_{}", i)));

        // --- Nuove colonne: packing, relocation, arch one-hot ---
        cols.extend(
            [
                "file_to_section_size_ratio",
                "section_table_inconsistent",
                "entry_point_outside_text",
                "nonstandard_section_name_count",
                "known_packer_signature_found",
                "reloc_dyn_count",
                "reloc_plt_count",
                "nonstandard_reloc_type_count",
                "reloc_total_to_filesize_ratio",
            ]
            .iter()
            .map(|s| s.to_string()),
        );
        cols.extend(
            Progetto::features::ArchKind::CSV_COLS
                .iter()
                .map(|s| s.to_string()),
        );

        cols.join(",")
    }

    fn feature_row(sample: &Sample) -> String {
        let f = &sample.features;
        let mut vals: Vec<String> = vec![f.byte_level.global_entropy.to_string()];
        vals.extend(f.byte_level.bytes.iter().map(|v| v.to_string()));

        vals.extend([
            (f.metadata.is_64_bit as u8).to_string(),
            (f.metadata.is_shared_object as u8).to_string(),
            f.metadata.entry_point_offset_ratio.to_string(),
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
            f.strings.string_count.to_string(),
            f.strings.avg_string_length.to_string(),
            f.strings.network_indicators_count.to_string(),
            f.strings.suspicious_paths_count.to_string(),
            f.structural.section_count.to_string(),
            f.structural.segment_count.to_string(),
            f.structural.rwx_section_count.to_string(),
            f.structural.wx_segment_count.to_string(),
            f.structural.max_section_entropy.to_string(),
            f.structural.avg_section_entropy.to_string(),
            f.structural.empty_section_count.to_string(),
            f.structural.code_to_data_ratio.to_string(),
        ]);

        vals.extend(f.texture.lbp_histogram.iter().map(|v| v.to_string()));

        // --- Nuovi valori: packing, relocation, arch one-hot ---
        vals.extend([
            f.packing.file_to_section_size_ratio.to_string(),
            (f.packing.section_table_inconsistent as u8).to_string(),
            (f.packing.entry_point_outside_text as u8).to_string(),
            f.packing.nonstandard_section_name_count.to_string(),
            (f.packing.known_packer_signature_found as u8).to_string(),
            f.relocation.reloc_dyn_count.to_string(),
            f.relocation.reloc_plt_count.to_string(),
            f.relocation.nonstandard_reloc_type_count.to_string(),
            f.relocation.reloc_total_to_filesize_ratio.to_string(),
        ]);
        vals.extend(f.metadata.arch.one_hot().iter().map(|v| v.to_string()));

        vals.join(",")
    }
}

#[tokio::main]
async fn main() {
    let pipeline = Pipeline {
        directory_malware: "samples/malware".to_string(),
        directory_goodware: "samples/goodware".to_string(),
        directory_images: "dataset_images".to_string(),
        file_train: "dataset_train.csv".to_string(),
        file_val: "dataset_val.csv".to_string(),
        file_test: "dataset_test.csv".to_string(),
    };

    if let Err(e) = pipeline.run().await {
        eprintln!("Errore critico nella pipeline: {}", e);
        std::process::exit(1);
    }
}
