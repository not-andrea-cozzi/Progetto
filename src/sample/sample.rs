use crate::features::{
    ApiImportFeature, ByteLevelFeature, ImageFeature, InstructionFeature, MetadataFeature,
    PackingFeature, RelocationFeature, SampleFeature, StringFeature, StructuralFeature,
    TextureFeature, WarningLog,
};
use goblin::elf::Elf;
use image::GrayImage;
use std::{fs, path::PathBuf};

#[derive(Debug)]
pub struct Sample {
    pub filename: String,
    pub full_path: PathBuf,
    pub features: SampleFeature,
    pub raw_data: Vec<u8>,
}

impl Sample {
    pub fn new(filename: String, directory: String) -> Result<Self, String> {
        let mut sample = Self {
            filename,
            full_path: PathBuf::new(),
            features: SampleFeature::default(),
            raw_data: Vec::new(),
        };
        sample.read(directory)?;
        Ok(sample)
    }

    fn read(&mut self, directory: String) -> Result<(), String> {
        let path = PathBuf::from(directory).join(&self.filename);
        let data = fs::read(&path).map_err(|e| e.to_string())?;
        if data.is_empty() {
            return Err(format!("File {} is empty", self.filename));
        }
        self.full_path = path;
        self.raw_data = data;
        Ok(())
    }

    /// Solo due condizioni fanno fallire l'intero sample: file illeggibile da
    /// disco (gestito in `read`) o non parsabile come ELF (nessuna feature
    /// e' estraibile senza un ELF valido, quindi qui l'abort e' corretto).
    /// Ogni estrattore a valle del parsing ELF non ritorna mai un errore
    /// fatale: degrada a feature default con un warning accumulato in
    /// `log`, cosi' un campo corrotto isolato (string table, sezione non
    /// disassemblabile, relocation malformate...) non fa perdere l'intero
    /// sample — spesso e' proprio quel campo corrotto il segnale utile.
    pub fn extract(&mut self) -> Result<(), String> {
        let mut log = WarningLog::default();

        // ByteLevelFeature richiede solo raw_data non vuoto, gia' garantito
        // da `read`: extract() qui non puo' fallire nella pratica, ma il
        // tipo Result e' preservato per non toccare la sua firma pubblica.
        self.features.byte_level = ByteLevelFeature::extract(&self.raw_data).unwrap_or_else(|e| {
            log.push("byte_level", e);
            ByteLevelFeature::default()
        });

        let elf: Elf<'_> = Elf::parse(&self.raw_data)
            .map_err(|e: goblin::error::Error| format!("Cannot parse {}: {}", self.filename, e))?;

        self.features.metadata = MetadataFeature::extract(&elf, self.raw_data.len());
        let arch = self.features.metadata.arch;

        self.features.instruction =
            InstructionFeature::extract(&elf, &self.raw_data, arch, &mut log);

        self.features.api_imports = ApiImportFeature::extract(&elf);

        self.features.strings = StringFeature::extract(&elf, &self.raw_data, &mut log);

        self.features.structural =
            StructuralFeature::extract(&self.raw_data, &elf).unwrap_or_else(|e| {
                log.push("structural", e);
                StructuralFeature::default()
            });

        self.features.packing = PackingFeature::extract(&self.raw_data, &elf);
        self.features.relocation = RelocationFeature::extract(&elf, &self.raw_data, arch);

        let img: ImageFeature = ImageFeature::extract(&self.raw_data);
        self.features.texture = TextureFeature::extract(&img);

        if !log.is_empty() {
            log.eprint_all(&self.filename);
        }

        Ok(())
    }

    pub fn save_image(
        &self,
        output_dir: &str,
        width: u32,
        height: u32,
        file_name: &str,
    ) -> Result<(), String> {
        let target_size = (width * height) as usize;
        let mut image_buffer = vec![0u8; target_size];
        let bytes_to_copy = std::cmp::min(self.raw_data.len(), target_size);

        image_buffer[..bytes_to_copy].copy_from_slice(&self.raw_data[..bytes_to_copy]);

        let img = GrayImage::from_raw(width, height, image_buffer)
            .ok_or("Errore critico durante la costruzione del buffer immagine")?;

        let out_path = PathBuf::from(output_dir).join(file_name);

        img.save(&out_path)
            .map_err(|e| format!("Errore salvataggio immagine {}: {}", file_name, e))?;

        Ok(())
    }
}
