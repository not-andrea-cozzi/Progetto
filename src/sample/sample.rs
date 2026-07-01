use crate::features::{
    ApiImportFeature, ByteLevelFeature, ImageFeature, InstructionFeature, MetadataFeature,
    SampleFeature, TextureFeature,
};
use goblin::elf::Elf;
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

    pub fn extract(&mut self) -> Result<(), String> {
        self.features.byte_level = ByteLevelFeature::extract(&self.raw_data)?;

        let elf: Elf<'_> = Elf::parse(&self.raw_data)
            .map_err(|e: goblin::error::Error| format!("Cannot parse {}: {}", self.filename, e))?;

        self.features.metadata = MetadataFeature::extract(&elf, self.raw_data.len());
        self.features.instruction = InstructionFeature::extract(&elf, &self.raw_data)?;
        self.features.api_imports = ApiImportFeature::extract(&elf);

        let img: ImageFeature = ImageFeature::extract(&self.raw_data);
        self.features.texture = TextureFeature::extract(&img);

        Ok(())
    }
}
