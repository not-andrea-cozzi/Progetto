// src/features/mod.rs
pub mod api_imports;
pub mod byte_image;
pub mod byte_level;
pub mod instruction;
pub mod metadata;
pub mod strings;
pub mod structural;
pub mod texture;

pub use api_imports::ApiImportFeature;
pub use byte_image::ImageFeature;
pub use byte_level::ByteLevelFeature;
pub use instruction::InstructionFeature;
pub use metadata::MetadataFeature;
pub use strings::StringFeature;
pub use structural::StructuralFeature;
pub use texture::TextureFeature;

#[derive(Debug, Default)]
pub struct SampleFeature {
    pub byte_level: ByteLevelFeature,
    pub metadata: MetadataFeature,
    pub structural: StructuralFeature,
    pub instruction: InstructionFeature,
    pub api_imports: ApiImportFeature,
    pub strings: StringFeature,
    pub texture: TextureFeature,
}
