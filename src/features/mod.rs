// src/features/mod.rs
pub mod api_imports;
pub mod architecture;
pub mod byte_image;
pub mod byte_level;
pub mod extraction_warnings;
pub mod instruction;
pub mod metadata;
pub mod packing;
pub mod relocation;
pub mod strings;
pub mod structural;
pub mod texture;

pub use api_imports::ApiImportFeature;
pub use architecture::ArchKind;
pub use byte_image::ImageFeature;
pub use byte_level::ByteLevelFeature;
pub use extraction_warnings::{ExtractionWarning, WarningLog};
pub use instruction::InstructionFeature;
pub use metadata::MetadataFeature;
pub use packing::PackingFeature;
pub use relocation::RelocationFeature;
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
    pub packing: PackingFeature,
    pub relocation: RelocationFeature,
}
