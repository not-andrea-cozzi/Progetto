// src/features/byte_level.rs
#[derive(Debug)]
pub struct ByteLevelFeature {
    pub global_entropy: f64,
    pub bytes: [f64; 256],
}

impl Default for ByteLevelFeature {
    fn default() -> Self {
        Self {
            global_entropy: 0.0,
            bytes: [0.0; 256],
        }
    }
}

impl ByteLevelFeature {
    pub fn extract(raw_data: &[u8]) -> Result<Self, String> {
        let mut feature = Self::default();
        let total_bytes = raw_data.len() as f64;
        if total_bytes == 0.0 {
            return Err("raw_data is empty".to_string());
        }
        let mut counts = [0usize; 256];
        for &byte in raw_data {
            counts[byte as usize] += 1;
        }
        let mut entropy = 0.0;
        for i in 0..256 {
            if counts[i] > 0 {
                let p = counts[i] as f64 / total_bytes;
                feature.bytes[i] = p;
                entropy -= p * p.log2();
            }
        }
        feature.global_entropy = entropy;
        Ok(feature)
    }
}
