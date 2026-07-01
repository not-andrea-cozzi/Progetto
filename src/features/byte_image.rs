#[derive(Debug, Default)]
pub struct ImageFeature {
    pub width: usize,
    pub height: usize,
    pub matrix: Vec<Vec<u8>>,
}

impl ImageFeature {
    fn width_for_size(size: usize) -> usize {
        match size {
            0..=10_239 => 32,
            10_240..=30_719 => 64,
            30_720..=61_439 => 128,
            61_440..=102_399 => 256,
            102_400..=204_799 => 384,
            204_800..=409_599 => 512,
            409_600..=716_799 => 768,
            _ => 1024,
        }
    }

    pub fn extract(raw_data: &[u8]) -> Self {
        let width = Self::width_for_size(raw_data.len());
        let height = (raw_data.len() + width - 1) / width.max(1);
        let mut matrix = vec![vec![0u8; width]; height.max(1)];
        for (i, &b) in raw_data.iter().enumerate() {
            matrix[i / width][i % width] = b;
        }
        Self {
            width,
            height,
            matrix,
        }
    }
}
