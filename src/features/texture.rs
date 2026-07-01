use super::byte_image::ImageFeature;

#[derive(Debug)]
pub struct TextureFeature {
    pub block_entropy_mean: f64,
    pub block_entropy_std: f64,
    pub edge_density: f64,
    pub glcm_contrast: f64,
    pub glcm_homogeneity: f64,
    pub glcm_energy: f64,
    pub lbp_histogram: [f64; 256],
}

impl Default for TextureFeature {
    fn default() -> Self {
        Self {
            block_entropy_mean: 0.0,
            block_entropy_std: 0.0,
            edge_density: 0.0,
            glcm_contrast: 0.0,
            glcm_homogeneity: 0.0,
            glcm_energy: 0.0,
            lbp_histogram: [0.0; 256],
        }
    }
}

impl TextureFeature {
    pub fn extract(img: &ImageFeature) -> Self {
        let mut f = Self::default();
        let (bm, bs) = Self::block_entropy(img, 16);
        f.block_entropy_mean = bm;
        f.block_entropy_std = bs;
        f.edge_density = Self::edge_density(img);
        let (c, h, e) = Self::glcm_features(img);
        f.glcm_contrast = c;
        f.glcm_homogeneity = h;
        f.glcm_energy = e;
        f.lbp_histogram = Self::lbp_histogram(img);
        f
    }

    // entropia di Shannon calcolata su blocchi non sovrapposti block_size x block_size,
    // poi media e deviazione standard tra blocchi (cattura uniformità/eterogeneità locale)
    fn block_entropy(img: &ImageFeature, block_size: usize) -> (f64, f64) {
        let mut entropies = Vec::new();
        let mut by = 0;
        while by < img.height {
            let mut bx = 0;
            while bx < img.width {
                let mut counts = [0usize; 256];
                let mut total = 0usize;
                for y in by..(by + block_size).min(img.height) {
                    for x in bx..(bx + block_size).min(img.width) {
                        counts[img.matrix[y][x] as usize] += 1;
                        total += 1;
                    }
                }
                if total > 0 {
                    let mut e = 0.0;
                    for &c in &counts {
                        if c > 0 {
                            let p = c as f64 / total as f64;
                            e -= p * p.log2();
                        }
                    }
                    entropies.push(e);
                }
                bx += block_size;
            }
            by += block_size;
        }
        if entropies.is_empty() {
            return (0.0, 0.0);
        }
        let mean = entropies.iter().sum::<f64>() / entropies.len() as f64;
        let var =
            entropies.iter().map(|e| (e - mean).powi(2)).sum::<f64>() / entropies.len() as f64;
        (mean, var.sqrt())
    }

    // gradiente di Sobel semplificato: frazione di pixel con gradiente sopra soglia
    fn edge_density(img: &ImageFeature) -> f64 {
        if img.height < 3 || img.width < 3 {
            return 0.0;
        }
        let mut edge_count = 0usize;
        let mut total = 0usize;
        for y in 1..img.height - 1 {
            for x in 1..img.width - 1 {
                let gx = img.matrix[y][x + 1] as i32 - img.matrix[y][x - 1] as i32;
                let gy = img.matrix[y + 1][x] as i32 - img.matrix[y - 1][x] as i32;
                let mag = ((gx * gx + gy * gy) as f64).sqrt();
                if mag > 30.0 {
                    edge_count += 1;
                }
                total += 1;
            }
        }
        if total == 0 {
            0.0
        } else {
            edge_count as f64 / total as f64
        }
    }

    // GLCM con offset (1,0), livelli quantizzati a 32 per tenere la matrice 32x32 gestibile
    fn glcm_features(img: &ImageFeature) -> (f64, f64, f64) {
        const LEVELS: usize = 32;
        let quant = |v: u8| (v as usize * LEVELS) / 256;
        let mut glcm = vec![vec![0f64; LEVELS]; LEVELS];
        let mut pair_count = 0usize;

        for y in 0..img.height {
            for x in 0..img.width.saturating_sub(1) {
                let i = quant(img.matrix[y][x]);
                let j = quant(img.matrix[y][x + 1]);
                glcm[i][j] += 1.0;
                pair_count += 1;
            }
        }
        if pair_count == 0 {
            return (0.0, 0.0, 0.0);
        }
        for row in glcm.iter_mut() {
            for v in row.iter_mut() {
                *v /= pair_count as f64;
            }
        }

        let mut contrast = 0.0;
        let mut homogeneity = 0.0;
        let mut energy = 0.0;
        for i in 0..LEVELS {
            for j in 0..LEVELS {
                let p = glcm[i][j];
                let diff = (i as f64 - j as f64).abs();
                contrast += p * diff * diff;
                homogeneity += p / (1.0 + diff);
                energy += p * p;
            }
        }
        (contrast, homogeneity, energy)
    }

    // Local Binary Pattern: confronta ogni pixel con gli 8 vicini, costruisce un codice 0-255,
    // poi istogramma normalizzato. Cattura microtessitura indipendentemente da rotazioni grossolane.
    fn lbp_histogram(img: &ImageFeature) -> [f64; 256] {
        let mut hist = [0f64; 256];
        if img.height < 3 || img.width < 3 {
            return hist;
        }
        let offsets = [
            (-1i32, -1i32),
            (-1, 0),
            (-1, 1),
            (0, 1),
            (1, 1),
            (1, 0),
            (1, -1),
            (0, -1),
        ];
        let mut total = 0usize;
        for y in 1..img.height - 1 {
            for x in 1..img.width - 1 {
                let center = img.matrix[y][x];
                let mut code: u8 = 0;
                for (k, (dy, dx)) in offsets.iter().enumerate() {
                    let ny = (y as i32 + dy) as usize;
                    let nx = (x as i32 + dx) as usize;
                    if img.matrix[ny][nx] >= center {
                        code |= 1 << k;
                    }
                }
                hist[code as usize] += 1.0;
                total += 1;
            }
        }
        if total > 0 {
            for v in hist.iter_mut() {
                *v /= total as f64;
            }
        }
        hist
    }
}
