## WSI Patch Encryption Visual Audit
This repo contains a small audit tool for patch-based encryption on Whole Slide Images (WSIs).
It reads patch coordinates from a coords-only HDF5 file (`coords` dataset), extracts the corresponding patches from an SVS slide with OpenSlide, then applies an Encrypt-then-MAC construction to each patch.

For each mode (CTR / CBC / ECB), the script:
- encrypts + decrypts a set of sampled patches and saves side-by-side visuals
- builds a large mosaic from a contiguous neighborhood of coordinates (to visually verify consistency)
- runs a couple of simple integrity demos (bit-flip, patch-swap)


## Files
- main.py


## Requirements
Python packages
- numpy
- h5py
- Pillow
- pycryptodome
- openslide-python


## Input format
1) Slide file
- An SVS WSI file, e.g. 'wsi.svs'

2) Coordinates file (HDF5)
- H5 file containing a dataset named 'coords'
- Shape: (N, 2)
- Stored order: (y, x)


## Example Usage
python main.py \
 --svs ./TCGA-WR-A838-01Z-00-DX1.5FE22DE4-CEFB-45F6-9299-505023A8F3BA.svs \
 --coords-h5 ./content/TCGA-WR-A838-01Z-00-DX1.5FE22DE4-CEFB-45F6-9299-505023A8F3BA_256.h5 \
 --outdir ./output_256 \
 --patch-size 256 \
 --sample_k 20 \
 --mosaic_k 2500 \
 --password serra


## Output Structure
The tool creates a folder (default: ./output_256) containing:
- patch_256/mode_CTR/: Results for CTR mode
- samples/: Visual audit images for individual patches
- mosaic/: mosaic_decrypted.png (The stitched image proving spatial correctness)
- all_patch_sizes_modes_stats.json: Quantitative results and timing metrics


## Attack Demonstrations
The console output will show real-time verification of security checks:
[demo] bit flip: Should print "detected tampering"
[demo] patch swap: Should print "detected tampering"


