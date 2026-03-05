#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
wsi_coords_only_crypto_audit_with_demos.py

Reads patches from an SVS file using a coords-only H5 (dataset: coords).
For each AES mode (CTR/CBC/ECB), it:
- encrypts/decrypts a set of sample patches and saves visual audit rows
- builds a mosaic from a contiguous coord neighborhood
- optionally runs a few simple attack demos (bit flip, patch swap, ECB leakage)
"""

from __future__ import annotations

import os
import json
import time
import math
import random
from typing import Tuple, List, Dict, Optional

import numpy as np
import h5py
import argparse
from PIL import Image

# Crypto (PyCryptodome)
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import hmac
import hashlib

import openslide


Coords = Tuple[int, int]   # Coords order is stores as yx in HDF5 file


# =============================================================================
# Encrypt-then-MAC
# =============================================================================

class WSIPatchEncryption:
    """
    Encrypt-then-MAC with:
      - AES-256 in CTR/CBC/ECB
      - HMAC-SHA256
    """

    def __init__(self, key_enc: bytes = None, key_mac: bytes = None, password: str = None):
        if key_enc is None or key_mac is None:
            self.key_enc, self.key_mac = self.generate_keys(password=password)
        else:
            if len(key_enc) != 32:
                raise ValueError("key_enc must be 32 bytes (AES-256).")
            if len(key_mac) != 32:
                raise ValueError("key_mac must be 32 bytes.")
            self.key_enc = key_enc
            self.key_mac = key_mac

    @staticmethod
    def generate_keys(password: str) -> Tuple[bytes, bytes]:
        salt = b"wsi_encryption_salt_v1"
        master_key = PBKDF2(password, salt, dkLen=64, count=100000)
        return master_key[:32], master_key[32:]

    @staticmethod
    def _make_aad(coords: Coords, patch_shape: Tuple[int, ...], patch_index: int, mode: str) -> bytes:
        y, x = coords
        payload = {
            "y": int(y),
            "x": int(x),
            "shape": list(patch_shape),
            "index": int(patch_index),
            "mode": str(mode).upper(),
        }
        return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    def encrypt_patch(self, patch_data: np.ndarray, coords: Coords, patch_index: int, mode: str) -> Dict:
        mode = mode.upper()
        patch_bytes = patch_data.tobytes()
        patch_shape = patch_data.shape

        if mode == "CTR":
            nonce = get_random_bytes(8)
            cipher = AES.new(self.key_enc, AES.MODE_CTR, nonce=nonce)
            ciphertext = cipher.encrypt(patch_bytes)

        elif mode == "CBC":
            nonce = get_random_bytes(16)
            cipher = AES.new(self.key_enc, AES.MODE_CBC, iv=nonce)
            ciphertext = cipher.encrypt(pad(patch_bytes, AES.block_size))

        elif mode == "ECB":
            nonce = b""
            cipher = AES.new(self.key_enc, AES.MODE_ECB)
            ciphertext = cipher.encrypt(pad(patch_bytes, AES.block_size))


        aad = self._make_aad(coords, patch_shape, patch_index, mode)
        tag = hmac.new(self.key_mac, aad + ciphertext, hashlib.sha256).digest()

        return {
            "coords": coords,
            "nonce": nonce,
            "ciphertext": ciphertext,
            "tag": tag,
            "aad": aad,  
            "shape": patch_shape,
            "index": int(patch_index),
            "mode": mode,
        }

    def decrypt_patch(self, encrypted_patch: Dict, verify_only: bool = False) -> Optional[np.ndarray]:
        mode = encrypted_patch.get("mode", "CTR").upper()
        coords = tuple(encrypted_patch["coords"])
        shape = tuple(encrypted_patch["shape"])
        index = int(encrypted_patch["index"])

        expected_aad = self._make_aad(coords, shape, index, mode)

        stored_aad = encrypted_patch.get("aad", None)
        if stored_aad is not None and bytes(stored_aad) != expected_aad:
            raise ValueError(f"AAD mismatch at {coords} (mode={mode}).")

        ciphertext = encrypted_patch["ciphertext"]
        tag = encrypted_patch["tag"]

        mac = hmac.new(self.key_mac, expected_aad + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, tag):
            raise ValueError(f"MAC verification failed at {coords} (mode={mode}).")

        if verify_only:
            return None

        nonce = encrypted_patch.get("nonce", b"") or b""

        if mode == "CTR":
            if len(nonce) != 8:
                raise ValueError(f"CTR nonce must be 8 bytes, got {len(nonce)} at {coords}")
            cipher = AES.new(self.key_enc, AES.MODE_CTR, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)

        elif mode == "CBC":
            if len(nonce) != 16:
                raise ValueError(f"CBC IV must be 16 bytes, got {len(nonce)} at {coords}")
            cipher = AES.new(self.key_enc, AES.MODE_CBC, iv=nonce)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        elif mode == "ECB":
            cipher = AES.new(self.key_enc, AES.MODE_ECB)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        else:
            raise ValueError(f"Unknown cipher mode '{mode}' at {coords}")

        arr = np.frombuffer(plaintext, dtype=np.uint8)
        expected_len = int(np.prod(shape))
        if arr.size != expected_len:
            raise ValueError(f"Plaintext length mismatch at {coords} (mode={mode}).")

        return arr.reshape(shape)


# =============================================================================
# Demos
# =============================================================================

class SecurityDemonstrations:
    @staticmethod
    def demo_bitflip_attack(encryptor: WSIPatchEncryption, encrypted_patch: Dict) -> None:
        print("\n[demo] bit flip (ciphertext)")
        encryptor.decrypt_patch(encrypted_patch)  

        corrupted = dict(encrypted_patch)
        ct = bytearray(corrupted["ciphertext"])
        if len(ct) < 10:
            print("  ciphertext too short, skipping")
            return

        pos = min(100, len(ct) - 1)
        ct[pos] ^= 0x01
        corrupted["ciphertext"] = bytes(ct)

        try:
            encryptor.decrypt_patch(corrupted)
            print("  accepted corrupted ciphertext (unexpected)")
        except ValueError as e:
            print("  detected tampering:", str(e))

    @staticmethod
    def demo_patch_swap_attack(encryptor: WSIPatchEncryption, encrypted_patches: List[Dict]) -> None:
        print("\n[demo] patch swap (relabel coords)")
        if len(encrypted_patches) < 2:
            print("  need at least 2 patches, skipping")
            return

        p1 = encrypted_patches[0]
        p2 = encrypted_patches[1]

        swapped = dict(p1)
        swapped["coords"] = p2["coords"]

        try:
            encryptor.decrypt_patch(swapped)
            print("  accepted swapped coords (unexpected)")
        except ValueError as e:
            print("  detected tampering:", str(e))




def to_uint8_rgb(arr: np.ndarray) -> np.ndarray:
    if arr.dtype != np.uint8:
        arr = np.clip(arr, 0, 255).astype(np.uint8)
    if arr.ndim != 3 or arr.shape[2] != 3:
        raise ValueError(f"Expected RGB array (H,W,3), got shape={arr.shape}")
    return arr


def make_diff_heatmap(a: np.ndarray, b: np.ndarray, amplify: float = 12.0) -> Image.Image:
    a16 = a.astype(np.int16)
    b16 = b.astype(np.int16)
    diff = np.abs(a16 - b16).astype(np.float32)
    diff = np.clip(diff * float(amplify), 0, 255).astype(np.uint8)
    return Image.fromarray(diff, mode="RGB")


def save_row_image(out_path: str, imgs: List[Image.Image]) -> None:
    w, h = imgs[0].size
    canvas = Image.new("RGB", (w * len(imgs), h), color=(255, 255, 255))
    for i, im in enumerate(imgs):
        canvas.paste(im, (i * w, 0))
    canvas.save(out_path)


def in_bounds_indices(slide, coords: np.ndarray, patch_size: int) -> List[int]:
    W0, H0 = slide.dimensions
    keep = []
    for i in range(coords.shape[0]):
        x, y = coords[i, 1], coords[i, 0]
        if x < 0 or y < 0:
            continue
        if (x + patch_size) <= W0 and (y + patch_size) <= H0:
            keep.append(i)
    return keep

def pick_contiguous_indices(coords: np.ndarray, pool: List[int], k: int) -> List[int]:
    if not pool or k <= 0:
        return []
    k = min(k, len(pool))
    center_i = random.choice(pool)
    cx, cy = coords[center_i, 1], coords[center_i, 0]

    dists = []
    for i in pool:
        x, y = coords[i, 1], coords[i, 0]
        d = abs(x - cx) + abs(y - cy)
        dists.append((d, i))
    dists.sort(key=lambda t: t[0])
    return [i for _, i in dists[:k]]

def build_mosaic(coords: np.ndarray, patches: Dict[int, np.ndarray], patch_size: int) -> Image.Image:
    if not patches:
        return Image.new("RGB", (patch_size, patch_size), color=(0, 0, 0))

    xs, ys = [], []
    for idx in patches.keys():
        x, y = coords[idx, 1], coords[idx, 0]
        xs.append(x)
        ys.append(y)

    min_x, max_x = min(xs), max(xs)
    min_y, max_y = min(ys), max(ys)

    width = (max_x - min_x) + patch_size
    height = (max_y - min_y) + patch_size

    MAX_SIDE = 8000
    scale = int(math.ceil(max(width / MAX_SIDE, height / MAX_SIDE))) if (width > MAX_SIDE or height > MAX_SIDE) else 1

    canvas = Image.new("RGB", (max(1, width // scale), max(1, height // scale)), color=(0, 0, 0))

    for idx, patch in patches.items():
        x, y = coords[idx, 1], coords[idx, 0]
        ox = (x - min_x) // scale
        oy = (y - min_y) // scale

        im = Image.fromarray(to_uint8_rgb(patch), mode="RGB")
        if scale != 1:
            im = im.resize((max(1, patch_size // scale), max(1, patch_size // scale)), resample=Image.BILINEAR)
        canvas.paste(im, (int(ox), int(oy)))

    return canvas

def ciphertext_to_rgb(ciphertext: bytes, h: int, w: int, c: int = 3) -> np.ndarray:
    needed = h * w * c
    ct = np.frombuffer(ciphertext, dtype=np.uint8)
    if ct.size >= needed:
        ct = ct[:needed]
    else:
        ct = np.pad(ct, (0, needed - ct.size), mode="constant")
    return ct.reshape((h, w, c))


# =============================================================================
# Run per mode
# =============================================================================

def run_for_mode(
    slide,
    coords: np.ndarray,
    outdir: str,
    patch_size: int,
    mode: str,
    sample_k: int,
    mosaic_k: int,
    level: int,
    seed: int,
    password: str,
    run_attacks: bool,
):
    random.seed(seed + patch_size + hash(mode) % 1000)
    np.random.seed(seed + patch_size + hash(mode) % 1000)

    mode = mode.upper()
    run_dir = os.path.join(outdir, f"patch_{patch_size}", f"mode_{mode}")
    os.makedirs(os.path.join(run_dir, "samples"), exist_ok=True)
    os.makedirs(os.path.join(run_dir, "mosaic"), exist_ok=True)

    pool = in_bounds_indices(slide, coords, patch_size)

    random.shuffle(pool)
    sample_indices = pool[:min(sample_k, len(pool))]
    mosaic_indices = pick_contiguous_indices(coords, pool, k=min(mosaic_k, len(pool)))

    encryptor = WSIPatchEncryption(password=password)

    stats = {
        "patch_size": int(patch_size),
        "mode": mode,
        "level": int(level),
        "total_coords_in_file": int(coords.shape[0]),
        "coords_in_bounds": int(len(pool)),
        "sample_k": int(len(sample_indices)),
        "mosaic_k": int(len(mosaic_indices)),
        "svs_vs_dec": {"exact_matches": 0, "max_abs_diff": 0, "mean_abs_diff": 0.0},
        "timing_ms": {"enc_mean": 0.0, "dec_mean": 0.0},
    }

    enc_times, dec_times = [], []
    encrypted_for_demos: List[Dict] = []
    first_plain_patch: Optional[np.ndarray] = None
    first_coords: Optional[Coords] = None
    first_index: Optional[int] = None

    # samples
    for j, idx in enumerate(sample_indices):
        c0, c1 = coords[idx, 0], coords[idx, 1]
        x, y = c1, c0

        region = slide.read_region((int(x), int(y)), int(level), (int(patch_size), int(patch_size)))
        patch_svs = np.array(region.convert("RGB"), dtype=np.uint8)

        if first_plain_patch is None:
            first_plain_patch = patch_svs
            first_coords = (int(c0), int(c1))
            first_index = int(idx)

        t0 = time.time()
        enc = encryptor.encrypt_patch(patch_svs, coords=(int(c0), int(c1)), patch_index=int(idx), mode=mode)
        enc_times.append((time.time() - t0) * 1000.0)

        t1 = time.time()
        dec = encryptor.decrypt_patch(enc)
        dec_times.append((time.time() - t1) * 1000.0)

        encrypted_for_demos.append(enc)

        exact = bool(np.array_equal(patch_svs, dec))
        diff = np.abs(patch_svs.astype(np.int16) - dec.astype(np.int16))
        maxd = int(diff.max())
        meand = float(diff.mean())

        stats["svs_vs_dec"]["exact_matches"] += int(exact)
        stats["svs_vs_dec"]["max_abs_diff"] = max(stats["svs_vs_dec"]["max_abs_diff"], maxd)
        stats["svs_vs_dec"]["mean_abs_diff"] += meand
        ct_img = ciphertext_to_rgb(enc["ciphertext"], patch_size, patch_size, 3)

        im_svs = Image.fromarray(patch_svs, mode="RGB")
        im_dec = Image.fromarray(dec, mode="RGB")
        im_ct = Image.fromarray(ct_img, mode="RGB")
        im_diff = make_diff_heatmap(patch_svs, dec, amplify=12.0)

        base = f"idx{idx}_c0{int(c0)}_c1{int(c1)}"
        save_row_image(
            os.path.join(run_dir, "samples", f"{base}_svs_dec_ct_diff.png"),
            [im_svs, im_dec, im_ct, im_diff],
        )


    denom = float(len(sample_indices)) if sample_indices else 1.0
    stats["svs_vs_dec"]["mean_abs_diff"] /= denom
    stats["timing_ms"]["enc_mean"] = float(np.mean(enc_times)) if enc_times else 0.0
    stats["timing_ms"]["dec_mean"] = float(np.mean(dec_times)) if dec_times else 0.0

    # mosaic
    mosaic_svs: Dict[int, np.ndarray] = {}
    mosaic_dec: Dict[int, np.ndarray] = {}

    for idx in mosaic_indices:
        c0, c1 = coords[idx, 0], coords[idx, 1]
        x, y = c1, c0

        region = slide.read_region((int(x), int(y)), int(level), (int(patch_size), int(patch_size)))
        patch_svs = np.array(region.convert("RGB"), dtype=np.uint8)

        enc = encryptor.encrypt_patch(patch_svs, coords=(int(c0), int(c1)), patch_index=int(idx), mode=mode)
        dec = encryptor.decrypt_patch(enc)

        mosaic_svs[idx] = patch_svs
        mosaic_dec[idx] = dec

    if mosaic_indices:
        mosaic_img_svs = build_mosaic(coords, mosaic_svs, patch_size)
        mosaic_img_dec = build_mosaic(coords, mosaic_dec, patch_size)
        diff_mosaic = make_diff_heatmap(np.array(mosaic_img_svs), np.array(mosaic_img_dec), amplify=12.0)

        mosaic_img_svs.save(os.path.join(run_dir, "mosaic", "mosaic_svs.png"))
        mosaic_img_dec.save(os.path.join(run_dir, "mosaic", "mosaic_decrypted.png"))
        diff_mosaic.save(os.path.join(run_dir, "mosaic", "mosaic_diff.png"))

    # demos
    if run_attacks and encrypted_for_demos:
        try:
            SecurityDemonstrations.demo_bitflip_attack(encryptor, encrypted_for_demos[0])
        except Exception as e:
            print("[warn] bitflip demo failed:", e)

        try:
            SecurityDemonstrations.demo_patch_swap_attack(encryptor, encrypted_for_demos)
        except Exception as e:
            print("[warn] swap demo failed:", e)

    print(f"[{mode}] done. exact matches: {stats['svs_vs_dec']['exact_matches']}/{len(sample_indices)}")
    return stats


# =============================================================================
# Main
# =============================================================================

def main():
    
    parser = argparse.ArgumentParser(description="WSI Encryption Audit Tool")
    parser.add_argument("--svs", help="Path to .svs file", default="/content/TCGA-WR-A838-01Z-00-DX1.5FE22DE4-CEFB-45F6-9299-505023A8F3BA.svs")
    parser.add_argument("--coords-h5", help="Path to .h5 coordinate file", default="/content/TCGA-WR-A838-01Z-00-DX1.5FE22DE4-CEFB-45F6-9299-505023A8F3BA_256.h5")
    parser.add_argument("--outdir", help="Output directory", default="./output_256")
    parser.add_argument("--patch-size", type=int, help="Patch size (e.g., 256)", default=256)
    parser.add_argument("--sample_k", type=int, help="Number of patches to audit", default=20)
    parser.add_argument("--mosaic_k", type=int, help="Number of patches in mosaic", default=2500)
    parser.add_argument("--password", type=str, default="serra")
    args = parser.parse_args()

    level = 0
    seed = 1337
    run_attacks = True

    modes = ["CTR","CBC","ECB"]


    print("WSI crypto audit")
    print("  svs:", args.svs)
    print("  coords:", args.coords_h5)
    print("  patch_size:", args.patch_size)
    print("  modes:", modes)
    print("  out:", args.outdir)

    slide = openslide.OpenSlide(args.svs)

    with h5py.File(args.coords_h5, "r") as f:
        coords = np.array(f["coords"][:])
    
    os.makedirs(args.outdir, exist_ok=True)

    all_stats: Dict[str, Dict[str, dict]] = {str(args.patch_size): {}}

    for mode in modes:
        st = run_for_mode(
            slide=slide,
            coords=coords,
            outdir=args.outdir,
            patch_size=int(args.patch_size),
            mode=mode,
            sample_k=args.sample_k,
            mosaic_k=args.mosaic_k,
            level=level,
            seed=seed,
            password=args.password,
            run_attacks=run_attacks,
        )
        all_stats[str(args.patch_size)][mode] = st


    with open(os.path.join(args.outdir, "all_patch_sizes_modes_stats.json"), "w", encoding="utf-8") as f:
        json.dump(all_stats, f, indent=2)

    slide.close()
    print("done.")
    for mode in modes:
        print("  ", os.path.join(args.outdir, f"patch_{args.patch_size}", f"mode_{mode}"))


if __name__ == "__main__":
    main()
