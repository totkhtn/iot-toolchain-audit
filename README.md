# Toolchain fingerprints, not malice: auditing the evidence of heterogeneous graph IoT malware detectors

Code, function-level ground truth, library hash database, splits and results for the paper

> D.-T. Tran, A.-T. Tran, K. Nguyen-An, T.-D. Luong. *Toolchain Fingerprints, Not Malice: Auditing and Correcting
> the Evidence of Heterogeneous Graph IoT Malware Detectors with Automatic Function Level Ground Truth.* Submitted to
> the Journal of Science and Technology on Information Security (ISJ), 2026.

The repository implements the four steps of the study: (1) role labelling of the functions of stripped ELF binaries from the symbol tables
of their unstripped originals, (2) exact attribution of the additive top-K evidence of a detector to functions and a
per-file audit, (3) a whole-function hash database for library identification, built from an earlier period, and
(4) library-aware training and post hoc filtering. All numbers of the paper can be recomputed from this repository
and its release assets **without the binaries or feature files** (see "Reproducing").

## Layout

```
code/                     scripts as used for the paper (comments in Vietnamese; see docs/FILE_MAP.md)
data/
  manifests/              files_2020.csv.gz, files_2024.csv.gz: SHA-256, label, ISA, stripped, static, sizes
  ground_truth/gt_v1/     gt_ham.csv.gz (one row per symbol-matched function), gt_tep.csv (one row per file)
  ground_truth/gt_v2/     final roles used in the paper (payload/author vs helper vs library), libc name list
  function_hashes/        bam_ham.csv.gz: whole-function hashes (opcode and semantic) of 8,140 files
  library_db/             ham_thu_vien_2020.txt: the library database D (2,390 hashes, 2020 data only)
  signature_roles/        chu_ky_thu_vien.csv.gz: per file and semantic signature, number of blocks in library /
                          malware / other functions (input of the symbol-table mask)
  splits/                 grouped_2024_10seeds.csv.gz (train/val/test of every seed), leave_one_isa_out/
results/
  rq1_grouped/            RQ1 (evidence shares, function ranking, top functions)
  library_db/             RQ2 (accuracy and coverage of the hash database)
  masks/                  RQ3, masks (a)-(c): detection per seed (libsym_results.csv) and summary
  library_aware/          RQ3, library-aware HIN within distribution: detection per seed and summary
  cross_isa/              RQ3, leave one ISA out: predictions (npz) of both runs and summaries
scripts/setup_workdir.py  builds the working folder ket_qua/ from data/ and the release assets
docs/                     FILE_MAP.md (script and column names), TRAINING.md (GPU runs)
```

Summaries (`*.md`) in `results/` are the files written by the aggregation scripts (Vietnamese labels); the CSV and
NPZ files are language neutral.

## Data description

`gt_v2/gt_ham.csv.gz`: `file_hash`, `addr` (function start address, decimal; Thumb bit cleared), `size`, `name`
(symbol name, **never shown to the models**), `vai_tro` (`payload` = payload or author code, `helper`, `khac` =
library), `vai_tro_chi_tiet` (`payload`, `tac_gia` = author, `helper`, `thu_vien` = library). 2,140 unstripped malware
files (1,065 from 2020, 1,075 from 2024), 605,021 functions. Rules: `code/01_trich_symtab_gt.py` (name rules
`QUY_TAC`), `code/14_tao_gt_v2.py` (library rules) and the extra payload patterns `MA_DOC_THEM` shared by all scripts.

`library_db/ham_thu_vien_2020.txt`: one line per hash, `MD5(ISA + '#' + opcode sequence of all blocks in address
order)[:16]`, the number of 2020 ground-truth functions with that hash and an example name.

## Reproducing

```bash
pip install -r requirements.txt
# download the release assets (audit_per_file.zip, function_caches_*.zip) into release_assets/
python3 scripts/setup_workdir.py --assets release_assets

# Step 3 (library hash database) and RQ2: accuracy and coverage
python3 code/10_tao_csdl_ham_thu_vien.py --gt-dir ket_qua/gt --cache ket_qua/bam_ham --out out/libaware
python3 code/08_bam_ham.py phan_tich --gt-dir ket_qua/gt --cache ket_qua/bam_ham --out out/b3
# Step 1, final function roles (from gt_v1 + hashes + libc names)
python3 code/14_tao_gt_v2.py --gt-dir ket_qua/gt --bam ket_qua/bam_ham --libc-names ket_qua/gt_v2/ten_libc_glibc.txt --out out/gt_v2
# Step 2 (exact evidence attribution and audit) for one run (here mask (c), seed 42) from the function-level cache
python3 code/02_dinh_vi_ham.py --gt-dir ket_qua/gt_v2 --cache ket_qua/A_cache_libsym_grouped-2024_seed42 \
   --ten-cache S_libboth --ten-mo-hinh A_libsym_S_libboth_grouped-2024_seed42 --test-hashes ket_qua/splits/test_hashes_grouped-2024_seed42.txt --q4-mau 0 --out out/a42
# Aggregation over seeds (RQ1, RQ3)
python3 code/20_rq1_grouped.py
python3 code/09_tong_hop_libsym.py --results results/masks/libsym_results.csv --a-dir ket_qua/gt_v2_A --out out/masks
python3 code/16_tong_hop_libaware.py --goc results/library_aware/libaware_results_unfiltered.csv \
   --loc results/library_aware/libaware_results_filtered.csv --a-dir ket_qua/A_la_ms --out out/library_aware
python3 code/17_tong_hop_xisa.py --goc results/cross_isa/predictions/unfiltered --loc results/cross_isa/predictions/filtered --out out/xisa
python3 code/19_tong_hop_A_xisa.py --a-dir ket_qua/A_xisa --out out/xisa
```

Each command above was checked to reproduce the released file byte for byte. Cache names: `S`, `S_libben`,
`S_libsym`, `S_libboth` = no mask, mask (a), (b), (c); `goc` = unfiltered model, `loc` = library-aware model;
`A_cache_*_libfn_*` = evaluation restricted to non-library functions.

Steps that need the binaries or the feature JSON files (not distributed): extracting the symbol tables
(`01_trich_symtab_gt.py`), hashing functions (`08_bam_ham.py bam`), computing the function-level caches
(`02_dinh_vi_ham.py --tinh-cache`) and training the models (GPU; the training scripts contain the full detector code,
which belongs to a separate manuscript and is available on request; see `docs/TRAINING.md`). The library-related
parts of step 4 (library-aware training and post hoc filtering) are in `code/algorithm4_library_filter.py`.

## Release assets

| Archive | Content |
|---|---|
| `audit_per_file.zip` | per-run audit output (`A_Q1_tong_hop.csv`, `A_theo_tep.csv`) of all 220 runs |
| `function_caches_masks.zip` | function-level evidence of the four mask variants, 10 seeds |
| `function_caches_library_aware.zip` | function-level evidence of the unfiltered and library-aware models, 10 seeds |
| `function_caches_cross_isa.zip` | the same for leave one ISA out, 5 ISAs x 10 seeds |

## Licence

Code: MIT (`LICENSE`). Data and results: CC BY 4.0 (`DATA_LICENSE`). Malware binaries are not distributed; files are
identified by SHA-256.

## Citation

See `CITATION.cff`.
