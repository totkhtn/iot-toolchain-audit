# Auditing Evidence and Mitigating Toolchain Bias in Heterogeneous Graph-Based IoT Malware Detection

This repository contains the code, the function-level ground truth, the library hash database, the data splits and the
results of the paper

> D.-T. Tran, A.-T. Tran, K. Nguyen-An, T.-D. Luong. *Auditing Evidence and Mitigating Toolchain Bias in Heterogeneous Graph-Based IoT Malware Detection.*
> Submitted to the Journal of Computer Science and Cybernetics (JCC), 2026.

The repository implements the four steps of the study: (1) role labelling of the functions of stripped ELF binaries
from the symbol tables of their unstripped originals, (2) exact attribution of the additive top-K evidence of a
detector to functions, followed by a per-file audit, (3) a whole-function hash database for library identification,
built from an earlier period, and (4) library-aware training and post hoc filtering. All numbers reported in the paper
can be recomputed from this repository and its release assets **without the binaries or the feature files** (see
"Reproducing").

## Layout

```
code/                     scripts used for the paper (see docs/FILE_MAP.md)
data/
  manifests/              files_2020.csv.gz, files_2024.csv.gz: SHA-256, label, ISA, stripped, static, sizes
  ground_truth/gt_v1/     gt_functions.csv.gz (one row per symbol-matched function), gt_files.csv (one row per file)
  ground_truth/gt_v2/     final roles used in the paper (payload/author vs helper vs library), libc name list
  function_hashes/        function_hashes.csv.gz: whole-function hashes (opcode and semantic) of 8,140 files
  library_db/             library_functions_2020.txt: the library database D (2,390 hashes, 2020 data only)
  signature_roles/        signature_roles.csv.gz: per file and semantic signature, number of blocks in library /
                          malware / other functions (input of the symbol-table mask)
  splits/                 grouped_2024_10seeds.csv.gz (train/val/test of every seed), leave_one_isa_out/
results/
  rq1_grouped/            RQ1 (evidence shares, function ranking, top functions)
  library_db/             RQ2 (accuracy and coverage of the hash database)
  masks/                  RQ3, masks (a)-(c): detection per seed (libsym_results.csv) and summary
  library_aware/          RQ3, library-aware HIN within distribution: detection per seed and summary
  cross_isa/              RQ3, leave one ISA out: predictions (npz) of both runs and summaries
scripts/setup_workdir.py  builds the working folder workdir/ from data/ and the release assets
docs/                     FILE_MAP.md (scripts, outputs and column names), TRAINING.md (GPU runs)
```

The summaries (`*.md`) in `results/` are the files written by the aggregation scripts.

## Data description

`gt_v2/gt_functions.csv.gz`: `file_hash`, `addr` (function start address, decimal; Thumb bit cleared), `size`, `name`
(symbol name, **never shown to the models**), `role` (`payload` = payload or author code, `helper`, `other` =
library), `role_detail` (`payload`, `author`, `helper`, `library`). 2,140 unstripped malware files (1,065 from 2020,
1,075 from 2024), 605,021 functions. Rules: `code/01_extract_symtab_gt.py` (name rules `NAME_RULES`),
`code/14_build_gt_v2.py` (library rules) and the additional payload patterns `EXTRA_MALWARE_NAMES` shared by all
scripts.

`library_db/library_functions_2020.txt`: one line per hash, `MD5(ISA + '#' + opcode sequence of all blocks in address
order)[:16]`, followed by the number of 2020 ground-truth functions with that hash and an example name.

## Reproducing

```bash
pip install -r requirements.txt
# download the release assets (audit_per_file.zip, function_caches_*.zip) into release_assets/
python3 scripts/setup_workdir.py --assets release_assets

# Step 3 (library hash database) and RQ2: accuracy and coverage
python3 code/10_build_library_db.py --gt-dir workdir/gt --cache workdir/function_hashes --out out/libaware
python3 code/08_hash_functions.py analyze --gt-dir workdir/gt --cache workdir/function_hashes --out out/b3
# Step 1, final function roles (from gt_v1 + function hashes + libc names)
python3 code/14_build_gt_v2.py --gt-dir workdir/gt --hashes workdir/function_hashes \
   --libc-names workdir/gt_v2/libc_glibc_names.txt --out out/gt_v2
# Step 2 (exact evidence attribution and audit) for one run (here mask (c), seed 42) from the function-level cache
python3 code/02_localize_functions.py --gt-dir workdir/gt_v2 --cache workdir/A_cache_libsym_grouped-2024_seed42 \
   --cache-model S_libboth --model-name A_libsym_S_libboth_grouped-2024_seed42 \
   --test-hashes workdir/splits/test_hashes_grouped-2024_seed42.txt --q4-sample 0 --out out/a42
# Aggregation over seeds (RQ1, RQ3)
python3 code/20_rq1_grouped.py
python3 code/09_aggregate_libsym.py --results results/masks/libsym_results.csv --a-dir workdir/gt_v2_A --out out/masks
python3 code/16_aggregate_libaware.py --unfiltered results/library_aware/libaware_results_unfiltered.csv \
   --filtered results/library_aware/libaware_results_filtered.csv --a-dir workdir/A_la_ms --out out/library_aware
python3 code/17_aggregate_xisa.py --unfiltered results/cross_isa/predictions/unfiltered \
   --filtered results/cross_isa/predictions/filtered --out out/xisa
python3 code/19_aggregate_audit_xisa.py --a-dir workdir/A_xisa --out out/xisa
```

Each command above reproduces the corresponding released file; all reported values are identical, and a few cells of
the per-run CSV files can differ in the last floating-point digit because of the summation order. Cache and run
names: `S`, `S_libben`, `S_libsym`, `S_libboth` = no mask, mask (a), (b), (c); `unfiltered` = model trained on all
functions, `filtered` = library-aware model; `A_cache_*_libfn_*` = evaluation restricted to non-library functions;
`unfiltered_all_functions`, `unfiltered_non_library`, `filtered_non_library` = the three evaluation settings of the
library-aware audit.

The following steps need the binaries or the feature JSON files, which are not distributed: extracting the symbol
tables (`01_extract_symtab_gt.py`), hashing functions (`08_hash_functions.py hash`), computing the function-level
caches (`02_localize_functions.py --compute-cache`) and training the models (GPU). The training scripts contain the
full detector code, which belongs to a separate manuscript and is available on request (see `docs/TRAINING.md`). The
library-related parts of step 4 (library-aware training and post hoc filtering) are provided in
`code/algorithm4_library_filter.py`.

## Release assets

| Archive | Content |
|---|---|
| `audit_per_file.zip` | per-run audit output (`A_Q1_summary.csv`, `A_per_file.csv`, `SUMMARY_A.md`) of all 220 runs |
| `function_caches_masks.zip` | function-level evidence of the four mask variants, 10 seeds |
| `function_caches_library_aware.zip` | function-level evidence of the unfiltered and library-aware models, 10 seeds |
| `function_caches_cross_isa.zip` | the same for leave one ISA out, 5 ISAs x 10 seeds |

## Licence

Code: MIT (`LICENSE`). Data and results: CC BY 4.0 (`DATA_LICENSE`). Malware binaries are not distributed; files are
identified by their SHA-256 hashes.

## Citation

See `CITATION.cff`.
