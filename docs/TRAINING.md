# Training runs (GPU)

The models were trained on Kaggle (one T4 GPU) with two training scripts (`hin_static_v15_libsym.py`,
`hin_static_v15_libaware.py`) that contain the full code of the audited detector. The detector is described in a
separate manuscript, so these scripts are **not included** in this repository; they are available from the authors on
request and will be added after that manuscript is published. The library-related parts of the training (filtering
of library functions and the masks) are given in `code/algorithm4_library_filter.py`. The scripts read the per-file
feature JSON files (static extractor v5.2) and a VirusTotal report table, which are not distributed. Configuration is
passed as a JSON file in the environment variable `HIN_CONFIG`; the settings below document the runs.

Seeds of every grouped experiment: 10, 42, 100, 314, 555, 777, 999, 1234, 2024, 2026. Splits are the same for all
experiments of a seed (`data/splits/grouped_2024_10seeds.csv.gz`).

## Masks (a)-(c), modes (a)-(c)

```json
{"RUN_SCENARIOS": ["libsym"], "SEEDS_PER_SCENARIO": {"libsym": 10},
 "LIBSYM_CSV": "<data/signature_roles/chu_ky_thu_vien.csv.gz>",
 "DATA_DIR": "<feature JSON folder>", "VT_CSV": "<VirusTotal report>"}
```
Variants: `base` (no mask), `benign` (mask a: signatures in at least
`LIBSUP_FRAC` = 5% of the statically linked benign training files), `symtab` (mask b), `symtab+benign` (mask c).
Mask (b) uses only training files: with `n_lib(e)` = number of unstripped training malware files in which signature
`e` occurs in a library function (name in at least 10% of ground-truth files) and `n_mal(e)` = number in which it
occurs in a payload or helper function, `e` is masked if `n_lib(e) >= LIBSYM_MIN_FILES` (3) and
`n_mal(e) <= LIBSYM_MAX_MAL_FRAC * (n_lib(e) + n_mal(e))` (0.10).

## Library-aware HIN, mode (d), within distribution and leave one ISA out

Two runs with identical settings, differing only in `LIBFN_HASHES`:

```json
{"RUN_SCENARIOS": ["libaware"], "SEEDS_PER_SCENARIO": {"libaware": 10},
 "LIBFN_HASHES": null,                                   # unfiltered run
 "DATA_DIR": "<feature JSON folder>", "VT_CSV": "<VirusTotal report>"}
{"...": "...", "LIBFN_HASHES": "<data/library_db/ham_thu_vien_2020.txt>"}   # library-aware run
```
Use `"RUN_SCENARIOS": ["libaware_xisa"]` for leave one ISA out. Models: Meta-RF (shortcut probe), LightGBM,
LightGBM-monotone, MLP-flat-AT, HGT-AT, MHEN-O, MHEN-S. Deduplication and splits are computed on unfiltered data, so
both runs use identical files and splits (23,297 files).

## Outputs used by the audit

`reports/mhenS*_entity_scores_semblock_<split>_seed<s>.csv` (entity scores, input of
`02_dinh_vi_ham.py --tinh-cache`), `reports/*_test_hashes_*.txt`, `reports/libsym_results.csv`,
`reports/libaware_results.csv` and `predictions/*.npz`. The function-level caches computed from the entity scores are
released (see README), so the audit does not need to be recomputed from the entity scores.
