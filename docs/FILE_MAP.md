# Scripts, algorithms and names

| Script | Step (paper section) | Role |
|---|---|---|
| `00_inventory.py` | Section 3.3 | inventory of the feature files (manifests) |
| `01_extract_symtab_gt.py` | Step 1 | reads the `.symtab` of the unstripped originals; name rules `NAME_RULES` (ground truth v1) |
| `14_build_gt_v2.py` | Step 1: function roles | final roles: library (libc/libgcc names, leading underscore, name in >= 10% of the files, library hash), author, payload, helper |
| `08_hash_functions.py` | Step 3: function hash, RQ2 | whole-function hashes (`hash`) and accuracy/coverage of the database (`analyze`) |
| `10_build_library_db.py` | Step 3 | library database D from the 2020 ground truth |
| `05_build_signature_roles.py` | Step 4: mask (b) | role counts per semantic signature |
| `algorithm4_library_filter.py` | Step 4 | filtering of library functions (modes d/e) and masks (a)-(c), as used in training |
| `02_localize_functions.py` | Step 2 | exact attribution (`--compute-cache`) and per-file audit; `--libfn` = post hoc filter (mode e) |
| `07*`, `12*`, `16_run*`, `18*` (`.sh`) | | drivers that ran `02_localize_functions.py` for every run |
| `09_aggregate_libsym.py`, `16_aggregate_libaware.py`, `13_compare_libaware.py` | RQ3 | aggregation over seeds, exact Wilcoxon tests |
| `17_aggregate_xisa.py`, `19_aggregate_audit_xisa.py` | RQ3, leave one ISA out | detection from predictions, localization |
| `20_rq1_grouped.py` | RQ1 | evidence shares, ranking, top functions |

## Outputs of `02_localize_functions.py` (one folder per run)

| File | Content |
|---|---|
| `A_per_file.csv` | one row per ground-truth file: family, test flag, function counts, vocabulary coverage, evidence shares (`ev_share_payload`, `ev_share_helper`, `ev_share_other`), ranking metrics per score |
| `A_Q1_summary.csv` | mean and bootstrap 95% CI of every ranking metric per `group` (period, period x ISA, `test_only`) and `score` |
| `A_payload_rank.csv`, `A_Q3_cross_isa.csv` | percentile rank of every payload function, rank consistency across ISAs (not released; recomputable) |
| `SUMMARY_A.md` | human-readable summary of the run |

## Column and value names

| Name | Meaning |
|---|---|
| `workdir` | working folder created by `scripts/setup_workdir.py` |
| `role`, `role_detail` | coarse role (`payload`, `helper`, `other`) and detailed role (`payload`, `author`, `helper`, `library`) of a function |
| `other` | coarse role of non-malicious code; in ground truth v2 it is exactly the library code |
| `family` | malware family inferred from the symbol names (`mirai`, `gafgyt`, `other`) |
| `n_library`, `n_malware`, `n_other` | number of blocks of a signature in library, malware and other functions |
| `group` (function hashes) | `gt` (unstripped malware with ground truth), `malware_stripped`, `benign` |
| `unfiltered`, `filtered` | model trained on all functions, library-aware model (library functions filtered) |
| `all_functions`, `non_library` | evaluation on all functions, evaluation without the functions that match the library database |
| `ev_share_*` | share of the top-K evidence on functions of a role |
| `payload_out_of_vocab` | share of payload functions without any signature in the model vocabulary |
| `split`, `size`, `recall_library`, `malware_as_library` | split of the database experiment, function size bin, library recall, share of malware functions identified as library |
| `frac_functions`, `frac_instructions` | share of functions, and of instructions, matching the library database |
| `SUMMARY_*` | human-readable summaries written by the scripts |

The only non-English name left in the code is `tap_chinh`, the sub-folder of the main sample set in the output of the
static feature extractor (`<feature_json_root>/<period>/tap_chinh/`), together with the extractor field
`cfg_tren_ban_strip` (CFG computed on the stripped copy). Both are fixed by the extractor and are only read.
