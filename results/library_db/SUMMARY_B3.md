# Step 3: library function identification by whole-function hashing (FLIRT-like)

Ground-truth files: 2140 (database 1712 / evaluation 428, split by file). "Library" names: 422.

## (1) Accuracy: split `random_80_20` (database 1712 files, evaluation 428 files), hash `h_op`

| Function size | n library (GT) | Library recall | n malware (GT) | Malware identified as library | Precision (library vs malware) |
|---|---|---|---|---|---|
| <5 insns | 3099 | 0.898 | 17 | 0.000 | 1.0000 |
| 5–19 | 25091 | 0.998 | 1905 | 0.000 | 1.0000 |
| 20–99 | 33134 | 0.993 | 7376 | 0.000 | 0.9999 |
| >=100 | 8122 | 0.992 | 3290 | 0.000 | 1.0000 |
| All | 69446 | 0.991 | 12588 | 0.000 | 1.0000 |

## (1) Accuracy: split `random_80_20` (database 1712 files, evaluation 428 files), hash `h_sem`

| Function size | n library (GT) | Library recall | n malware (GT) | Malware identified as library | Precision (library vs malware) |
|---|---|---|---|---|---|
| <5 insns | 3099 | 0.898 | 17 | 0.000 | 1.0000 |
| 5–19 | 25091 | 0.998 | 1905 | 0.000 | 1.0000 |
| 20–99 | 33134 | 0.993 | 7376 | 0.000 | 0.9999 |
| >=100 | 8122 | 0.992 | 3290 | 0.000 | 1.0000 |
| All | 69446 | 0.991 | 12588 | 0.000 | 1.0000 |

## (1) Accuracy: split `temporal_2020_to_2024` (database 1065 files, evaluation 1075 files), hash `h_op`

| Function size | n library (GT) | Library recall | n malware (GT) | Malware identified as library | Precision (library vs malware) |
|---|---|---|---|---|---|
| <5 insns | 8173 | 0.842 | 68 | 0.015 | 0.9999 |
| 5–19 | 68867 | 0.969 | 6149 | 0.000 | 1.0000 |
| 20–99 | 83311 | 0.927 | 20178 | 0.000 | 1.0000 |
| >=100 | 20427 | 0.886 | 7975 | 0.000 | 1.0000 |
| All | 180778 | 0.935 | 34370 | 0.000 | 1.0000 |

## (1) Accuracy: split `temporal_2020_to_2024` (database 1065 files, evaluation 1075 files), hash `h_sem`

| Function size | n library (GT) | Library recall | n malware (GT) | Malware identified as library | Precision (library vs malware) |
|---|---|---|---|---|---|
| <5 insns | 8173 | 0.843 | 68 | 0.015 | 0.9999 |
| 5–19 | 68867 | 0.970 | 6149 | 0.000 | 1.0000 |
| 20–99 | 83311 | 0.927 | 20178 | 0.000 | 1.0000 |
| >=100 | 20427 | 0.886 | 7975 | 0.000 | 1.0000 |
| All | 180778 | 0.935 | 34370 | 0.000 | 1.0000 |

## (2) Coverage on files without ground truth (database built from all ground-truth files)

| Hash | Period | Group | n files | % functions matching the library DB (median) | % instructions in matching functions (median) |
|---|---|---|---|---|---|
| op | 2020 | gt | 1065 | 0.789 | 0.591 |
| op | 2020 | malware_stripped | 1500 | 0.677 | 0.306 |
| op | 2020 | benign | 1500 | 0.023 | 0.002 |
| op | 2024 | gt | 1075 | 0.775 | 0.613 |
| op | 2024 | malware_stripped | 1500 | 0.696 | 0.440 |
| op | 2024 | benign | 1500 | 0.015 | 0.001 |
| sem | 2020 | gt | 1065 | 0.789 | 0.591 |
| sem | 2020 | malware_stripped | 1500 | 0.677 | 0.306 |
| sem | 2020 | benign | 1500 | 0.026 | 0.002 |
| sem | 2024 | gt | 1075 | 0.775 | 0.613 |
| sem | 2024 | malware_stripped | 1500 | 0.696 | 0.442 |
| sem | 2024 | benign | 1500 | 0.017 | 0.001 |

