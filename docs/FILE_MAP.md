# Scripts, algorithms and names

| Script | Step (paper section) | Role |
|---|---|---|
| `00_kiem_ke.py` | Section 3.3 | inventory of the feature files (manifests) |
| `01_trich_symtab_gt.py` | Step 1 | reads `.symtab` of the unstripped originals, name rules `QUY_TAC` (ground truth v1) |
| `14_tao_gt_v2.py` | Step 1: function roles | final roles: library (libc/libgcc names, leading underscore, name in >= 10% of files, library hash), author, payload, helper |
| `08_bam_ham.py` | Step 3: function hash, RQ2 | whole-function hashes (`bam`) and accuracy/coverage of the database (`phan_tich`) |
| `10_tao_csdl_ham_thu_vien.py` | Step 3 | library database D from 2020 ground truth |
| `05_tao_chu_ky_thu_vien.py` | Step 4: mask (b) | role counts per semantic signature |
| `algorithm4_library_filter.py` | Step 4 | filtering of library functions (mode d/e) and masks (a)-(c), as used in training |
| `02_dinh_vi_ham.py` | Step 2 | exact attribution (`--tinh-cache`) and per-file audit; `--libfn` = post hoc filter (mode e) |
| `07*`, `12*`, `16_chay*`, `18*` (`.sh`) | | drivers that ran `02_dinh_vi_ham.py` for every run |
| `09_tong_hop_libsym.py`, `16_tong_hop_libaware.py`, `13_so_sanh_libaware.py` | RQ3 | aggregation over seeds, exact Wilcoxon tests |
| `17_tong_hop_xisa.py`, `19_tong_hop_A_xisa.py` | RQ3, leave one ISA out | detection from predictions, localization |
| `20_rq1_grouped.py` | RQ1 | evidence shares, ranking, top functions |

Vietnamese names in files and columns:

| Name | Meaning |
|---|---|
| `ket_qua` | results / working folder |
| `vai_tro`, `vai_tro_chi_tiet` | role, detailed role |
| `thu_vien`, `tac_gia`, `khac` | library, author, other (= library in ground truth v2 coarse roles) |
| `ma_doc`, `lanh_tinh` | malware, benign |
| `bam`, `ham`, `tep` | hash, function, file |
| `goc`, `loc` | unfiltered (original), filtered (library-aware) |
| `bo_thu_vien`, `moi_ham` | library functions removed, all functions |
| `ty_trong` / `ev_share_*` | share of evidence |
| `chia`, `kich_thuoc`, `do_chinh_xac`, `do_phu` | split, size, accuracy, coverage |
| `TOM_TAT`, `TONG_HOP` | summary, aggregate |
