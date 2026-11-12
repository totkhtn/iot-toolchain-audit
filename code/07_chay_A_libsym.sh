#!/bin/bash
# Giai đoạn A cho 4 biến thể MHEN-S của kịch bản 'libsym' (sau khi chạy Kaggle).
# Đặt các tệp tải về từ /kaggle/working/hin_static_v15_libsym/reports/ vào ket_qua/kaggle_libsym/:
#   mhenS_entity_scores_semblock_grouped-2024_seed10.csv
#   mhenS_libben_entity_scores_semblock_grouped-2024_seed10.csv
#   mhenS_libsym_entity_scores_semblock_grouped-2024_seed10.csv
#   mhenS_libboth_entity_scores_semblock_grouped-2024_seed10.csv
#   libsym_test_hashes_grouped-2024_seed10.txt, libsym_results.csv
# Chạy từ thư mục ytuong-moi:  bash code/07_chay_A_libsym.sh        (chạy lại được: cache có resume)
#                              BUOC=phan_tich bash code/07_chay_A_libsym.sh   (chỉ phần tổng hợp)
H="${H:-$HOME/mnt/HIN-Static}"; K="${K:-ket_qua/kaggle_libsym/reports}"; T=grouped-2024_seed10; HAN="${HAN:-160}"
S=(S S_libben S_libsym S_libboth)
FILES=(); for s in "${S[@]}"; do FILES+=("$K/mhen${s}_entity_scores_semblock_$T.csv"); done
if [ "${BUOC:-cache}" = cache ]; then
  python3 code/02_dinh_vi_ham.py --tinh-cache --period 2024 --han $HAN --json-dir "$H/dataset-moi" --gt-dir ket_qua/gt \
    --scores "${FILES[@]}" --ten-diem "${S[@]}" --cache ket_qua/A_cache_libsym --out ket_qua/A_cache_libsym \
    >> logs/07_cache_libsym.log 2>&1
  tail -n 1 logs/07_cache_libsym.log
  grep -q "XONG cache" logs/07_cache_libsym.log || { echo "Chưa xong cache — chạy lại lệnh này."; exit 0; }
fi
for s in "${S[@]}"; do
  python3 code/02_dinh_vi_ham.py --json-dir "$H/dataset-moi" --gt-dir ket_qua/gt --cache ket_qua/A_cache_libsym \
    --ten-cache $s --ten-mo-hinh "ict_$s" --test-hashes $K/libsym_test_hashes_$T.txt --out ket_qua/A_libsym_$s \
    > logs/07_A_$s.log 2>&1
  echo "== $s"; grep -E "^\| 2024\|test_only \| (s_topk|s_sum|b_ninsn|b_random) " ket_qua/A_libsym_$s/TOM_TAT_A.md
done
