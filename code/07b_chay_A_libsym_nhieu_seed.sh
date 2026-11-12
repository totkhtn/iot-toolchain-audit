#!/bin/bash
# Giai đoạn A cho MỌI seed của kịch bản 'libsym' có trong thư mục reports (sau khi chạy Kaggle nhiều seed).
# Chạy từ thư mục ytuong-moi:   K=<thư mục reports> bash code/07b_chay_A_libsym_nhieu_seed.sh
#   - mỗi seed: cache điểm cấp hàm (chạy tiếp được, có hạn HAN giây) -> phân tích 4 biến thể trên tệp TEST của seed đó
#   - chạy lại lệnh cho tới khi in "TẤT CẢ XONG"; sau đó: python3 code/09_tong_hop_libsym.py ...
H="${H:-$HOME/mnt/HIN-Static}"; K="${K:-ket_qua/kaggle_libsym_seeds/reports}"; HAN="${HAN:-150}"
S=(S S_libben S_libsym S_libboth)
con=0
for TH in "$K"/libsym_test_hashes_grouped-2024_seed*.txt; do
  T=$(basename "$TH" .txt); T=${T#libsym_test_hashes_}          # grouped-2024_seedNN
  C=ket_qua/A_cache_libsym_$T
  F=(); for s in "${S[@]}"; do F+=("$K/mhen${s}_entity_scores_semblock_$T.csv"); done
  if ! grep -q "XONG cache" logs/07b_cache_$T.log 2>/dev/null; then
    python3 code/02_dinh_vi_ham.py --tinh-cache --period 2024 --han $HAN --json-dir "$H/dataset-moi" --gt-dir ket_qua/gt \
      --scores "${F[@]}" --ten-diem "${S[@]}" --cache $C --out $C >> logs/07b_cache_$T.log 2>&1
    grep -q "XONG cache" logs/07b_cache_$T.log || { echo "$T: cache chưa xong — chạy lại lệnh"; con=1; break; }
  fi
  for s in "${S[@]}"; do
    O=ket_qua/A_libsym_${s}_$T
    [ -f "$O/A_Q1_tong_hop.csv" ] && continue
    python3 code/02_dinh_vi_ham.py --json-dir "$H/dataset-moi" --gt-dir ket_qua/gt --cache $C --ten-cache $s \
      --ten-mo-hinh "ict_${s}_$T" --test-hashes "$TH" --q4-mau 0 --out $O > logs/07b_A_${s}_$T.log 2>&1
    echo "$T $s: $(tail -n 1 logs/07b_A_${s}_$T.log)"
  done
done
[ $con = 0 ] && echo "TẤT CẢ XONG"
