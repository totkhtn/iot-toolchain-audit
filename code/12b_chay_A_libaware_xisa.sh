#!/bin/bash
# Giai đoạn A cho kịch bản 'libaware_xisa' (leave-one-ISA-out), mô hình gốc và library-aware.
# Đặt reports của hai lần chạy cross-ISA vào (hoặc đặt G=..., L=... khi gọi):
#   G = reports lần KHÔNG lọc ;  L = reports lần library-aware
# Chạy từ ytuong-moi:  G=<...> L=<...> bash code/12b_chay_A_libaware_xisa.sh   (lặp tới khi in "TẤT CẢ XONG")
# Mặc định dùng GT v2 (mã tác giả vs thư viện); đặt GT=ket_qua/gt để dùng GT v1.
H="${H:-$HOME/mnt/HIN-Static}"; G="${G:-ket_qua/kaggle_libaware_xisa/goc/reports}"; L="${L:-ket_qua/kaggle_libaware_xisa/loc/reports}"
GT="${GT:-ket_qua/gt_v2}"; HAN="${HAN:-150}"; DB=ket_qua/libaware/ham_thu_vien_2020.txt; O=ket_qua/A_xisa; mkdir -p $O
python3 code/13_so_sanh_libaware.py --goc $G/libaware_results.csv --loc $L/libaware_results.csv --out $O > /dev/null 2>&1 \
  && echo "so sánh phát hiện -> $O/SO_SANH_PHAT_HIEN.md"
for TH in $L/libaware_test_hashes_ISA-*_seed*.txt; do
  T=$(basename $TH .txt); T=${T#libaware_test_hashes_}               # vd ISA-ARM_seed10
  cmp -s "$G/libaware_test_hashes_$T.txt" "$TH" || echo "⚠ $T: tập test hai lần chạy khác nhau"
  SG=$G/mhenS_entity_scores_semblock_$T.csv; SL=$L/mhenS_entity_scores_semblock_$T.csv
  for C in goc libfn; do
    CD=ket_qua/A_cache_xisa_${C}_$T; LOG=logs/12b_cache_${C}_$T.log
    grep -q "XONG cache" $LOG 2>/dev/null && continue
    if [ $C = goc ]; then EXTRA=(--scores $SG --ten-diem goc); else EXTRA=(--scores $SG $SL --ten-diem goc loc --libfn $DB); fi
    python3 code/02_dinh_vi_ham.py --tinh-cache --period 2024 --han $HAN --json-dir "$H/dataset-moi" --gt-dir $GT \
      --cache $CD --out $CD "${EXTRA[@]}" >> $LOG 2>&1
    grep -q "XONG cache" $LOG || { echo "$T/$C: cache chưa xong — chạy lại lệnh"; exit 0; }
  done
  for spec in "goc goc moi_ham" "libfn goc bo_thu_vien" "libfn loc bo_thu_vien"; do
    set -- $spec; D=$O/A_${2}_${3}_$T
    [ -f "$D/A_Q1_tong_hop.csv" ] && continue
    X=(); [ $1 = libfn ] && X=(--libfn $DB)
    python3 code/02_dinh_vi_ham.py --json-dir "$H/dataset-moi" --gt-dir $GT --cache ket_qua/A_cache_xisa_${1}_$T --ten-cache $2 \
      --ten-mo-hinh "$(basename $D)" --test-hashes $TH --q4-mau 0 --out $D "${X[@]}" > logs/12b_$(basename $D).log 2>&1
    echo "$(basename $D): $(grep -E '^\| 2024\|test_only \| s_topk ' $D/TOM_TAT_A.md | cut -d'|' -f5,6)"
  done
done
echo "TẤT CẢ XONG"
