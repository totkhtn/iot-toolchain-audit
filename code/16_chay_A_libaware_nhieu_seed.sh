#!/bin/bash
# Giai đoạn A cho library-aware nhiều seed (kịch bản 'libaware', grouped-2024). GT v2 mặc định.
# Chạy từ ytuong-moi:  G=<goc/reports> L=<loc/reports> bash code/16_chay_A_libaware_nhieu_seed.sh   (lặp tới "TẤT CẢ XONG")
# Sau đó: python3 code/16_tong_hop_libaware.py --goc $G/libaware_results.csv --loc $L/libaware_results.csv --a-dir ket_qua/A_la_ms --out ket_qua/libaware_tong_hop
H="${H:-$HOME/mnt/HIN-Static}"; G="${G:-ket_qua/kaggle_libsym/goc/reports}"; L="${L:-ket_qua/kaggle_libsym/loc/reports}"
GT="${GT:-ket_qua/gt_v2}"; HAN="${HAN:-150}"; DB=ket_qua/libaware/ham_thu_vien_2020.txt; O=ket_qua/A_la_ms; mkdir -p $O
T0=$(date +%s)
for TH in $L/libaware_test_hashes_grouped-*_seed${SEEDPAT:-*}.txt; do
  T=$(basename $TH .txt); T=${T#libaware_test_hashes_}
  cmp -s "$G/libaware_test_hashes_$T.txt" "$TH" || echo "⚠ $T: tập test hai lần chạy khác nhau"
  SG=$G/mhenS_entity_scores_semblock_$T.csv; SL=$L/mhenS_entity_scores_semblock_$T.csv
  for C in goc libfn; do
    CD=ket_qua/A_cache_la_ms_${C}_$T; LOG=logs/16_cache_${C}_$T.log
    grep -q "XONG cache" $LOG 2>/dev/null && continue
    left=$(( HAN - ($(date +%s) - T0) )); [ $left -lt 40 ] && { echo "hết giờ lượt này — chạy lại lệnh"; exit 0; }
    if [ $C = goc ]; then EXTRA=(--scores $SG --ten-diem goc); else EXTRA=(--scores $SG $SL --ten-diem goc loc --libfn $DB); fi
    python3 code/02_dinh_vi_ham.py --tinh-cache --period 2024 --han $left --json-dir "$H/dataset-moi" --gt-dir $GT \
      --cache $CD --out $CD "${EXTRA[@]}" >> $LOG 2>&1
    grep -q "XONG cache" $LOG || { echo "$T/$C: cache chưa xong — chạy lại lệnh"; exit 0; }
  done
  for spec in "goc goc moi_ham" "libfn goc bo_thu_vien" "libfn loc bo_thu_vien"; do
    set -- $spec; D=$O/${2}_${3}_$T
    [ -f "$D/A_Q1_tong_hop.csv" ] && continue
    [ $(( $(date +%s) - T0 )) -gt $HAN ] && { echo "hết giờ lượt này — chạy lại lệnh"; exit 0; }
    X=(); [ $1 = libfn ] && X=(--libfn $DB)
    python3 code/02_dinh_vi_ham.py --json-dir "$H/dataset-moi" --gt-dir $GT --cache ket_qua/A_cache_la_ms_${1}_$T --ten-cache $2 \
      --ten-mo-hinh "$(basename $D)" --test-hashes $TH --q4-mau 0 --out $D "${X[@]}" > logs/16_$(basename $D).log 2>&1
    echo "$(basename $D): xong"
  done
done
echo "TẤT CẢ XONG"
