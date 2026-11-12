#!/bin/bash
# Giai đoạn A cho cross-ISA library-aware (10 seed × 5 ISA giữ lại), GT v2.
# Mỗi ISA: 1 cache "gốc, mọi hàm" (10 tệp điểm gốc) + 1 cache "bỏ thư viện" (10 gốc + 10 lọc), chỉ tệp GT của ISA đó;
# rồi phân tích 3 cách × 10 seed. Kết quả: ket_qua/A_xisa/<ISA>/<cách>_grouped-ISA-<ISA>_seed<s>/
# Chạy từ ytuong-moi:  [ISAPAT=ARM] bash code/18_chay_A_xisa.sh     (lặp tới "TẤT CẢ XONG")
# Sau đó (từng ISA): python3 code/16_tong_hop_libaware.py --goc <goc>/libaware_results.csv --loc <loc>/libaware_results.csv \
#                       --a-dir ket_qua/A_xisa/<ISA> --out ket_qua/A_xisa/<ISA>/tong_hop
H="${H:-$HOME/mnt/HIN-Static}"; K="${K:-ket_qua/kaggle_libaware_xisa}"; GT="${GT:-ket_qua/gt_v2}"; HAN="${HAN:-150}"
DB=ket_qua/libaware/ham_thu_vien_2020.txt; T0=$(date +%s)
SEEDS=(10 42 100 314 555 777 999 1234 2024 2026)
for ISA in ${ISAPAT:-ARM MIPS PowerPC x64 x86}; do
  O=ket_qua/A_xisa/$ISA; mkdir -p $O
  TH=$(ls $K/goc/reports/libaware_test_hashes_ISA-${ISA}_seed*.txt 2>/dev/null | head -1)
  [ -z "$TH" ] && TH=ket_qua/xisa_test_hashes/$ISA.txt          # ARM/MIPS: tập con 2024 theo ISA (siêu tập của test)
  GF=(); LF=(); GN=(); LN=()
  for s in "${SEEDS[@]}"; do
    GF+=($K/goc/reports/mhenS_entity_scores_semblock_ISA-${ISA}_seed$s.csv); GN+=(g$s)
    LF+=($K/loc/reports/mhenS_entity_scores_semblock_ISA-${ISA}_seed$s.csv); LN+=(l$s)
  done
  for C in goc libfn; do
    CD=ket_qua/A_cache_xisa_${C}_$ISA; LOG=logs/18_cache_${C}_$ISA.log
    grep -q "XONG cache" $LOG 2>/dev/null && continue
    left=$(( HAN - ($(date +%s) - T0) )); [ $left -lt 30 ] && { echo "hết giờ — chạy lại lệnh"; exit 0; }
    if [ $C = goc ]; then EX=(--scores "${GF[@]}" --ten-diem "${GN[@]}"); else EX=(--scores "${GF[@]}" "${LF[@]}" --ten-diem "${GN[@]}" "${LN[@]}" --libfn $DB); fi
    python3 code/02_dinh_vi_ham.py --tinh-cache --period 2024 --han $left --json-dir "$H/dataset-moi" --gt-dir $GT \
      --test-hashes $TH --cache $CD --out $CD "${EX[@]}" >> $LOG 2>&1
    grep -q "XONG cache" $LOG || { echo "$ISA/$C: cache chưa xong — chạy lại lệnh"; exit 0; }
  done
  for s in "${SEEDS[@]}"; do
    for spec in "goc g goc_moi_ham" "libfn g goc_bo_thu_vien" "libfn l loc_bo_thu_vien"; do
      set -- $spec; D=$O/${3}_grouped-ISA-${ISA}_seed$s
      [ -f "$D/A_Q1_tong_hop.csv" ] && continue
      [ $(( $(date +%s) - T0 )) -gt $HAN ] && { echo "hết giờ — chạy lại lệnh"; exit 0; }
      X=(); [ $1 = libfn ] && X=(--libfn $DB)
      python3 code/02_dinh_vi_ham.py --json-dir "$H/dataset-moi" --gt-dir $GT --cache ket_qua/A_cache_xisa_${1}_$ISA \
        --ten-cache $2$s --ten-mo-hinh "$(basename $D)" --test-hashes $TH --q4-mau 0 --out $D "${X[@]}" > logs/18_$(basename $D).log 2>&1
    done
  done
  echo "$ISA: xong"
done
echo "TẤT CẢ XONG"
