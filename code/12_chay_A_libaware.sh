#!/bin/bash
# Sau khi chạy Kaggle library-aware (KAGGLE_LIBAWARE.md). Đặt reports của hai lần chạy vào:
#   ket_qua/kaggle_libaware/goc/reports/   (LIBFN_HASHES = null — đối chứng không lọc)
#   ket_qua/kaggle_libaware/loc/reports/   (LIBFN_HASHES = ham_thu_vien_2020.txt — library-aware)
# Chạy từ ytuong-moi:  bash code/12_chay_A_libaware.sh      (lặp lại tới khi in "TẤT CẢ XONG"; cache có resume)
H="${H:-$HOME/mnt/HIN-Static}"; G="${G:-ket_qua/kaggle_libaware/goc/reports}"; L="${L:-ket_qua/kaggle_libaware/loc/reports}"
T="${T:-grouped-2024_seed10}"; HAN="${HAN:-150}"; DB=ket_qua/libaware/ham_thu_vien_2020.txt
SG=$G/mhenS_entity_scores_semblock_$T.csv; SL=$L/mhenS_entity_scores_semblock_$T.csv
TH=$L/libaware_test_hashes_$T.txt
cmp -s "$G/libaware_test_hashes_$T.txt" "$TH" || echo "⚠ tập test của hai lần chạy KHÁC nhau — kiểm tra lại cấu hình"
python3 code/13_so_sanh_libaware.py --goc $G/libaware_results.csv --loc $L/libaware_results.csv --out ket_qua/libaware

run_cache () {  # $1 = thư mục cache, $2.. = tham số thêm
  local C=$1; shift
  grep -q "XONG cache" logs/12_cache_$(basename $C).log 2>/dev/null && return 0
  python3 code/02_dinh_vi_ham.py --tinh-cache --period 2024 --han $HAN --json-dir "$H/dataset-moi" --gt-dir ket_qua/gt \
    --cache $C --out $C "$@" >> logs/12_cache_$(basename $C).log 2>&1
  grep -q "XONG cache" logs/12_cache_$(basename $C).log || { echo "$C chưa xong — chạy lại lệnh"; exit 0; }
}
# (a) mô hình gốc, đánh giá trên MỌI hàm (như giai đoạn A trước)
run_cache ket_qua/A_cache_la_goc --scores $SG --ten-diem goc
# (b) cả hai mô hình, đánh giá CHỈ trên hàm không phải thư viện (bỏ hàm khớp CSDL — đúng cái mô hình lọc nhìn thấy)
run_cache ket_qua/A_cache_la_libfn --scores $SG $SL --ten-diem goc loc --libfn $DB

phan () {  # $1 cache, $2 tên mô hình trong cache, $3 thư mục ra, $4.. thêm
  local C=$1 M=$2 O=$3; shift 3
  [ -f "$O/A_Q1_tong_hop.csv" ] && return 0
  python3 code/02_dinh_vi_ham.py --json-dir "$H/dataset-moi" --gt-dir ket_qua/gt --cache $C --ten-cache $M \
    --ten-mo-hinh "$(basename $O)" --test-hashes $TH --q4-mau 0 --out $O "$@" > logs/12_$(basename $O).log 2>&1
}
phan ket_qua/A_cache_la_goc   goc ket_qua/A_la_goc_moi_ham
phan ket_qua/A_cache_la_libfn goc ket_qua/A_la_goc_bo_thu_vien --libfn $DB
phan ket_qua/A_cache_la_libfn loc ket_qua/A_la_loc_bo_thu_vien --libfn $DB
for O in A_la_goc_moi_ham A_la_goc_bo_thu_vien A_la_loc_bo_thu_vien; do
  echo "== $O"; grep -E "^\| 2024\|test_only \| (s_topk|s_sum|b_ninsn|b_random) " ket_qua/$O/TOM_TAT_A.md; grep "test_only:" ket_qua/$O/TOM_TAT_A.md
done
echo "TẤT CẢ XONG"
