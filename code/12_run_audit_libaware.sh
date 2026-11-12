#!/bin/bash
# After the library-aware Kaggle runs (see docs/TRAINING.md). Put the reports of the two runs into:
#   workdir/kaggle_libaware/unfiltered/reports/   (LIBFN_HASHES = null: unfiltered control)
#   workdir/kaggle_libaware/filtered/reports/     (LIBFN_HASHES = library_functions_2020.txt: library-aware)
# Run from the repository root:  JSON_DIR=<feature JSON root> bash code/12_run_audit_libaware.sh
#   (repeat until it prints "ALL DONE"; the cache resumes)
JSON_DIR="${JSON_DIR:-features}"; U="${U:-workdir/kaggle_libaware/unfiltered/reports}"; F="${F:-workdir/kaggle_libaware/filtered/reports}"
T="${T:-grouped-2024_seed10}"; TIME_LIMIT="${TIME_LIMIT:-150}"; DB=workdir/libaware/library_functions_2020.txt
mkdir -p logs
SU=$U/mhenS_entity_scores_semblock_$T.csv; SF=$F/mhenS_entity_scores_semblock_$T.csv
TH=$F/libaware_test_hashes_$T.txt
cmp -s "$U/libaware_test_hashes_$T.txt" "$TH" || echo "WARNING: the test sets of the two runs DIFFER; check the configuration"
python3 code/13_compare_libaware.py --unfiltered $U/libaware_results.csv --filtered $F/libaware_results.csv --out workdir/libaware

run_cache () {  # $1 = cache folder, $2.. = extra arguments
  local C=$1; shift
  grep -q "DONE cache" logs/12_cache_$(basename $C).log 2>/dev/null && return 0
  python3 code/02_localize_functions.py --compute-cache --period 2024 --time-limit $TIME_LIMIT --json-dir "$JSON_DIR" --gt-dir workdir/gt \
    --cache $C --out $C "$@" >> logs/12_cache_$(basename $C).log 2>&1
  grep -q "DONE cache" logs/12_cache_$(basename $C).log || { echo "$C not complete yet: run the command again"; exit 0; }
}
# (a) unfiltered model, evaluated on ALL functions (as in the earlier stage A runs)
run_cache workdir/A_cache_la_unfiltered --scores $SU --score-names unfiltered
# (b) both models, evaluated ONLY on non-library functions (functions matching the database removed, i.e. exactly what
#     the filtered model sees)
run_cache workdir/A_cache_la_libfn --scores $SU $SF --score-names unfiltered filtered --libfn $DB

analyze () {  # $1 cache, $2 model name in the cache, $3 output folder, $4.. extra arguments
  local C=$1 M=$2 O=$3; shift 3
  [ -f "$O/A_Q1_summary.csv" ] && return 0
  python3 code/02_localize_functions.py --json-dir "$JSON_DIR" --gt-dir workdir/gt --cache $C --cache-model $M \
    --model-name "$(basename $O)" --test-hashes $TH --q4-sample 0 --out $O "$@" > logs/12_$(basename $O).log 2>&1
}
analyze workdir/A_cache_la_unfiltered unfiltered workdir/A_la_unfiltered_all_functions
analyze workdir/A_cache_la_libfn      unfiltered workdir/A_la_unfiltered_non_library --libfn $DB
analyze workdir/A_cache_la_libfn      filtered   workdir/A_la_filtered_non_library --libfn $DB
for O in A_la_unfiltered_all_functions A_la_unfiltered_non_library A_la_filtered_non_library; do
  echo "== $O"; grep -E "^\| 2024\|test_only \| (s_topk|s_sum|b_ninsn|b_random) " workdir/$O/SUMMARY_A.md; grep "test_only:" workdir/$O/SUMMARY_A.md
done
echo "ALL DONE"
