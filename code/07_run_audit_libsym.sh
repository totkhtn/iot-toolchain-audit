#!/bin/bash
# Audit stage A for the four MHEN-S variants of the 'libsym' scenario (after the Kaggle run), one seed.
# Put the files downloaded from /kaggle/working/hin_static_v15_libsym/reports/ into workdir/kaggle_libsym/reports/:
#   mhenS_entity_scores_semblock_grouped-2024_seed10.csv
#   mhenS_libben_entity_scores_semblock_grouped-2024_seed10.csv
#   mhenS_libsym_entity_scores_semblock_grouped-2024_seed10.csv
#   mhenS_libboth_entity_scores_semblock_grouped-2024_seed10.csv
#   libsym_test_hashes_grouped-2024_seed10.txt, libsym_results.csv
# Run from the repository root:  JSON_DIR=<feature JSON root> bash code/07_run_audit_libsym.sh   (resumable: the cache resumes)
#                                STEP=analyze bash code/07_run_audit_libsym.sh                    (analysis only)
JSON_DIR="${JSON_DIR:-features}"; K="${K:-workdir/kaggle_libsym/reports}"; T=grouped-2024_seed10; TIME_LIMIT="${TIME_LIMIT:-160}"
mkdir -p logs
S=(S S_libben S_libsym S_libboth)
FILES=(); for s in "${S[@]}"; do FILES+=("$K/mhen${s}_entity_scores_semblock_$T.csv"); done
if [ "${STEP:-cache}" = cache ]; then
  python3 code/02_localize_functions.py --compute-cache --period 2024 --time-limit $TIME_LIMIT --json-dir "$JSON_DIR" --gt-dir workdir/gt \
    --scores "${FILES[@]}" --score-names "${S[@]}" --cache workdir/A_cache_libsym --out workdir/A_cache_libsym \
    >> logs/07_cache_libsym.log 2>&1
  tail -n 1 logs/07_cache_libsym.log
  grep -q "DONE cache" logs/07_cache_libsym.log || { echo "Cache not complete yet: run this command again."; exit 0; }
fi
for s in "${S[@]}"; do
  python3 code/02_localize_functions.py --json-dir "$JSON_DIR" --gt-dir workdir/gt --cache workdir/A_cache_libsym \
    --cache-model $s --model-name "ict_$s" --test-hashes $K/libsym_test_hashes_$T.txt --out workdir/A_libsym_$s \
    > logs/07_A_$s.log 2>&1
  echo "== $s"; grep -E "^\| 2024\|test_only \| (s_topk|s_sum|b_ninsn|b_random) " workdir/A_libsym_$s/SUMMARY_A.md
done
