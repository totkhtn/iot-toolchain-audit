#!/bin/bash
# Audit stage A for EVERY seed of the 'libsym' scenario found in the reports folder (after the multi-seed Kaggle runs).
# Run from the repository root:   JSON_DIR=<feature JSON root> K=<reports folder> bash code/07b_run_audit_libsym_multiseed.sh
#   - per seed: function-level score cache (resumable, limited to TIME_LIMIT seconds) -> analysis of the 4 variants on
#     the TEST files of that seed
#   - repeat the command until it prints "ALL DONE"; then: python3 code/09_aggregate_libsym.py ...
JSON_DIR="${JSON_DIR:-features}"; K="${K:-workdir/kaggle_libsym_seeds/reports}"; TIME_LIMIT="${TIME_LIMIT:-150}"
mkdir -p logs
S=(S S_libben S_libsym S_libboth)
pending=0
for TH in "$K"/libsym_test_hashes_grouped-2024_seed*.txt; do
  T=$(basename "$TH" .txt); T=${T#libsym_test_hashes_}          # grouped-2024_seedNN
  C=workdir/A_cache_libsym_$T
  F=(); for s in "${S[@]}"; do F+=("$K/mhen${s}_entity_scores_semblock_$T.csv"); done
  if ! grep -q "DONE cache" logs/07b_cache_$T.log 2>/dev/null; then
    python3 code/02_localize_functions.py --compute-cache --period 2024 --time-limit $TIME_LIMIT --json-dir "$JSON_DIR" --gt-dir workdir/gt \
      --scores "${F[@]}" --score-names "${S[@]}" --cache $C --out $C >> logs/07b_cache_$T.log 2>&1
    grep -q "DONE cache" logs/07b_cache_$T.log || { echo "$T: cache not complete yet, run the command again"; pending=1; break; }
  fi
  for s in "${S[@]}"; do
    O=workdir/A_libsym_${s}_$T
    [ -f "$O/A_Q1_summary.csv" ] && continue
    python3 code/02_localize_functions.py --json-dir "$JSON_DIR" --gt-dir workdir/gt --cache $C --cache-model $s \
      --model-name "ict_${s}_$T" --test-hashes "$TH" --q4-sample 0 --out $O > logs/07b_A_${s}_$T.log 2>&1
    echo "$T $s: $(tail -n 1 logs/07b_A_${s}_$T.log)"
  done
done
[ $pending = 0 ] && echo "ALL DONE"
