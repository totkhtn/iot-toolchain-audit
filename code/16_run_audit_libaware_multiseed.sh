#!/bin/bash
# Audit stage A for the library-aware experiment over several seeds ('libaware' scenario, grouped-2024). Ground truth v2 by default.
# Run from the repository root:  JSON_DIR=<...> U=<unfiltered/reports> F=<filtered/reports> bash code/16_run_audit_libaware_multiseed.sh
#   (repeat until "ALL DONE")
# Then: python3 code/16_aggregate_libaware.py --unfiltered $U/libaware_results.csv --filtered $F/libaware_results.csv \
#           --a-dir workdir/A_la_ms --out workdir/libaware_summary
JSON_DIR="${JSON_DIR:-features}"; U="${U:-workdir/kaggle_libaware/unfiltered/reports}"; F="${F:-workdir/kaggle_libaware/filtered/reports}"
GT="${GT:-workdir/gt_v2}"; TIME_LIMIT="${TIME_LIMIT:-150}"; DB=workdir/libaware/library_functions_2020.txt; O=workdir/A_la_ms; mkdir -p $O logs
T0=$(date +%s)
for TH in $F/libaware_test_hashes_grouped-*_seed${SEEDPAT:-*}.txt; do
  T=$(basename $TH .txt); T=${T#libaware_test_hashes_}
  cmp -s "$U/libaware_test_hashes_$T.txt" "$TH" || echo "WARNING: $T: the test sets of the two runs differ"
  SU=$U/mhenS_entity_scores_semblock_$T.csv; SF=$F/mhenS_entity_scores_semblock_$T.csv
  for C in unfiltered libfn; do
    CD=workdir/A_cache_la_ms_${C}_$T; LOG=logs/16_cache_${C}_$T.log
    grep -q "DONE cache" $LOG 2>/dev/null && continue
    left=$(( TIME_LIMIT - ($(date +%s) - T0) )); [ $left -lt 40 ] && { echo "time budget of this call used up: run the command again"; exit 0; }
    if [ $C = unfiltered ]; then EXTRA=(--scores $SU --score-names unfiltered); else EXTRA=(--scores $SU $SF --score-names unfiltered filtered --libfn $DB); fi
    python3 code/02_localize_functions.py --compute-cache --period 2024 --time-limit $left --json-dir "$JSON_DIR" --gt-dir $GT \
      --cache $CD --out $CD "${EXTRA[@]}" >> $LOG 2>&1
    grep -q "DONE cache" $LOG || { echo "$T/$C: cache not complete yet, run the command again"; exit 0; }
  done
  for spec in "unfiltered unfiltered all_functions" "libfn unfiltered non_library" "libfn filtered non_library"; do
    set -- $spec; D=$O/${2}_${3}_$T
    [ -f "$D/A_Q1_summary.csv" ] && continue
    [ $(( $(date +%s) - T0 )) -gt $TIME_LIMIT ] && { echo "time budget of this call used up: run the command again"; exit 0; }
    X=(); [ $1 = libfn ] && X=(--libfn $DB)
    python3 code/02_localize_functions.py --json-dir "$JSON_DIR" --gt-dir $GT --cache workdir/A_cache_la_ms_${1}_$T --cache-model $2 \
      --model-name "$(basename $D)" --test-hashes $TH --q4-sample 0 --out $D "${X[@]}" > logs/16_$(basename $D).log 2>&1
    echo "$(basename $D): done"
  done
done
echo "ALL DONE"
