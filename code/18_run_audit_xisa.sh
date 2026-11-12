#!/bin/bash
# Audit stage A for cross-ISA library-aware runs (10 seeds x 5 held-out ISAs), ground truth v2.
# Per ISA: one cache "unfiltered, all functions" (10 unfiltered score files) and one cache "library removed"
# (10 unfiltered + 10 filtered score files), ground-truth files of that ISA only; then 3 settings x 10 seeds are
# analysed. Results: workdir/A_xisa/<ISA>/<setting>_grouped-ISA-<ISA>_seed<s>/
# Run from the repository root:  JSON_DIR=<...> [ISAPAT=ARM] bash code/18_run_audit_xisa.sh     (repeat until "ALL DONE")
# Then: python3 code/19_aggregate_audit_xisa.py --a-dir workdir/A_xisa --out workdir/A_xisa
JSON_DIR="${JSON_DIR:-features}"; K="${K:-workdir/kaggle_libaware_xisa}"; GT="${GT:-workdir/gt_v2}"; TIME_LIMIT="${TIME_LIMIT:-150}"
DB=workdir/libaware/library_functions_2020.txt; T0=$(date +%s); mkdir -p logs
SEEDS=(10 42 100 314 555 777 999 1234 2024 2026)
for ISA in ${ISAPAT:-ARM MIPS PowerPC x64 x86}; do
  O=workdir/A_xisa/$ISA; mkdir -p $O
  TH=$(ls $K/unfiltered/reports/libaware_test_hashes_ISA-${ISA}_seed*.txt 2>/dev/null | head -1)
  [ -z "$TH" ] && TH=workdir/xisa_test_hashes/$ISA.txt          # ARM/MIPS: 2024 subset of the ISA (superset of the test set)
  UF=(); FF=(); UN=(); FN=()
  for s in "${SEEDS[@]}"; do
    UF+=($K/unfiltered/reports/mhenS_entity_scores_semblock_ISA-${ISA}_seed$s.csv); UN+=(u$s)
    FF+=($K/filtered/reports/mhenS_entity_scores_semblock_ISA-${ISA}_seed$s.csv); FN+=(f$s)
  done
  for C in unfiltered libfn; do
    CD=workdir/A_cache_xisa_${C}_$ISA; LOG=logs/18_cache_${C}_$ISA.log
    grep -q "DONE cache" $LOG 2>/dev/null && continue
    left=$(( TIME_LIMIT - ($(date +%s) - T0) )); [ $left -lt 30 ] && { echo "time budget used up: run the command again"; exit 0; }
    if [ $C = unfiltered ]; then EX=(--scores "${UF[@]}" --score-names "${UN[@]}"); else EX=(--scores "${UF[@]}" "${FF[@]}" --score-names "${UN[@]}" "${FN[@]}" --libfn $DB); fi
    python3 code/02_localize_functions.py --compute-cache --period 2024 --time-limit $left --json-dir "$JSON_DIR" --gt-dir $GT \
      --test-hashes $TH --cache $CD --out $CD "${EX[@]}" >> $LOG 2>&1
    grep -q "DONE cache" $LOG || { echo "$ISA/$C: cache not complete yet, run the command again"; exit 0; }
  done
  for s in "${SEEDS[@]}"; do
    for spec in "unfiltered u unfiltered_all_functions" "libfn u unfiltered_non_library" "libfn f filtered_non_library"; do
      set -- $spec; D=$O/${3}_grouped-ISA-${ISA}_seed$s
      [ -f "$D/A_Q1_summary.csv" ] && continue
      [ $(( $(date +%s) - T0 )) -gt $TIME_LIMIT ] && { echo "time budget used up: run the command again"; exit 0; }
      X=(); [ $1 = libfn ] && X=(--libfn $DB)
      python3 code/02_localize_functions.py --json-dir "$JSON_DIR" --gt-dir $GT --cache workdir/A_cache_xisa_${1}_$ISA \
        --cache-model $2$s --model-name "$(basename $D)" --test-hashes $TH --q4-sample 0 --out $D "${X[@]}" > logs/18_$(basename $D).log 2>&1
    done
  done
  echo "$ISA: done"
done
echo "ALL DONE"
