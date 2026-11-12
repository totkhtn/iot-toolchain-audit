#!/bin/bash
# Audit stage A for the 'libaware_xisa' scenario (leave one ISA out), unfiltered and library-aware models.
# Put the reports of the two cross-ISA runs into the default folders below (or set U=..., F=... when calling):
#   U = reports of the UNFILTERED run;  F = reports of the library-aware (filtered) run
# Run from the repository root:  JSON_DIR=<...> U=<...> F=<...> bash code/12b_run_audit_libaware_xisa.sh   (repeat until "ALL DONE")
# Ground truth v2 (author code vs library) is used by default; set GT=workdir/gt to use ground truth v1.
JSON_DIR="${JSON_DIR:-features}"; U="${U:-workdir/kaggle_libaware_xisa/unfiltered/reports}"; F="${F:-workdir/kaggle_libaware_xisa/filtered/reports}"
GT="${GT:-workdir/gt_v2}"; TIME_LIMIT="${TIME_LIMIT:-150}"; DB=workdir/libaware/library_functions_2020.txt; O=workdir/A_xisa; mkdir -p $O logs
python3 code/13_compare_libaware.py --unfiltered $U/libaware_results.csv --filtered $F/libaware_results.csv --out $O > /dev/null 2>&1 \
  && echo "detection comparison -> $O/DETECTION_COMPARISON.md"
for TH in $F/libaware_test_hashes_ISA-*_seed*.txt; do
  T=$(basename $TH .txt); T=${T#libaware_test_hashes_}               # e.g. ISA-ARM_seed10
  cmp -s "$U/libaware_test_hashes_$T.txt" "$TH" || echo "WARNING: $T: the test sets of the two runs differ"
  SU=$U/mhenS_entity_scores_semblock_$T.csv; SF=$F/mhenS_entity_scores_semblock_$T.csv
  for C in unfiltered libfn; do
    CD=workdir/A_cache_xisa_${C}_$T; LOG=logs/12b_cache_${C}_$T.log
    grep -q "DONE cache" $LOG 2>/dev/null && continue
    if [ $C = unfiltered ]; then EXTRA=(--scores $SU --score-names unfiltered); else EXTRA=(--scores $SU $SF --score-names unfiltered filtered --libfn $DB); fi
    python3 code/02_localize_functions.py --compute-cache --period 2024 --time-limit $TIME_LIMIT --json-dir "$JSON_DIR" --gt-dir $GT \
      --cache $CD --out $CD "${EXTRA[@]}" >> $LOG 2>&1
    grep -q "DONE cache" $LOG || { echo "$T/$C: cache not complete yet, run the command again"; exit 0; }
  done
  for spec in "unfiltered unfiltered all_functions" "libfn unfiltered non_library" "libfn filtered non_library"; do
    set -- $spec; D=$O/A_${2}_${3}_$T
    [ -f "$D/A_Q1_summary.csv" ] && continue
    X=(); [ $1 = libfn ] && X=(--libfn $DB)
    python3 code/02_localize_functions.py --json-dir "$JSON_DIR" --gt-dir $GT --cache workdir/A_cache_xisa_${1}_$T --cache-model $2 \
      --model-name "$(basename $D)" --test-hashes $TH --q4-sample 0 --out $D "${X[@]}" > logs/12b_$(basename $D).log 2>&1
    echo "$(basename $D): $(grep -E '^\| 2024\|test_only \| s_topk ' $D/SUMMARY_A.md | cut -d'|' -f5,6)"
  done
done
echo "ALL DONE"
