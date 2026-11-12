# -*- coding: utf-8 -*-
"""20_rq1_grouped.py: RQ1 of the paper, grouped models only (10 seeds, test files, ground truth v2).
Evidence shares per role, function ranking (mean over seeds) and the functions that receive the most evidence
(pooled over seeds).
Usage: python3 code/20_rq1_grouped.py  -> workdir/rq1_grouped/RQ1_grouped.md"""
import csv, glob, os, re, statistics as st
from collections import defaultdict
R = 'workdir'
gt = {}
for r in csv.DictReader(open(f'{R}/gt_v2/gt_functions.csv', encoding='utf-8')):
    gt[(r['file_hash'], r['addr'])] = (r['name'], r['role'], r['role_detail'])
rank = defaultdict(lambda: defaultdict(list)); share = defaultdict(list); top = defaultdict(float); tot = 0.0; nt = 0
for d in sorted(glob.glob(f'{R}/gt_v2_A/A_libsym_S_grouped-2024_seed*')):
    s = re.search(r'seed(\d+)$', d).group(1)
    for r in csv.DictReader(open(f'{d}/A_Q1_summary.csv', encoding='utf-8')):
        if r['group'].endswith('test_only'):
            for m in ('auc', 'ap', 'hit5'):
                rank[r['score']][m].append(float(r[m]))
    tt = [r for r in csv.DictReader(open(f'{d}/A_per_file.csv', encoding='utf-8')) if r['is_test'] == 'True']
    test = {r['file_hash'] for r in tt}; nt += len(test)
    for v in ('payload', 'helper', 'other'):
        share[v].append(st.mean(float(r['ev_share_' + v]) for r in tt if r['ev_share_' + v] not in ('', 'nan')))
    for r in csv.DictReader(open(f'{R}/A_cache_libsym_grouped-2024_seed{s}/cache_functions_2024.csv', encoding='utf-8')):
        if r['file_hash'] in test:
            x = float(r['s_topk_S'])
            if x > 0:
                g = gt.get((r['file_hash'], r['addr']))
                if g:
                    top[(g[0], g[2] or g[1])] += x; tot += x
L = ['# RQ1 grouped (10 seeds, test files, GT v2); total GT test files = %d' % nt, '',
     'Evidence shares (mean over seeds of the per-file mean): payload+author %.3f±%.3f, helper %.3f±%.3f, library %.3f±%.3f' % (
     st.mean(share['payload']), st.stdev(share['payload']), st.mean(share['helper']), st.stdev(share['helper']),
     st.mean(share['other']), st.stdev(share['other'])), '', '| Score | AUC | AP | Hit@5 |', '|---|---|---|---|']
for k, v in rank.items():
    L.append('| %s | %.3f±%.3f | %.3f±%.3f | %.3f±%.3f |' % (k, st.mean(v['auc']), st.stdev(v['auc']), st.mean(v['ap']), st.stdev(v['ap']), st.mean(v['hit5']), st.stdev(v['hit5'])))
L += ['', '| Function | Role | Pooled share |', '|---|---|---|']
for (n, v), x in sorted(top.items(), key=lambda t: -t[1])[:15]:
    L.append('| %s | %s | %.1f%% |' % (n, v, 100 * x / tot))
os.makedirs(f'{R}/rq1_grouped', exist_ok=True)
open(f'{R}/rq1_grouped/RQ1_grouped.md', 'w', encoding='utf-8').write('\n'.join(L) + '\n'); print('\n'.join(L))
