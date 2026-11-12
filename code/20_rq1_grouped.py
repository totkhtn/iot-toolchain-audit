# -*- coding: utf-8 -*-
"""20_rq1_grouped.py — RQ1 cho bài ISJ chỉ dùng mô hình grouped (10 seed, tệp test, GT v2).
Tỉ trọng bằng chứng theo vai trò, xếp hạng hàm (mean qua seed), và hàm nhận nhiều bằng chứng nhất (gộp seed).
Dùng: python3 code/20_rq1_grouped.py  → ket_qua/rq1_grouped/RQ1_grouped.md"""
import csv, glob, os, re, statistics as st
from collections import defaultdict
R = 'ket_qua'
gt = {}
for r in csv.DictReader(open(f'{R}/gt_v2/gt_ham.csv', encoding='utf-8')):
    gt[(r['file_hash'], r['addr'])] = (r['name'], r['vai_tro'], r['vai_tro_chi_tiet'])
rank = defaultdict(lambda: defaultdict(list)); share = defaultdict(list); top = defaultdict(float); tot = 0.0; nt = 0
for d in sorted(glob.glob(f'{R}/gt_v2_A/A_libsym_S_grouped-2024_seed*')):
    s = re.search(r'seed(\d+)$', d).group(1)
    for r in csv.DictReader(open(f'{d}/A_Q1_tong_hop.csv', encoding='utf-8')):
        if r['nhom'].endswith('test_only'):
            for m in ('auc', 'ap', 'hit5'):
                rank[r['diem']][m].append(float(r[m]))
    tt = [r for r in csv.DictReader(open(f'{d}/A_theo_tep.csv', encoding='utf-8')) if r['is_test'] == 'True']
    test = {r['file_hash'] for r in tt}; nt += len(test)
    for v in ('payload', 'helper', 'khac'):
        share[v].append(st.mean(float(r['ev_share_' + v]) for r in tt if r['ev_share_' + v] not in ('', 'nan')))
    for r in csv.DictReader(open(f'{R}/A_cache_libsym_grouped-2024_seed{s}/cache_ham_2024.csv', encoding='utf-8')):
        if r['file_hash'] in test:
            x = float(r['s_topk_S'])
            if x > 0:
                g = gt.get((r['file_hash'], r['addr']))
                if g:
                    top[(g[0], g[2] or g[1])] += x; tot += x
L = ['# RQ1 grouped (10 seed, test, GT v2); tệp test GT tổng = %d' % nt, '',
     'Tỉ trọng (mean qua seed của mean theo tệp): payload+tác giả %.3f±%.3f, helper %.3f±%.3f, thư viện %.3f±%.3f' % (
     st.mean(share['payload']), st.stdev(share['payload']), st.mean(share['helper']), st.stdev(share['helper']),
     st.mean(share['khac']), st.stdev(share['khac'])), '', '| Điểm | AUC | AP | Hit@5 |', '|---|---|---|---|']
for k, v in rank.items():
    L.append('| %s | %.3f±%.3f | %.3f±%.3f | %.3f±%.3f |' % (k, st.mean(v['auc']), st.stdev(v['auc']), st.mean(v['ap']), st.stdev(v['ap']), st.mean(v['hit5']), st.stdev(v['hit5'])))
L += ['', '| Hàm | vai trò | tỉ trọng gộp |', '|---|---|---|']
for (n, v), x in sorted(top.items(), key=lambda t: -t[1])[:15]:
    L.append('| %s | %s | %.1f%% |' % (n, v, 100 * x / tot))
os.makedirs(f'{R}/rq1_grouped', exist_ok=True)
open(f'{R}/rq1_grouped/RQ1_grouped.md', 'w', encoding='utf-8').write('\n'.join(L) + '\n'); print('\n'.join(L))
