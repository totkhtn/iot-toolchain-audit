# -*- coding: utf-8 -*-
"""02_dinh_vi_ham.py — Giai đoạn A: định vị hàm độc từ điểm bằng chứng của MHEN-S (không cần GPU, không huấn luyện lại).

Ý tưởng (mượn từ XAIDroid, JISA 2026): mô hình chỉ học nhãn cấp tệp; điểm của nút được cộng lên cấp hàm rồi so với
ground truth cấp hàm. Khác XAIDroid ở hai điểm:
  1. MHEN-S có hạng bằng chứng CỘNG TÍNH: evidence(f) = sum_t softplus(w_t) * TopK_{e in N_t(f)} s_e. Vì vậy phần đóng
     góp của từng chữ ký semblock vào bằng chứng là CHÍNH XÁC (không phải giải thích hậu nghiệm như attention).
     Điểm 'topk' bên dưới chia đúng phần đóng góp đó về các block, rồi cộng lên hàm.
  2. Ground truth lấy tự động từ .symtab của tệp gốc (01_trich_symtab_gt.py) thay vì gán tay 135 mẫu.

Câu hỏi trả lời ở giai đoạn này:
  Q1  Định vị:      điểm hàm có xếp hàm 'payload' lên trên không? (AUC, AP, Hit@k, công sức analyst) so với baseline.
  Q1b Lối tắt:      bao nhiêu % bằng chứng rơi vào hàm thư viện ('khac') thay vì 'payload'?
  Q1c Phủ từ vựng:  bao nhiêu % hàm payload không có chữ ký nào trong từ vựng (điểm = 0, như 'API chưa thấy' ở XAIDroid)?
  Q3  Cross-ISA:    cùng tên hàm payload trên các ISA có thứ hạng tương tự không? (so với baseline kích thước hàm)
  Q4a Drift (phần không cần dự đoán): độ phủ từ vựng và khối lượng bằng chứng của tệp 2020 so với 2024.
Q2 (fidelity xoá top-k) và Q4b (điểm lệch dự báo lỗi) cần mô hình/dự đoán -> giai đoạn B (03_*, trên Kaggle).

Hai chế độ:
  --lap-danh-sach : từ kiem_ke_*.csv chọn mã độc còn ký hiệu, đọc file_path trong JSON -> danh_sach_tep_goc.csv
                    (đưa sang máy Linux cho 01_trich_symtab_gt.py).
  (mặc định)      : chạy Q1/Q1b/Q1c/Q3/Q4a.

Ví dụ (Windows/VM hoặc Kaggle CPU):
  python 02_dinh_vi_ham.py --lap-danh-sach --kiem-ke ket_qua/kiem_ke_dataset_moi_2020.csv ket_qua/kiem_ke_dataset_moi_2024.csv \
         --json-dir .../HIN-Static/dataset-moi --out ket_qua
  python 02_dinh_vi_ham.py --json-dir .../dataset-moi --gt-dir ket_qua/gt \
         --scores .../reports/mhenS_entity_scores_semblock_grouped-2024_seed10.csv \
         --kiem-ke ket_qua/kiem_ke_dataset_moi_2020.csv ket_qua/kiem_ke_dataset_moi_2024.csv \
         --ten-mo-hinh mhenS_seed10 --out ket_qua/A_seed10
"""
import argparse, csv, glob, gzip, json, math, os, random, re, sys, time
from collections import defaultdict

SEM_DROP = {'nop'}
MIN_INSNS = 3            # = CFG['BLOCK_MIN_INSNS'] của hin_static_v15
TOPK = 8                 # = CFG['MHEN_TOPK']
ISAS = ['ARM', 'MIPS', 'PowerPC', 'x86', 'x64']
_ARCH = {'EM_ARM': 'ARM', 'EM_MIPS': 'MIPS', 'EM_PPC': 'PowerPC', 'EM_386': 'x86', 'EM_X86_64': 'x64'}


def log(*a):
    print(time.strftime('%H:%M:%S'), *a, flush=True)


def doc_json(p):
    op = gzip.open if p.endswith('.gz') else open
    with op(p, 'rt', encoding='utf-8', errors='ignore') as f:
        return json.load(f)


def sem_key(sem):
    s = [x for x in sem if x not in SEM_DROP]
    return 'S:' + '|'.join(s) if len(s) >= MIN_INSNS else None


def hash_tu_ten(p):
    """Tên tệp: <sha256>[.elf]__<8 ký tự>_static.json.gz -> 64 ký tự hex đầu (khớp 00_kiem_ke.py)."""
    b = os.path.basename(p)
    m = re.match(r'[0-9a-fA-F]{64}', b)
    return m.group(0).lower() if m else b.split('__')[0].split('_')[0]


def tim_json(json_dir):
    m = {}
    for p in glob.glob(os.path.join(json_dir, '*', 'tap_chinh', '**', '*.json*'), recursive=True):
        per = os.path.relpath(p, json_dir).split(os.sep)[0]
        m[(per, hash_tu_ten(p))] = p
    return m


def doc_kiem_ke(paths):
    rows = []
    for p in paths:
        with open(p, newline='', encoding='utf-8') as f:
            rows += list(csv.DictReader(f))
    return rows


# ------------------------------------------------------------------ chế độ lập danh sách
def lap_danh_sach(a):
    kk = doc_kiem_ke(a.kiem_ke)
    js = tim_json(a.json_dir)
    chon = [r for r in kk if r.get('label') == '1' and r.get('is_stripped') == '0' and r.get('status') == 'ok']
    log('mã độc còn ký hiệu:', len(chon))
    os.makedirs(a.out, exist_ok=True)
    out = os.path.join(a.out, 'danh_sach_tep_goc.csv')
    with open(out, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['file_hash', 'file_path', 'period', 'arch'])
        for r in chon:
            p = js.get((r['period'], r['file_hash']))
            if p:
                w.writerow([r['file_hash'], doc_json(p).get('file_path'), r['period'], r['arch']])
    log('đã ghi', out)


# ------------------------------------------------------------------ đọc điểm thực thể + ground truth
def doc_diem(path):
    s = {}
    with open(path, newline='', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            if r.get('entity_type', 'semblock') == 'semblock':
                s[r['entity']] = float(r['malice_score'])
    log('điểm semblock:', len(s), 'thực thể từ', os.path.basename(path))
    return s


# (24/10) Bổ sung QUY_TAC của 01: tên hàm mã độc bị bỏ sót (giống MA_DOC_THEM trong 05_tao_chu_ky_thu_vien.py)
MA_DOC_THEM = re.compile(r'flood|attack|scanner|killer|watchdog|vse|deobf|random_string|^astd$|^add_strings$|'
                         r'^add_entry$|^rand_alpha_str$|^rand_int$|^rand_next_range$|^getRandom|^makeRandom|huawei|'
                         r'exploit|botkill|^csum$|^trim$|^itoa$|cnc|^do_clone$', re.I)


def doc_gt(gt_dir):
    ham = defaultdict(dict)
    with open(os.path.join(gt_dir, 'gt_ham.csv'), newline='', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            vt = r['vai_tro']
            if vt == 'khac' and MA_DOC_THEM.search(r['name']):
                vt = 'payload'
            ham[r['file_hash']][int(r['addr'])] = (r['name'], vt)
    tep = {}
    with open(os.path.join(gt_dir, 'gt_tep.csv'), newline='', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            tep[r['file_hash']] = r
    return ham, tep


# ------------------------------------------------------------------ điểm cấp hàm cho một tệp
LIBFN = None      # (24/10) tập băm hàm thư viện (--libfn): hàm khớp bị BỎ khỏi đánh giá (giống library-aware HIN)


def ham_thu_vien_cua_tep(d):
    """Địa chỉ (chuỗi hex) các hàm có băm md5(arch#ops)[:16] trong LIBFN — giống hệt hin_static_v15_libaware.py."""
    if not LIBFN:
        return set()
    import hashlib
    arch = str(d.get('arch') or '')
    G = defaultdict(list)
    for nd in (d.get('cfg_graph') or {}).get('nodes') or []:
        G[nd.get('func')].append(nd)
    out = set()
    for fa, nds in G.items():
        ops = '/'.join(','.join(nd.get('ops_seq') or []) for nd in sorted(nds, key=lambda x: x.get('addr', 0)))
        if hashlib.md5((arch + '#' + ops).encode()).hexdigest()[:16] in LIBFN:
            out.add(fa)
    return out


def ham_cua_tep(d, diem):
    """Trả về {addr_ham: dict(n_blocks, ninsn, n_sys, s_sum, s_max, keys:set)} và thông tin tệp."""
    F = defaultdict(lambda: dict(n_blocks=0, ninsn=0, n_sys=0, s_sum=0.0, s_max=0.0, keys=defaultdict(int)))
    sig_tep = set()
    n_sem = n_vocab = 0
    bo = ham_thu_vien_cua_tep(d)
    for nd in (d.get('cfg_graph') or {}).get('nodes') or []:
        if nd.get('func') in bo:
            continue
        fa = int(nd['func'], 16)
        g = F[fa]
        tf = nd.get('opcodes_tf') or {}
        ni = sum(int(v) for v in tf.values())
        g['n_blocks'] += 1; g['ninsn'] += ni
        g['n_sys'] += int((nd.get('sem_tf') or {}).get('syscall', 0) > 0)
        if ni < MIN_INSNS:
            continue
        k = sem_key(nd.get('sem_seq') or [])
        if not k:
            continue
        n_sem += 1
        sig_tep.add(k)
        if k in diem:
            n_vocab += 1
            v = diem[k]
            g['s_sum'] += v; g['s_max'] = max(g['s_max'], v); g['keys'][k] += 1
    # --- phần đóng góp CHÍNH XÁC vào bằng chứng MHEN: top-K chữ ký khác nhau của tệp ---
    trong = sorted((k for k in sig_tep if k in diem), key=lambda k: -diem[k])[:TOPK]
    ev = sum(diem[k] for k in trong)
    dem = defaultdict(int)
    for g in F.values():
        for k, c in g['keys'].items():
            dem[k] += c
    for g in F.values():
        g['s_topk'] = sum(diem[k] * c / dem[k] for k, c in g['keys'].items() if k in trong)
    info = dict(n_sem=n_sem, n_sig=len(sig_tep), n_sig_vocab=sum(k in diem for k in sig_tep),
                frac_block_vocab=n_vocab / n_sem if n_sem else 0.0, evidence_topk=ev)
    return F, info


# ------------------------------------------------------------------ chỉ số xếp hạng
def auc(pos, neg):
    if not pos or not neg:
        return float('nan')
    allv = sorted([(v, 1) for v in pos] + [(v, 0) for v in neg])
    r, i, sp = 0.0, 0, 0.0
    while i < len(allv):                      # hạng trung bình cho giá trị bằng nhau
        j = i
        while j < len(allv) and allv[j][0] == allv[i][0]:
            j += 1
        rk = (i + j + 1) / 2.0
        sp += rk * sum(1 for t in allv[i:j] if t[1] == 1)
        i = j
    n1, n0 = len(pos), len(neg)
    return (sp - n1 * (n1 + 1) / 2.0) / (n1 * n0)


def ap(scores, labels):
    o = sorted(zip(scores, labels), key=lambda t: -t[0])
    tp, s, P = 0, 0.0, sum(labels)
    if not P:
        return float('nan')
    for i, (_, l) in enumerate(o, 1):
        if l:
            tp += 1; s += tp / i
    return s / P


def xep_hang(scores, rng):
    """Thứ hạng 1 = điểm cao nhất; hoà điểm thì xếp ngẫu nhiên (không ưu ái phương pháp nào)."""
    idx = list(range(len(scores)))
    rng.shuffle(idx)
    idx.sort(key=lambda i: -scores[i])
    rank = [0] * len(scores)
    for r, i in enumerate(idx, 1):
        rank[i] = r
    return rank


def bootstrap(vals, B=2000, seed=0):
    """Trung bình và CI95 bootstrap theo TỆP (numpy, vector hoá)."""
    import numpy as np
    v = np.array([x for x in vals if x == x], dtype=float)
    if not len(v):
        return float('nan'), float('nan'), float('nan')
    rng = np.random.default_rng(seed)
    ms = v[rng.integers(0, len(v), size=(B, len(v)))].mean(1)
    return float(v.mean()), float(np.quantile(ms, 0.025)), float(np.quantile(ms, 0.975))


def spearman(x, y):
    n = len(x)
    if n < 3:
        return float('nan')
    def rk(a):
        o = sorted(range(n), key=lambda i: a[i]); r = [0.0] * n
        i = 0
        while i < n:
            j = i
            while j < n and a[o[j]] == a[o[i]]:
                j += 1
            for t in range(i, j):
                r[o[t]] = (i + j - 1) / 2.0
            i = j
        return r
    rx, ry = rk(x), rk(y)
    mx, my = sum(rx) / n, sum(ry) / n
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den = math.sqrt(sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry))
    return num / den if den else float('nan')


DIEM = ['s_topk', 's_sum', 's_max']                       # điểm từ mô hình
BASE = ['b_ninsn', 'b_nblocks', 'b_nsys', 'b_random']     # baseline không dùng mô hình


# ------------------------------------------------------------------ chế độ phân tích
def phan_tich(a):
    rng = random.Random(a.seed)
    diem = doc_diem(a.scores) if not a.cache else None
    if a.cache:
        a.q4_mau = 0                       # Q4a đầy đủ đã chạy riêng (--chi-q4a)
    ham_gt, tep_gt = doc_gt(a.gt_dir)
    kk = {(r['period'], r['file_hash']): r for r in doc_kiem_ke(a.kiem_ke)} if a.kiem_ke else {}
    js = tim_json(a.json_dir) if a.json_dir else {}
    if not js and a.cache:   # (release) analysis from the function-level cache only, no JSON needed
        js = dict.fromkeys(doc_cache(a.cache, a.ten_cache))
    test_set = None
    if a.test_hashes:
        with open(a.test_hashes, encoding='utf-8') as f:
            test_set = {l.strip() for l in f if l.strip()}
    os.makedirs(a.out, exist_ok=True)

    tep_rows, ham_rows = [], []
    cac = [(per, h) for (per, h) in js if h in tep_gt and int(tep_gt[h].get('n_payload') or 0) > 0]
    if a.max_files:
        cac = cac[:a.max_files]
    log('tệp có ground truth payload:', len(cac))
    cache = doc_cache(a.cache, a.ten_cache) if a.cache else None
    n_bo_khong_khop = [0]
    for i, (per, h) in enumerate(sorted(cac)):
        if cache is not None:
            if (per, h) not in cache:
                continue
            F, info, arch0 = cache[(per, h)]
            d = {'arch': arch0}
        else:
            d = doc_json(js[(per, h)])
            F, info = ham_cua_tep(d, diem)
        gt = ham_gt.get(h, {})
        addrs = [fa for fa in F if fa in gt]                       # chỉ hàm khớp được ký hiệu
        if not addrs:
            continue
        lab = [1 if gt[fa][1] == 'payload' else 0 for fa in addrs]
        vt = [gt[fa][1] for fa in addrs]
        cols = {k: [F[fa][k] for fa in addrs] for k in DIEM}
        cols['b_ninsn'] = [F[fa]['ninsn'] for fa in addrs]
        cols['b_nblocks'] = [F[fa]['n_blocks'] for fa in addrs]
        cols['b_nsys'] = [F[fa]['n_sys'] for fa in addrs]
        cols['b_random'] = [rng.random() for _ in addrs]
        arch = _ARCH.get(d.get('arch'), d.get('arch'))
        row = dict(period=per, file_hash=h, arch=arch, ho=tep_gt[h].get('ho_doan'),
                   is_test=(h in test_set) if test_set is not None else '', n_ham=len(addrs), n_payload=sum(lab),
                   n_ham_r2=len(F), n_ham_symtab=len(gt), **info)
        tot = sum(cols['s_topk']) or 1.0
        for r_ in ('payload', 'helper', 'khac'):
            row['ev_share_' + r_] = sum(c for c, v in zip(cols['s_topk'], vt) if v == r_) / tot if sum(cols['s_topk']) else float('nan')
        pay_idx = [j for j, l in enumerate(lab) if l]
        if not pay_idx:                # có payload trong .symtab nhưng r2 không tìm thấy hàm nào trong số đó
            n_bo_khong_khop[0] += 1
            continue
        row['payload_khong_vocab'] = sum(1 for j in pay_idx if not F[addrs[j]]['keys']) / len(pay_idx)
        neg_idx = [j for j, v in enumerate(vt) if v == 'khac']       # nghiêm: payload vs thư viện/khác (bỏ helper)
        for k in DIEM + BASE:
            sc = cols[k]
            row['auc_' + k] = auc([sc[j] for j in pay_idx], [sc[j] for j in neg_idx])
            row['ap_' + k] = ap(sc, lab)
            rk = xep_hang(sc, rng)
            best = min(rk[j] for j in pay_idx)
            row['hit1_' + k] = int(best <= 1); row['hit5_' + k] = int(best <= 5); row['hit10_' + k] = int(best <= 10)
            row['p10_' + k] = sum(1 for j in pay_idx if rk[j] <= 10) / min(10, len(addrs))
            row['effort_first_' + k] = best / len(addrs)                       # % số hàm phải xem tới payload đầu tiên
            half = sorted(rk[j] for j in pay_idx)[max(0, math.ceil(len(pay_idx) / 2) - 1)]
            row['effort_half_' + k] = half / len(addrs)                        # ... tới khi gặp một nửa số payload
            if k in ('s_topk', 's_sum', 'b_ninsn'):
                for j, fa in enumerate(addrs):
                    if vt[j] == 'payload':
                        ham_rows.append(dict(period=per, file_hash=h, arch=arch, name=gt[fa][0], diem=k,
                                             pct_rank=(rk[j] - 1) / max(1, len(addrs) - 1), score=sc[j]))
        tep_rows.append(row)
        if (i + 1) % 200 == 0:
            log('%d/%d' % (i + 1, len(cac)))

    if not tep_rows:
        sys.exit('Không có tệp nào khớp ground truth.')
    log('bỏ %d tệp: không hàm payload nào khớp địa chỉ hàm của r2' % n_bo_khong_khop[0])
    ghi_csv(os.path.join(a.out, 'A_theo_tep.csv'), tep_rows)
    ghi_csv(os.path.join(a.out, 'A_payload_rank.csv'), ham_rows)

    # ---- Tổng hợp Q1/Q1b/Q1c theo giai đoạn × ISA ----
    tong = []
    def nhom(rows, ten):
        for k in DIEM + BASE:
            r = dict(nhom=ten, n_tep=len(rows), diem=k)
            for m in ('auc', 'ap', 'hit1', 'hit5', 'hit10', 'p10', 'effort_first', 'effort_half'):
                mu, lo, hi = bootstrap([x[m + '_' + k] for x in rows])
                r[m] = mu; r[m + '_lo'] = lo; r[m + '_hi'] = hi
            tong.append(r)
    pers = sorted({r['period'] for r in tep_rows})
    for per in pers:
        rr = [r for r in tep_rows if r['period'] == per]
        nhom(rr, per)
        for isa in ISAS:
            sub = [r for r in rr if r['arch'] == isa]
            if len(sub) >= a.min_tep:
                nhom(sub, '%s|%s' % (per, isa))
        if test_set is not None:
            nhom([r for r in rr if r['is_test']], per + '|test_only')
    ghi_csv(os.path.join(a.out, 'A_Q1_tong_hop.csv'), tong)

    # ---- Q3: nhất quán thứ hạng giữa ISA (cùng tên hàm payload) ----
    q3 = []
    for per in pers:
        for k in ('s_topk', 's_sum', 'b_ninsn'):
            m = defaultdict(list)
            for r in ham_rows:
                if r['period'] == per and r['diem'] == k:
                    m[(r['name'], r['arch'])].append(r['pct_rank'])
            mean = {key: sum(v) / len(v) for key, v in m.items() if len(v) >= a.min_tep_ten}
            for i1, A in enumerate(ISAS):
                for B in ISAS[i1 + 1:]:
                    names = sorted({n for (n, s) in mean if s == A} & {n for (n, s) in mean if s == B})
                    x = [mean[(n, A)] for n in names]; y = [mean[(n, B)] for n in names]
                    q3.append(dict(period=per, diem=k, isa_a=A, isa_b=B, n_ten=len(names), spearman=spearman(x, y),
                                   mean_abs_diff=sum(abs(p - q) for p, q in zip(x, y)) / len(x) if x else float('nan')))
    ghi_csv(os.path.join(a.out, 'A_Q3_cross_isa.csv'), q3)

    # ---- Q4a: drift từ vựng / bằng chứng trên MỌI tệp trong kiểm kê (không cần ground truth) ----
    if a.q4_mau and kk:
        q4 = []
        for per in pers:
            for lab in ('0', '1'):
                ds = [key for key, r in kk.items() if key[0] == per and r.get('label') == lab and r.get('status') == 'ok']
                rng.shuffle(ds)
                for key in ds[:a.q4_mau]:
                    if key not in js:
                        continue
                    _, info = ham_cua_tep(doc_json(js[key]), diem)
                    q4.append(dict(period=per, label=lab, file_hash=key[1], arch=kk[key].get('arch'), **info))
        ghi_csv(os.path.join(a.out, 'A_Q4a_drift_tu_vung.csv'), q4)

    viet_tom_tat(a, tep_rows, tong, q3)
    log('XONG ->', a.out)


INFO_K = ('n_sem', 'n_sig', 'n_sig_vocab', 'frac_block_vocab', 'evidence_topk')


def tinh_cache(a):
    """Đọc JSON MỘT lần cho mọi tệp có GT payload, tính điểm cấp hàm cho nhiều mô hình, ghi cache (chạy tiếp được,
    có hạn --han giây). phan_tich(--cache) sau đó chỉ đọc cache -> nhanh, không cần đọc lại 2.000 JSON."""
    ten = a.ten_diem or ['m%d' % i for i in range(len(a.scores))]
    diems = [doc_diem(p) for p in a.scores]
    _, tep_gt = doc_gt_tep(a.gt_dir)
    js = tim_json(a.json_dir)
    os.makedirs(a.cache, exist_ok=True)
    f_ham, f_tep = os.path.join(a.cache, 'cache_ham_%s.csv' % a.period), os.path.join(a.cache, 'cache_tep_%s.csv' % a.period)
    xong = set()
    if os.path.exists(f_tep):
        with open(f_tep, newline='', encoding='utf-8') as f:
            xong = {r['file_hash'] for r in csv.DictReader(f)}
    cot_h = ['period', 'file_hash', 'addr', 'n_blocks', 'ninsn', 'n_sys'] + \
        ['%s_%s' % (k, t) for t in ten for k in ('s_sum', 's_max', 's_topk', 'nk')]
    cot_t = ['period', 'file_hash', 'arch'] + ['%s_%s' % (k, t) for t in ten for k in INFO_K]
    viec = sorted(k for k in js if k[0] == a.period and k[1] in tep_gt and int(tep_gt[k[1]].get('n_payload') or 0) > 0
                  and k[1] not in xong)
    if a.test_hashes:                     # (25/10) chỉ tính cache cho tệp thuộc tập test (vd ISA giữ lại ở cross-ISA)
        with open(a.test_hashes, encoding='utf-8') as f:
            chi = {l.strip() for l in f if l.strip()}
        viec = [k for k in viec if k[1] in chi]
    log('cache %s: còn %d tệp (đã xong %d)' % (a.period, len(viec), len(xong)))
    t0, n = time.time(), 0
    moi = not xong
    with open(f_ham, 'a', newline='', encoding='utf-8') as fh, open(f_tep, 'a', newline='', encoding='utf-8') as ft:
        wh, wt = csv.DictWriter(fh, fieldnames=cot_h), csv.DictWriter(ft, fieldnames=cot_t)
        if moi:
            wh.writeheader(); wt.writeheader()
        for key in viec:
            d = doc_json(js[key])
            res = [ham_cua_tep(d, dm) for dm in diems]
            F0 = res[0][0]
            for fa in F0:
                r = dict(period=key[0], file_hash=key[1], addr=fa, n_blocks=F0[fa]['n_blocks'], ninsn=F0[fa]['ninsn'],
                         n_sys=F0[fa]['n_sys'])
                for t, (F, _) in zip(ten, res):
                    g = F[fa]
                    r.update({'s_sum_' + t: round(g['s_sum'], 7), 's_max_' + t: round(g['s_max'], 7),
                              's_topk_' + t: round(g['s_topk'], 7), 'nk_' + t: len(g['keys'])})
                wh.writerow(r)
            rt = dict(period=key[0], file_hash=key[1], arch=d.get('arch'))
            for t, (_, info) in zip(ten, res):
                rt.update({'%s_%s' % (k, t): info[k] for k in INFO_K})
            wt.writerow(rt)                       # ghi tệp SAU hàm -> dòng tệp có nghĩa là hàm của nó đã đủ
            n += 1
            if n % 100 == 0:
                fh.flush(); ft.flush(); log('%d tệp, %.0fs' % (n, time.time() - t0))
            if time.time() - t0 > a.han:
                log('DUNG_THEO_HAN sau %d tệp' % n); return
    log('XONG cache %s (%d tệp mới)' % (a.period, n))


def doc_gt_tep(gt_dir):
    tep = {}
    with open(os.path.join(gt_dir, 'gt_tep.csv'), newline='', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            tep[r['file_hash']] = r
    return None, tep


def doc_cache(cache_dir, t):
    """-> {(period, hash): (F, info, arch)} cho mô hình t, chỉ các tệp đã có dòng trong cache_tep (đã đủ hàm)."""
    out, xong = {}, set()
    for p in sorted(glob.glob(os.path.join(cache_dir, 'cache_tep_*.csv'))):
        with open(p, newline='', encoding='utf-8') as f:
            for r in csv.DictReader(f):
                info = {k: float(r['%s_%s' % (k, t)]) for k in INFO_K}
                out[(r['period'], r['file_hash'])] = ({}, info, r['arch'])
    for p in sorted(glob.glob(os.path.join(cache_dir, 'cache_ham_*.csv'))):
        with open(p, newline='', encoding='utf-8') as f:
            for r in csv.DictReader(f):
                key = (r['period'], r['file_hash'])
                if key not in out:
                    continue
                out[key][0][int(r['addr'])] = dict(
                    n_blocks=int(r['n_blocks']), ninsn=int(r['ninsn']), n_sys=int(r['n_sys']),
                    s_sum=float(r['s_sum_' + t]), s_max=float(r['s_max_' + t]), s_topk=float(r['s_topk_' + t]),
                    keys=int(r['nk_' + t]))
    log('cache mô hình %s: %d tệp' % (t, len(out)))
    return out


def chi_q4a(a):
    """Q4a trên TOÀN BỘ tệp của một giai đoạn, không cần ground truth. Một lượt đọc JSON tính cho nhiều tệp điểm
    (--scores có thể nhiều tệp, tên mô hình lấy theo --ten-diem). Chạy tiếp được, có hạn thời gian (--han giây)."""
    ten = a.ten_diem or ['m%d' % i for i in range(len(a.scores))]
    diems = [doc_diem(p) for p in a.scores]
    kk = {(r['period'], r['file_hash']): r for r in doc_kiem_ke(a.kiem_ke)}
    js = tim_json(a.json_dir)
    os.makedirs(a.out, exist_ok=True)
    out = os.path.join(a.out, 'A_Q4a_day_du_%s.csv' % a.period)
    xong = set()
    if os.path.exists(out):
        with open(out, newline='', encoding='utf-8') as f:
            xong = {r['file_hash'] for r in csv.DictReader(f)}
    cot = ['period', 'file_hash', 'label', 'arch', 'is_static', 'is_stripped', 'n_sem', 'n_sig']
    for t in ten:
        cot += ['%s_%s' % (k, t) for k in ('n_sig_vocab', 'frac_block_vocab', 'evidence_topk')]
    viec = sorted(k for k in js if k[0] == a.period and k[1] not in xong and k in kk)
    log('Q4a %s: còn %d tệp (đã xong %d)' % (a.period, len(viec), len(xong)))
    t0, n = time.time(), 0
    with open(out, 'a', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=cot)
        if not xong:
            w.writeheader()
        for key in viec:
            d = doc_json(js[key]); r = kk[key]
            row = dict(period=key[0], file_hash=key[1], label=r.get('label'), arch=r.get('arch'),
                       is_static=r.get('is_static'), is_stripped=r.get('is_stripped'))
            for t, dm in zip(ten, diems):
                _, info = ham_cua_tep(d, dm)
                row['n_sem'], row['n_sig'] = info['n_sem'], info['n_sig']
                for k in ('n_sig_vocab', 'frac_block_vocab', 'evidence_topk'):
                    row['%s_%s' % (k, t)] = round(info[k], 6) if isinstance(info[k], float) else info[k]
            w.writerow(row); n += 1
            if n % 500 == 0:
                f.flush(); log('%d tệp, %.0fs' % (n, time.time() - t0))
            if time.time() - t0 > a.han:
                log('DUNG_THEO_HAN sau %d tệp' % n); return
    log('XONG Q4a %s (%d tệp mới)' % (a.period, n))


def ghi_csv(path, rows):
    if not rows:
        return
    keys = list(rows[0].keys())
    for r in rows[1:]:
        for k in r:
            if k not in keys:
                keys.append(k)
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=keys); w.writeheader(); w.writerows(rows)


def viet_tom_tat(a, tep_rows, tong, q3):
    L = ['# Giai đoạn A — định vị hàm (%s)' % a.ten_mo_hinh, '',
         'Điểm thực thể: `%s`' % a.scores, '',
         '| Nhóm | Điểm | n tệp | AUC (payload vs khác) | AP | Hit@5 | Công sức tới payload đầu |', '|---|---|---|---|---|---|---|']
    for r in tong:
        if '|' in r['nhom'] and not r['nhom'].endswith('test_only'):
            continue
        L.append('| %s | %s | %d | %.3f [%.3f–%.3f] | %.3f | %.3f | %.3f |' % (
            r['nhom'], r['diem'], r['n_tep'], r['auc'], r['auc_lo'], r['auc_hi'], r['ap'], r['hit5'], r['effort_first']))
    L += ['', '## Q1b–Q1c', '']
    nhom_q1b = [(p_, [r for r in tep_rows if r['period'] == p_]) for p_ in sorted({r['period'] for r in tep_rows})]
    nhom_q1b += [(p_ + '|test_only', [r for r in rr_ if r['is_test'] is True]) for p_, rr_ in list(nhom_q1b)
                 if any(r['is_test'] is True for r in rr_)]
    for per, rr in nhom_q1b:
        f = lambda k: sum(r[k] for r in rr if r[k] == r[k]) / max(1, sum(1 for r in rr if r[k] == r[k]))
        L.append('- %s: tỉ lệ bằng chứng top-K rơi vào payload %.3f | helper %.3f | khác (thư viện) %.3f; '
                 'payload không có chữ ký nào trong từ vựng %.3f; block trong từ vựng %.3f' % (
                     per, f('ev_share_payload'), f('ev_share_helper'), f('ev_share_khac'), f('payload_khong_vocab'),
                     f('frac_block_vocab')))
    L += ['', '## Q3 (Spearman thứ hạng tên hàm payload giữa ISA)', '', '| Giai đoạn | Điểm | ISA | n tên | Spearman |', '|---|---|---|---|---|']
    for r in q3:
        if r['n_ten'] >= 3:
            L.append('| %s | %s | %s–%s | %d | %.3f |' % (r['period'], r['diem'], r['isa_a'], r['isa_b'], r['n_ten'], r['spearman']))
    L += ['', 'Lưu ý: `b_ninsn` (kích thước hàm) là baseline kiểm soát cho Q3 — cùng mã nguồn nên kích thước tương quan '
          'giữa ISA; MHEN chỉ có ý nghĩa nếu vượt baseline này.']
    with open(os.path.join(a.out, 'TOM_TAT_A.md'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(L) + '\n')


def main():
    ap_ = argparse.ArgumentParser()
    ap_.add_argument('--lap-danh-sach', action='store_true')
    ap_.add_argument('--json-dir', default='', help='feature JSON directory; optional when --cache is given')
    ap_.add_argument('--kiem-ke', nargs='*', default=[])
    ap_.add_argument('--gt-dir')
    ap_.add_argument('--scores', nargs='+', help='mhenS_entity_scores_semblock_*.csv (chế độ --chi-q4a: được nhiều tệp)')
    ap_.add_argument('--chi-q4a', action='store_true', help='chỉ chạy Q4a trên toàn bộ một giai đoạn (không cần GT)')
    ap_.add_argument('--tinh-cache', action='store_true', help='tính điểm cấp hàm cho tệp có GT, ghi vào --cache')
    ap_.add_argument('--cache', help='thư mục cache điểm cấp hàm (tạo bằng --tinh-cache)')
    ap_.add_argument('--ten-cache', help='tên mô hình trong cache dùng cho phân tích (vd S, S_libboth, goc, loc)')
    ap_.add_argument('--ten-diem', nargs='*', help='tên ngắn cho từng tệp --scores (chế độ --chi-q4a)')
    ap_.add_argument('--period', default='2024')
    ap_.add_argument('--han', type=float, default=1e18, help='giới hạn giây mỗi lần chạy (chạy tiếp được)')
    ap_.add_argument('--test-hashes', help='(tuỳ chọn) danh sách hash thuộc tập test của mô hình sinh ra --scores')
    ap_.add_argument('--ten-mo-hinh', default='mhenS')
    ap_.add_argument('--out', required=True)
    ap_.add_argument('--seed', type=int, default=10)
    ap_.add_argument('--min-tep', type=int, default=20, help='số tệp tối thiểu để báo cáo một nhóm ISA')
    ap_.add_argument('--min-tep-ten', type=int, default=3, help='số tệp tối thiểu cho một (tên hàm, ISA) ở Q3')
    ap_.add_argument('--q4-mau', type=int, default=1500, help='số tệp mẫu mỗi (giai đoạn, nhãn) cho Q4a; 0 = bỏ')
    ap_.add_argument('--max-files', type=int, default=0)
    ap_.add_argument('--libfn', help='ham_thu_vien_2020.txt: bỏ hàm thư viện (khớp băm) khỏi điểm và đánh giá')
    a = ap_.parse_args()
    if a.libfn:
        global LIBFN
        LIBFN = {l.split('\t')[0].strip() for l in open(a.libfn, encoding='utf-8') if l.strip() and not l.startswith('#')}
        log('bỏ hàm thư viện: %d băm từ %s' % (len(LIBFN), a.libfn))
    if a.lap_danh_sach:
        lap_danh_sach(a)
    elif a.tinh_cache:
        if not (a.scores and a.gt_dir and a.cache):
            sys.exit('Cần --scores, --gt-dir, --cache')
        tinh_cache(a)
    elif a.chi_q4a:
        if not a.scores:
            sys.exit('Cần --scores')
        chi_q4a(a)
    else:
        if not (a.gt_dir and (a.scores or a.cache)):
            sys.exit('Cần --gt-dir và (--scores hoặc --cache + --ten-cache)')
        a.scores = a.scores[0] if a.scores else 'cache:%s/%s' % (a.cache, a.ten_cache)
        phan_tich(a)


if __name__ == '__main__':
    main()
