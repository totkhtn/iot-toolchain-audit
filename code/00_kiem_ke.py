# -*- coding: utf-8 -*-
"""00_kiem_ke.py — Kiểm kê dataset-moi (2020, 2024) cho thí nghiệm định vị hàm.

Mỗi JSON v5.2 -> một dòng: giai đoạn, hash, nhãn, kiến trúc, còn ký hiệu hay không, liên kết tĩnh,
số block, số hàm, số block đủ dài để có chữ ký ngữ nghĩa (semblock), cờ cắt bớt CFG.
Chỉ đọc JSON, không sửa gì. Chạy tiếp được (resume): dòng đã có trong CSV thì bỏ qua.

Dùng:  python 00_kiem_ke.py <thu_muc_dataset-moi> <thu_muc_ket_qua> [so_giay_toi_da] [giai_doan]
       giai_doan: 2020 | 2024 | (bỏ trống = cả hai). Mỗi giai đoạn ghi một CSV riêng -> chạy song song được.
"""
import csv, glob, gzip, json, os, re, sys, time

SEM_DROP = {'nop'}
MIN_INSNS = 3          # = BLOCK_MIN_INSNS của hin_static_v15

COT = ['period', 'file_hash', 'label', 'arch', 'is_stripped', 'is_static', 'n_nodes', 'n_functions',
       'n_sem_blocks', 'truncated_blocks', 'cfg_tren_ban_strip', 'status']


def hash_tu_ten(p):
    """Tên tệp có dạng <sha256>[.elf]__<8 ký tự>_static.json.gz -> lấy 64 ký tự hex đầu."""
    b = os.path.basename(p)
    m = re.match(r'[0-9a-fA-F]{64}', b)
    return m.group(0).lower() if m else b.split('__')[0].split('_')[0]


def doc(p):
    op = gzip.open if p.endswith('.gz') else open
    with op(p, 'rt', encoding='utf-8', errors='ignore') as f:
        return json.load(f)


_RX = {k: re.compile(r'"%s":\s*"?([^",}\s]+)' % k) for k in
       ('label', 'arch', 'is_stripped', 'is_static', 'num_nodes', 'num_functions', 'status', 'file_hash')}


def mot_tep(per, p):
    """Đường nhanh: chỉ regex trên văn bản; chỉ parse JSON đầy đủ cho mã độc còn ký hiệu (cần n_sem_blocks)."""
    op = gzip.open if p.endswith('.gz') else open
    with op(p, 'rt', encoding='utf-8', errors='ignore') as f:
        txt = f.read()
    g = {k: (rx.search(txt).group(1) if rx.search(txt) else None) for k, rx in _RX.items()}
    if not (g['label'] == '1' and g['is_stripped'] == '0'):
        return dict(period=per, file_hash=hash_tu_ten(p),
                    label=g['label'], arch=g['arch'], is_stripped=g['is_stripped'], is_static=g['is_static'],
                    n_nodes=g['num_nodes'], n_functions=g['num_functions'], n_sem_blocks='', truncated_blocks='',
                    cfg_tren_ban_strip='', status=g['status'])
    d = json.loads(txt)
    em, cg = d.get('elf_meta') or {}, d.get('cfg_graph') or {}
    ns = 0
    for nd in cg.get('nodes') or []:
        tf = nd.get('opcodes_tf') or {}
        sem = [x for x in (nd.get('sem_seq') or []) if x not in SEM_DROP]
        if sum(int(v) for v in tf.values()) >= MIN_INSNS and len(sem) >= MIN_INSNS:
            ns += 1
    q = d.get('quality_flat') or {}
    return dict(period=per, file_hash=hash_tu_ten(p),
                label=int(d.get('label', 0) or 0), arch=d.get('arch'), is_stripped=em.get('is_stripped'),
                is_static=em.get('is_static'), n_nodes=cg.get('num_nodes', 0), n_functions=cg.get('num_functions', 0),
                n_sem_blocks=ns, truncated_blocks=int(bool(cg.get('truncated_blocks'))),
                cfg_tren_ban_strip=q.get('cfg_tren_ban_strip'), status=d.get('status'))


def main():
    goc, ra = sys.argv[1], sys.argv[2]
    han = float(sys.argv[3]) if len(sys.argv) > 3 else 1e18
    pers = [sys.argv[4]] if len(sys.argv) > 4 else ['2020', '2024']
    os.makedirs(ra, exist_ok=True)
    out = os.path.join(ra, 'kiem_ke_dataset_moi_%s.csv' % '_'.join(pers))
    xong = set()
    if os.path.exists(out):
        with open(out, newline='', encoding='utf-8') as f:
            xong = {(r['period'], r['file_hash']) for r in csv.DictReader(f)}
    moi = not os.path.exists(out)
    t0, n = time.time(), 0
    with open(out, 'a', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=COT)
        if moi:
            w.writeheader()
        for per in pers:
            for p in sorted(glob.glob(os.path.join(goc, per, 'tap_chinh', '**', '*.json*'), recursive=True)):
                h = hash_tu_ten(p)
                if (per, h) in xong:
                    continue
                try:
                    w.writerow(mot_tep(per, p))
                except Exception as e:
                    w.writerow(dict(period=per, file_hash=h, status='loi_doc:%s' % type(e).__name__))
                n += 1
                if n % 500 == 0:
                    f.flush(); print('%d tệp, %.0fs' % (n, time.time() - t0), flush=True)
                if time.time() - t0 > han:
                    print('DUNG_THEO_HAN %d tệp' % n, flush=True); return
    print('XONG %d tệp mới, %.0fs' % (n, time.time() - t0), flush=True)


if __name__ == '__main__':
    main()
