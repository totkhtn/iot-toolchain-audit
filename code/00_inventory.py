# -*- coding: utf-8 -*-
"""00_inventory.py: inventory of the feature files of the 2020 and 2024 periods (manifests).

Each feature JSON file (static extractor v5.2) yields one row: period, hash, label, architecture, whether the symbol
table is present, static linking, number of blocks, number of functions, number of blocks long enough to carry a
semantic signature (semblock) and the CFG truncation flag. The JSON files are only read, never modified. The script
can be resumed: rows that are already present in the output CSV are skipped.

Usage:  python 00_inventory.py <feature_json_root> <output_dir> [max_seconds] [period]
        period: 2020 | 2024 | (empty = both). Each period is written to its own CSV, so periods can run in parallel.
        The feature files are expected under <feature_json_root>/<period>/tap_chinh/ (layout of the extractor output).
"""
import csv, glob, gzip, json, os, re, sys, time

SEM_DROP = {'nop'}
MIN_INSNS = 3          # = BLOCK_MIN_INSNS of the training script (hin_static_v15)
MAIN_SUBDIR = 'tap_chinh'   # sub-folder of the main sample set in the extractor output (fixed by the extractor)

COLUMNS = ['period', 'file_hash', 'label', 'arch', 'is_stripped', 'is_static', 'n_nodes', 'n_functions',
           'n_sem_blocks', 'truncated_blocks', 'cfg_on_stripped_copy', 'status']


def hash_from_name(p):
    """File names have the form <sha256>[.elf]__<8 characters>_static.json.gz; return the leading 64 hex digits."""
    b = os.path.basename(p)
    m = re.match(r'[0-9a-fA-F]{64}', b)
    return m.group(0).lower() if m else b.split('__')[0].split('_')[0]


def read_json(p):
    op = gzip.open if p.endswith('.gz') else open
    with op(p, 'rt', encoding='utf-8', errors='ignore') as f:
        return json.load(f)


_RX = {k: re.compile(r'"%s":\s*"?([^",}\s]+)' % k) for k in
       ('label', 'arch', 'is_stripped', 'is_static', 'num_nodes', 'num_functions', 'status', 'file_hash')}


def one_file(per, p):
    """Fast path: regular expressions on the raw text; the JSON is fully parsed only for unstripped malware
    (needed for n_sem_blocks)."""
    op = gzip.open if p.endswith('.gz') else open
    with op(p, 'rt', encoding='utf-8', errors='ignore') as f:
        txt = f.read()
    g = {k: (rx.search(txt).group(1) if rx.search(txt) else None) for k, rx in _RX.items()}
    if not (g['label'] == '1' and g['is_stripped'] == '0'):
        return dict(period=per, file_hash=hash_from_name(p),
                    label=g['label'], arch=g['arch'], is_stripped=g['is_stripped'], is_static=g['is_static'],
                    n_nodes=g['num_nodes'], n_functions=g['num_functions'], n_sem_blocks='', truncated_blocks='',
                    cfg_on_stripped_copy='', status=g['status'])
    d = json.loads(txt)
    em, cg = d.get('elf_meta') or {}, d.get('cfg_graph') or {}
    ns = 0
    for nd in cg.get('nodes') or []:
        tf = nd.get('opcodes_tf') or {}
        sem = [x for x in (nd.get('sem_seq') or []) if x not in SEM_DROP]
        if sum(int(v) for v in tf.values()) >= MIN_INSNS and len(sem) >= MIN_INSNS:
            ns += 1
    q = d.get('quality_flat') or {}
    return dict(period=per, file_hash=hash_from_name(p),
                label=int(d.get('label', 0) or 0), arch=d.get('arch'), is_stripped=em.get('is_stripped'),
                is_static=em.get('is_static'), n_nodes=cg.get('num_nodes', 0), n_functions=cg.get('num_functions', 0),
                n_sem_blocks=ns, truncated_blocks=int(bool(cg.get('truncated_blocks'))),
                # 'cfg_tren_ban_strip' is the extractor's field name (CFG computed on the stripped copy)
                cfg_on_stripped_copy=q.get('cfg_tren_ban_strip'), status=d.get('status'))


def main():
    root, out_dir = sys.argv[1], sys.argv[2]
    limit = float(sys.argv[3]) if len(sys.argv) > 3 else 1e18
    pers = [sys.argv[4]] if len(sys.argv) > 4 else ['2020', '2024']
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, 'inventory_%s.csv' % '_'.join(pers))
    done = set()
    if os.path.exists(out):
        with open(out, newline='', encoding='utf-8') as f:
            done = {(r['period'], r['file_hash']) for r in csv.DictReader(f)}
    new_file = not os.path.exists(out)
    t0, n = time.time(), 0
    with open(out, 'a', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        if new_file:
            w.writeheader()
        for per in pers:
            for p in sorted(glob.glob(os.path.join(root, per, MAIN_SUBDIR, '**', '*.json*'), recursive=True)):
                h = hash_from_name(p)
                if (per, h) in done:
                    continue
                try:
                    w.writerow(one_file(per, p))
                except Exception as e:
                    w.writerow(dict(period=per, file_hash=h, status='read_error:%s' % type(e).__name__))
                n += 1
                if n % 500 == 0:
                    f.flush(); print('%d files, %.0fs' % (n, time.time() - t0), flush=True)
                if time.time() - t0 > limit:
                    print('STOPPED_AT_TIME_LIMIT %d files' % n, flush=True); return
    print('DONE %d new files, %.0fs' % (n, time.time() - t0), flush=True)


if __name__ == '__main__':
    main()
