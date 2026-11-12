"""Create the working folder `ket_qua/` expected by the scripts in code/, from data/ and the release assets.

Usage (from the repository root):
    python3 scripts/setup_workdir.py [--assets release_assets]
Afterwards run the commands of README.md from the repository root.
"""
import argparse, csv, glob, gzip, os, shutil, zipfile

ap = argparse.ArgumentParser(); ap.add_argument('--assets', default='release_assets'); a = ap.parse_args()
K = 'ket_qua'


def gunzip(src, dst):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with gzip.open(src, 'rb') as f, open(dst, 'wb') as g:
        shutil.copyfileobj(f, g)


def cp(src, dst):
    os.makedirs(os.path.dirname(dst), exist_ok=True); shutil.copy2(src, dst)


gunzip('data/ground_truth/gt_v1/gt_ham.csv.gz', f'{K}/gt/gt_ham.csv'); cp('data/ground_truth/gt_v1/gt_tep.csv', f'{K}/gt/gt_tep.csv')
gunzip('data/ground_truth/gt_v2/gt_ham.csv.gz', f'{K}/gt_v2/gt_ham.csv'); cp('data/ground_truth/gt_v2/gt_tep.csv', f'{K}/gt_v2/gt_tep.csv')
cp('data/ground_truth/gt_v2/ten_libc_glibc.txt', f'{K}/gt_v2/ten_libc_glibc.txt')
cp('data/function_hashes/bam_ham.csv.gz', f'{K}/bam_ham/bam_ham.csv.gz'); gunzip('data/function_hashes/bam_tep.csv.gz', f'{K}/bam_ham/bam_tep.csv')
cp('data/library_db/ham_thu_vien_2020.txt', f'{K}/libaware/ham_thu_vien_2020.txt')
cp('data/signature_roles/chu_ky_thu_vien.csv.gz', f'{K}/libsym/chu_ky_thu_vien.csv.gz')
# test hash lists per seed (grouped split, identical for the mask and library aware experiments)
with gzip.open('data/splits/grouped_2024_10seeds.csv.gz', 'rt', encoding='utf-8') as f:
    rows = list(csv.DictReader(f))
for col in [c for c in rows[0] if c.startswith('seed')]:
    os.makedirs(f'{K}/splits', exist_ok=True)
    for part in ('train', 'val', 'test'):
        with open(f'{K}/splits/{part}_hashes_grouped-2024_{col}.txt', 'w', encoding='utf-8') as g:
            g.write(''.join(r['file_hash'] + '\n' for r in rows if r[col] == part))
for p in glob.glob('data/splits/leave_one_isa_out/test_*.txt'):
    cp(p, f'{K}/xisa_test_hashes/' + os.path.basename(p)[len('test_'):])
for z in sorted(glob.glob(os.path.join(a.assets, '*.zip'))):
    with zipfile.ZipFile(z) as zz:
        zz.extractall('.')            # archives contain paths under ket_qua/
    print('extracted', z)
print('ket_qua/ ready')
