"""Create the working folder `workdir/` expected by the scripts in code/, from data/ and the release assets.

Usage (from the repository root):
    python3 scripts/setup_workdir.py [--assets release_assets]
Afterwards run the commands of README.md from the repository root.
"""
import argparse, csv, glob, gzip, os, shutil, zipfile

ap = argparse.ArgumentParser(); ap.add_argument('--assets', default='release_assets'); a = ap.parse_args()
K = 'workdir'


def gunzip(src, dst):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with gzip.open(src, 'rb') as f, open(dst, 'wb') as g:
        shutil.copyfileobj(f, g)


def cp(src, dst):
    os.makedirs(os.path.dirname(dst), exist_ok=True); shutil.copy2(src, dst)


gunzip('data/ground_truth/gt_v1/gt_functions.csv.gz', f'{K}/gt/gt_functions.csv'); cp('data/ground_truth/gt_v1/gt_files.csv', f'{K}/gt/gt_files.csv')
gunzip('data/ground_truth/gt_v2/gt_functions.csv.gz', f'{K}/gt_v2/gt_functions.csv'); cp('data/ground_truth/gt_v2/gt_files.csv', f'{K}/gt_v2/gt_files.csv')
cp('data/ground_truth/gt_v2/libc_glibc_names.txt', f'{K}/gt_v2/libc_glibc_names.txt')
cp('data/function_hashes/function_hashes.csv.gz', f'{K}/function_hashes/function_hashes.csv.gz')
gunzip('data/function_hashes/hashed_files.csv.gz', f'{K}/function_hashes/hashed_files.csv')
cp('data/library_db/library_functions_2020.txt', f'{K}/libaware/library_functions_2020.txt')
cp('data/signature_roles/signature_roles.csv.gz', f'{K}/libsym/signature_roles.csv.gz')
# test hash lists per seed (grouped split, identical for the mask and library-aware experiments)
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
        zz.extractall('.')            # the archives contain paths under workdir/
    print('extracted', z)
print('workdir/ ready')
