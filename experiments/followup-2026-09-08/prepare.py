"""Freeze retained input identities and a score-blind source-audit sample."""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def prepare(root):
    config = json.loads((HERE / 'config.json').read_text())
    manifest = {'input_root': str(root.resolve()), 'cases': {}}
    samples = []
    for case in config['cases']:
        legacy = 'v0-engine-py-frozen' if case == 'zoxide' else 'v0-engine-py-f1'
        prefix = f'worktrees/{legacy}'
        scope = '' if case == 'zoxide' else 'rust-nonstd/'
        paths = {
            'body': f'{prefix}/body_evidence/{scope}plain/{case}.O3S.body.json',
            'fixture': f'fixtures/angr/role/rust-nonstd/plain/{case}.O3S.fixture.json',
            'ground_truth': f'ground_truth/rust-nonstd/plain/{case}.O3S.gt.json',
            'linkage': f'{prefix}/results/{case}/plain/{case}.O3S.gt-mangled-audit.json',
            'reference_candidates': f'{prefix}/results/{case}/plain/{case}.O3S.v1.multi.k16.candidates.json',
            'reference_strict': f'{prefix}/results/{case}/plain/{case}.O3S.v1.consensus3.k16.formal.families.json',
            'raw_graph': f'extractions/angr/plain/{case}.O3S.raw.json',
            'build_manifest': f'build_info/plain/{case}.O3S.json',
        }
        manifest['cases'][case] = {
            key: {'path': rel, 'sha256': sha(root / rel), 'bytes': (root / rel).stat().st_size}
            for key, rel in paths.items()
        }
        gt = json.loads((root / paths['ground_truth']).read_text())
        audit = json.loads((root / paths['linkage']).read_text())
        all_groups = sorted(gt['origins'], key=lambda g: g['origin'])
        multi = [g for g in all_groups if len(g['members']) >= 2]
        seed = config['audit_seed']
        selected = sorted(multi, key=lambda g: hashlib.sha256(
            f"{seed}\0{case}\0{g['origin']}".encode()).hexdigest())[:10]
        assert len(selected) == 10
        rows = [(g, 'random', 'sha256_uniform_order') for g in selected]
        used = {g['origin'] for g in selected}
        shared = {a for a, r in audit['addresses'].items() if len(r['origins']) > 1}
        categories = [
            ('shared_address', lambda g: bool(set(g['members']) & shared)),
            ('trait_impl', lambda g: ' as ' in g['origin']),
            ('closure', lambda g: '{{closure}}' in g['origin']),
            ('generated_or_shim_candidate', lambda g: any(s in g['origin'] for s in ('ouroboros', 'shim', 'macro'))),
            ('drop_related', lambda g: 'drop' in g['origin']),
            ('largest_remaining', lambda g: len(g['members']) >= 2),
        ]
        for category, predicate in categories:
            candidates = [g for g in all_groups if g['origin'] not in used and predicate(g)]
            rule = category
            if not candidates:
                candidates = [g for g in multi if g['origin'] not in used]
                rule += ':fallback_lexical_multimember'
            if category == 'largest_remaining':
                candidates.sort(key=lambda g: (-len(g['members']), g['origin']))
            group = candidates[0]
            used.add(group['origin'])
            rows.append((group, 'purposeful', rule))
        for i, (group, stratum, rule) in enumerate(rows, 1):
            samples.append({
                'sample_id': f'{case}-{i:02}', 'case': case, 'stratum': stratum,
                'selection_rule': rule, 'origin': group['origin'],
                'members': sorted(group['members']),
                'symbols': {m: gt['symbols'].get(m, []) for m in sorted(group['members'])},
                'source_evidence': [], 'assessment': 'unreviewed',
                'review_scope': 'source-level consistency; not compiler-ID or external-human validation',
            })
        print(case, 'input hashes saved; random10 + purposeful6', flush=True)
    assert len(samples) == 48
    for name, value in [('inputs.json', manifest), ('audit-sample.json', samples)]:
        path = HERE / name
        if path.exists():
            assert json.loads(path.read_text()) == value, f'frozen file changed: {path}'
        else:
            path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-root', type=Path, required=True)
    prepare(parser.parse_args().input_root)
