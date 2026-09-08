"""Offline inference for the frozen follow-up. This module never reads GT."""
import argparse
import copy
import datetime
import json
import platform
import resource
import signal
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
from analysis.v1_family_rescue import build_rescue_artifact
from body_similarity import load_body_evidence
from engine import run_cg_wl
from family_rescue import RescueBudget
from loader import load_case
from v1_candidates import build_multiview_candidate_artifact_from_files, validate_candidate_artifact
from v1_engine import PairEvidenceCache, PairKey, PairPolicyConfig, build_family_artifact
from v1_retrieval_views import build_token_profiles
from analysis.v1_consensus_candidates import build_consensus_artifact
from prepare import sha


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True).strip()


def verify_frozen_environment(config):
    protocol_sha = sha(HERE / 'protocol.md')
    if protocol_sha != config['protocol_sha256']:
        raise ValueError('protocol SHA-256 does not match frozen config')
    base = config['base_commit']
    if subprocess.run(
        ['git', '-C', str(ROOT), 'merge-base', '--is-ancestor', base, 'HEAD'],
        check=False,
    ).returncode:
        raise ValueError('frozen base_commit is not an ancestor of HEAD')
    experiment = HERE.relative_to(ROOT).as_posix() + '/'
    changed = [
        path for path in git('diff', '--name-only', base, '--').splitlines()
        if path and not path.startswith(experiment)
    ]
    if changed:
        raise ValueError(
            'tracked core files differ from frozen base_commit: ' + ', '.join(changed)
        )


def execution_identity(config):
    return {
        'runner_sha256': sha(Path(__file__)),
        'config_sha256': sha(HERE / 'config.json'),
        'input_manifest_sha256': sha(HERE / 'inputs.json'),
        'python': platform.python_version(),
        'base_commit': config['base_commit'],
    }


def retained_state(path, identity, output_path=None):
    if not path.exists():
        return None
    try:
        metadata = read(path)
    except (OSError, ValueError, json.JSONDecodeError):
        return 'invalid'
    if not isinstance(metadata, dict):
        return 'invalid'
    if any(metadata.get(key) != value for key, value in identity.items()):
        return 'invalid'
    if metadata.get('status') == 'budget-refused':
        return 'budget-refused'
    if metadata.get('status') != 'completed':
        return 'invalid'
    if output_path is not None:
        expected = metadata.get('prediction_sha256')
        if not expected or not output_path.is_file() or sha(output_path) != expected:
            return 'invalid'
    outputs = metadata.get('output_sha256', {})
    valid_outputs = isinstance(outputs, dict) and all(
        (path.parent / name).is_file() and sha(path.parent / name) == digest
        for name, digest in outputs.items()
    )
    return 'completed' if valid_outputs else 'invalid'


def reusable_metadata(path, identity, output_path=None):
    return retained_state(path, identity, output_path) == 'completed'


def refuse_partial_directory(directory, metadata_path):
    if not metadata_path.exists() and directory.exists() and any(directory.iterdir()):
        raise ValueError(
            f'partial retained output exists at {directory}; use a new attempt/location'
        )


def resource_metadata():
    return {
        'address_space_limit_bytes': 12 * 1024**3,
        'resource_limit_kind': 'virtual-address-space',
        'wall_time_limit_seconds': 1800,
        'max_rss': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'max_rss_unit': 'bytes' if sys.platform == 'darwin' else 'KiB',
    }


def derive(base, k, views, minimum=None, source_sha=None):
    """Project ranked top32 to named views and a smaller k before consensus."""
    if not 0 < k <= base['config']['top_k']:
        raise ValueError('derived k must be within 1..source top_k')
    views = list(views)
    result = {**base, 'config': copy.deepcopy(base['config']), 'pairs': []}
    result['config'].update(top_k=k, views=views, view_top_k={v: k for v in views},
                            view_profiles={v: base['config']['view_profiles'][v] for v in views})
    if 'relation' not in views:
        result.pop('relation', None)
    for pair in base['pairs']:
        selected = {v: pair['views'][v] if pair['views'].get(v) is not None
                    and pair['views'][v]['rank'] <= k else None for v in views}
        if not any(selected.values()):
            continue
        item = {**pair, 'views': selected,
                'reasons': sorted(v + '_top_k' for v, value in selected.items() if value)}
        if 'relation' not in views:
            for key in ('same_final_color', 'same_prior_color', 'same_out_signature',
                        'same_in_signature', 'last_shared_round'):
                item[key] = None
        result['pairs'].append(item)
    result = build_consensus_artifact(result, minimum_views=minimum, source_sha256=source_sha)
    validate_candidate_artifact(result)
    return result


def input_path(manifest, case, key, root):
    record = manifest['cases'][case][key]
    path = root / record['path']
    if sha(path) != record['sha256']:
        raise ValueError(f'input hash mismatch: {case}/{key}')
    return path


def demand(candidate, bodies, policy):
    cache = PairEvidenceCache(bodies, candidate['pairs'], policy)
    count, cells = cache.demand(PairKey.make(p['first'], p['second']) for p in candidate['pairs'])
    return {'candidate_pairs': len(candidate['pairs']), 'comparisons': count,
            'alignment_cells': cells, 'fits': cache.within_budget(count, cells)}


def retrieve(case, manifest, config, root):
    dest = HERE / 'cache' / case
    identity = execution_identity(config)
    metadata_path = dest / 'retrieval.json'
    state = retained_state(metadata_path, identity)
    if state == 'completed':
        print(case, 'retrieval already retained', flush=True)
        return
    if state is not None:
        raise ValueError(
            f'non-reusable retrieval metadata exists at {metadata_path}; '
            'use a new attempt/location'
        )
    refuse_partial_directory(dest, metadata_path)
    started = time.perf_counter()
    metadata = {
        'case': case,
        'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        **identity,
    }
    try:
        body = input_path(manifest, case, 'body', root)
        fixture = input_path(manifest, case, 'fixture', root)
        base = build_multiview_candidate_artifact_from_files(
            body_path=body, fixture_path=fixture, top_k=32, mode='out-in',
            views=('token', 'cfg', 'relation'))
        generation_seconds = time.perf_counter() - started
        dump(dest / 'multi-k32.json', base)
        base_sha = sha(dest / 'multi-k32.json')
        old = read(input_path(manifest, case, 'reference_candidates', root))
        fresh16 = derive(base, 16, ('token', 'cfg', 'relation'), minimum=1)

        def ranks(artifact):
            return {(p['first'], p['second']): {v: r['rank'] for v, r in p['views'].items() if r}
                    for p in artifact['pairs']}

        reference_equal = ranks(fresh16) == ranks(old)
        dump(dest / 'reference-check.json', {'k16_pair_and_rank_match': reference_equal,
                                           'old_pair_count': len(old['pairs']),
                                           'new_pair_count': len(fresh16['pairs'])})
        if not reference_equal:
            if old['provenance'] != base['provenance'] or old['universe'] != fresh16['universe']:
                raise ValueError('historical candidate inputs differ; rank drift is not comparable')
            differences = {}
            for view in ('token', 'cfg', 'relation'):
                old_view = {tuple(p['pair']): p['views'][view] for p in old['pairs'] if p['views'][view]}
                new_view = {tuple(p['pair']): p['views'][view] for p in fresh16['pairs'] if p['views'][view]}
                common = old_view.keys() & new_view.keys()
                differences[view] = {
                    'reference_only': sorted(old_view.keys() - new_view.keys()),
                    'regenerated_only': sorted(new_view.keys() - old_view.keys()),
                    'rank_changes': [
                        {'pair': list(pair), 'reference': old_view[pair], 'regenerated': new_view[pair]}
                        for pair in sorted(common) if old_view[pair]['rank'] != new_view[pair]['rank']
                    ],
                }
            dump(dest / 'reference-drift.json', {
                'status': 'historical-candidates-not-reproduced',
                'input_provenance_equal': True, 'views': differences,
            })
        bodies = load_body_evidence(body)
        policy = PairPolicyConfig.from_dict(config['policy'])
        prices = {}
        output_names = ['multi-k32.json', 'reference-check.json']
        for k in config['k_values']:
            sets = {}
            for method, views in config['views'].items():
                candidate = derive(base, k, views, source_sha=base_sha)
                name = f'{method}-k{k}'
                output_name = name + '.candidates.json'
                dump(dest / output_name, candidate)
                output_names.append(output_name)
                prices[name] = demand(candidate, bodies, policy)
                sets[method] = {tuple(p['pair']) for p in candidate['pairs']}
            if not sets['combined3'] <= sets['body2']:
                raise ValueError(f'combined3-k{k} is not a subset of body2-k{k}')
        rescue = derive(base, 16, ('token', 'cfg', 'relation'), minimum=2, source_sha=base_sha)
        dump(dest / 'rescue-k16.candidates.json', rescue)
        output_names.append('rescue-k16.candidates.json')
        metadata.update({
            'status': 'completed',
            'generation_and_loading_seconds': generation_seconds,
            'prices': prices,
            'k16_reference_match': reference_equal,
            'eligible_ids': sorted(
                fid for fid, body_record in bodies.items()
                if body_record.complete
                and not body_record.quality.get('opaque_indirect_jumps', 0)
            ),
            'output_sha256': {
                name: sha(dest / name) for name in sorted(output_names)
            },
        })
        print(case, 'retrieval', json.dumps(prices), flush=True)
    except (MemoryError, TimeoutError) as exc:
        metadata.update(status='resource-incomplete', error=repr(exc))
    except Exception as exc:
        metadata.update(status='error', error=repr(exc))
        raise
    finally:
        metadata['total_seconds'] = time.perf_counter() - started
        metadata.update(resource_metadata())
        dump(metadata_path, metadata)
        print(case, 'retrieval', metadata.get('status'), round(metadata['total_seconds'], 3),
              'seconds', flush=True)


def partition_records(artifact):
    return {
        (cluster['status'], tuple(sorted(cluster['members'])))
        for cluster in artifact['clusters']
    }


def historical_partition_check(actual, reference, reference_path):
    actual_partition = partition_records(actual)
    reference_partition = partition_records(reference)
    matched = actual_partition == reference_partition

    def records(values):
        return [
            {'status': status, 'members': list(members)}
            for status, members in sorted(values)
        ]

    return {
        'reference_path': str(reference_path),
        'reference_sha256': sha(reference_path),
        'partition_match': matched,
        'historical_reproduction_claim': (
            'partition-reproduced' if matched else 'partition-not-reproduced'
        ),
        'partition_delta': {
            'reference_only': records(reference_partition - actual_partition),
            'regenerated_only': records(actual_partition - reference_partition),
        },
    }


def predict(case, method, k, manifest, config, root):
    if method == 'rescue' and k != 16:
        raise ValueError('rescue is frozen at k=16')
    name = method if method in ('exact', 'v0') else f'{method}-k{k}'
    dest = HERE / 'runs' / case / name
    identity = execution_identity(config)
    metadata_path = dest / 'metadata.json'
    prediction_path = dest / 'prediction.json'
    state = retained_state(metadata_path, identity, prediction_path)
    if state == 'completed':
        print(case, name, 'already retained', flush=True)
        return
    if state == 'budget-refused':
        print(case, name, 'budget refusal already retained', flush=True)
        return
    if state is not None:
        raise ValueError(
            f'non-reusable prediction metadata exists at {metadata_path}; '
            'use a new attempt/location'
        )
    refuse_partial_directory(dest, metadata_path)
    started = time.perf_counter()
    metadata = {'case': case, 'method': method, 'k': k, 'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'code_commit': git('rev-parse', 'HEAD'),
                'protocol_sha256': sha(HERE / 'protocol.md'), **identity}
    try:
        body_path = input_path(manifest, case, 'body', root)
        body_artifact = read(body_path)
        bodies = load_body_evidence(body_artifact)
        metadata['body_evidence_sha256'] = sha(body_path)
        metadata['load_seconds'] = time.perf_counter() - started
        stage_start = time.perf_counter()
        if method == 'rescue':
            retrieval_metadata = HERE / 'cache' / case / 'retrieval.json'
            if not reusable_metadata(retrieval_metadata, identity):
                raise ValueError('rescue requires current completed retrieval artifacts')
            candidate_path = HERE / 'cache' / case / 'rescue-k16.candidates.json'
            candidate = read(candidate_path)
            metadata['candidate_sha256'] = sha(candidate_path)
            strict_dir = HERE / 'runs' / case / 'combined3-k16'
            strict_metadata_path = strict_dir / 'metadata.json'
            strict_path = strict_dir / 'prediction.json'
            if not reusable_metadata(strict_metadata_path, identity, strict_path):
                raise ValueError('rescue requires a current completed combined3-k16 prediction')
            strict = read(strict_path)
            raw_path = input_path(manifest, case, 'raw_graph', root)
            rescue = build_rescue_artifact(
                strict,
                candidate,
                body_artifact,
                read(raw_path),
                budget=RescueBudget(),
                provenance={
                    'family_artifact_sha256': sha(strict_path),
                    'candidate_artifact_sha256': metadata['candidate_sha256'],
                    'body_evidence_sha256': metadata['body_evidence_sha256'],
                    'raw_graph_sha256': sha(raw_path),
                },
            )
            rescue_path = dest / 'rescue-artifact.json'
            dump(rescue_path, rescue)
            metadata.update({
                'rescue_artifact_sha256': sha(rescue_path),
                'strict_baseline_path': str(strict_path),
                'strict_baseline_sha256': sha(strict_path),
                'rescue_cost': {
                    key: rescue['summary'][key]
                    for key in ('reserved_comparisons', 'reserved_alignment_cells')
                },
            })
            prediction = {
                'artifact': 'followup-reference',
                'case': case,
                'universe': copy.deepcopy(strict['universe']),
                'clusters': [
                    {'members': list(cluster['members']), 'status': 'accepted'}
                    for cluster in rescue['final_partition']
                ],
            }
        elif method in ('exact', 'v0'):
            if method == 'exact':
                groups = defaultdict(list)
                for fid, profile in build_token_profiles(bodies).items():
                    body = bodies[fid]
                    if body.complete and body.instructions and not body.quality.get('opaque_indirect_jumps', 0):
                        groups[profile.exact_token_hash].append(fid)
                clusters = list(groups.values())
            else:
                fixture_path = input_path(manifest, case, 'fixture', root)
                metadata['fixture_sha256'] = sha(fixture_path)
                fixture = load_case(str(fixture_path))
                result = run_cg_wl(fixture, mode='out-in', trace=True)
                clusters = [sorted(set(group) & set(bodies)) for group in result.clusters]
            prediction = {'artifact': 'followup-reference', 'case': case,
                          'universe': {'target_ids': sorted(bodies)},
                          'clusters': [{'members': sorted(g), 'status': 'accepted'}
                                       for g in clusters if len(g) >= 2]}
        else:
            retrieval_metadata = HERE / 'cache' / case / 'retrieval.json'
            if not reusable_metadata(retrieval_metadata, identity):
                raise ValueError(f'{method}-k{k} requires current completed retrieval artifacts')
            candidate_path = HERE / 'cache' / case / (name + '.candidates.json')
            candidate = read(candidate_path)
            metadata['candidate_sha256'] = sha(candidate_path)
            policy = PairPolicyConfig.from_dict(config['policy'])
            metadata['demand'] = demand(candidate, bodies, policy)
            if not metadata['demand']['fits']:
                metadata['status'] = 'budget-refused'
                return
            prediction = build_family_artifact(candidate_artifact=candidate, bodies=bodies,
                config=policy, body_sha256=sha(body_path), body_provenance=body_artifact['provenance'],
                candidate_sha256=metadata['candidate_sha256'])
            if method == 'combined3' and k == 16:
                reference_path = input_path(manifest, case, 'reference_strict', root)
                metadata['historical_partition_check'] = historical_partition_check(
                    prediction, read(reference_path), reference_path
                )
        metadata['inference_seconds'] = time.perf_counter() - stage_start
        dump(prediction_path, prediction)
        metadata['prediction_sha256'] = sha(prediction_path)
        metadata['status'] = 'completed'
        if 'metrics' in prediction:
            metadata['comparison_cost'] = prediction['metrics']
    except (MemoryError, TimeoutError) as exc:
        metadata.update(status='resource-incomplete', error=repr(exc))
    except Exception as exc:
        metadata.update(status='error', error=repr(exc))
        raise
    finally:
        metadata['wall_seconds'] = time.perf_counter() - started
        metadata.update(resource_metadata())
        dump(metadata_path, metadata)
        print(case, name, metadata.get('status'), round(metadata['wall_seconds'], 3), 'seconds', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('retrieve', 'predict'))
    parser.add_argument('--case', required=True)
    parser.add_argument(
        '--method',
        choices=('body2', 'combined3', 'exact', 'v0', 'rescue'),
        default='combined3',
    )
    parser.add_argument('--k', type=int, choices=(8,16,32), default=16)
    parser.add_argument('--input-root', type=Path)
    args = parser.parse_args()
    config, manifest = read(HERE / 'config.json'), read(HERE / 'inputs.json')
    verify_frozen_environment(config)
    if args.case not in config['cases']:
        raise ValueError('case is outside the frozen development set')
    root = args.input_root or Path(manifest['input_root'])
    resource.setrlimit(resource.RLIMIT_AS, (12 * 1024**3, 12 * 1024**3))
    def alarm(*_):
        raise TimeoutError('30-minute process ceiling reached')
    signal.signal(signal.SIGALRM, alarm)
    signal.alarm(1800)
    if args.action == 'retrieve':
        retrieve(args.case, manifest, config, root)
    else:
        predict(args.case, args.method, args.k, manifest, config, root)


if __name__ == '__main__':
    main()
