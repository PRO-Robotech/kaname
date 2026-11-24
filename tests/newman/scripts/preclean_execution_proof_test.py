# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pre-clean доказательство различает исходную identity и потерянную при чистке."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
HELPER_PATH = ROOT / '.github/scripts/preclean-execution-proof.py'
spec = importlib.util.spec_from_file_location('preclean_execution_proof', HELPER_PATH)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
CANARY = 'fixture-only-sensitive-value-never-public-7Q2x'


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def read_json(path):
    return json.loads(path.read_text())


@pytest.fixture
def world(tmp_path, monkeypatch):
    root = tmp_path / 'repo'; root.mkdir()
    original = tmp_path / 'original'; original.mkdir()
    cleaned = tmp_path / 'cleaned'; cleaned.mkdir()
    private = tmp_path / 'private'
    for name in (helper.SELF, helper.VERIFIER):
        target = root / name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    command = './scripts/run.sh --remint-bootstrap ' + ' '.join('--service ' + stem for stem in helper.STEMS)
    write_json(root / helper.WORKFLOW, {'jobs': {'stand-ceremony': {'steps': [{'name': helper.STEP, 'run': command}]}}})
    # Контрпример158/167: запросы и scripts одинаковы, различаются только исходные имена.
    names = ['IAM-GDU-EXPAND-ROLE-ALLOWED-PATCH-S-B0-effective',
             'IAM-GDU-EXPAND-ROLE-ALLOWED-B0-still-allowed']
    leaves = [{'name': name, 'request': {'method': 'GET', 'url': 'https://fixture.invalid/'}} for name in names]
    for stem in helper.STEMS:
        collection = {'info': {'name': stem}, 'item': [{'name': 'fixture-folder', 'item': copy.deepcopy(leaves)}]}
        write_json(root / f'tests/newman/collections/{stem}.postman_collection.json', collection)
        embedded = copy.deepcopy(collection)
        for i, leaf in enumerate(embedded['item'][0]['item']):
            leaf['id'] = str(uuid.uuid5(uuid.NAMESPACE_URL, f'https://fixture.invalid/{stem}/{i}'))
        executions = [{'cursor': {'position': i, 'length': 2}, 'item': copy.deepcopy(leaf),
                       'response': {'code': 200}, 'assertions': [{'assertion': 'fixture check', 'skipped': False}]}
                      for i, leaf in enumerate(embedded['item'][0]['item'])]
        report = {'collection': embedded,
                  'environment': {'values': [{'key': 'jwtFixture', 'value': CANARY}]},
                  'run': {'executions': executions, 'failures': [],
                          'stats': {'iterations': {'total': 1, 'pending': 0, 'failed': 0},
                                    'items': {'total': 2, 'pending': 0, 'failed': 0},
                                    'scripts': {'total': 8, 'pending': 0, 'failed': 0},
                                    'prerequestScripts': {'total': 4, 'pending': 0, 'failed': 0},
                                    'testScripts': {'total': 4, 'pending': 0, 'failed': 0},
                                    'requests': {'total': 2, 'pending': 0, 'failed': 0},
                                    'assertions': {'total': 2, 'pending': 0, 'failed': 0}}}}
        write_json(original / (stem + '.json'), report)
        (original / (stem + '.rc')).write_text('0\n')
        public = copy.deepcopy(report)
        public['environment']['values'][0]['value'] = 'REDACTED'
        for leaf in public['collection']['item'][0]['item']:
            leaf['name'] = 'REDACTED-IDENTITY'
        for execution in public['run']['executions']:
            execution['item']['name'] = 'REDACTED-IDENTITY'
        write_json(cleaned / (stem + '.json'), public)
    git_env = os.environ.copy()
    git_env.update(GIT_AUTHOR_NAME='fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid',
                   GIT_COMMITTER_NAME='fixture', GIT_COMMITTER_EMAIL='fixture@example.invalid')
    def git(*argv):
        return subprocess.check_output(['git', '-C', str(root), *argv], env=git_env, stderr=subprocess.PIPE, text=True).strip()
    git('init', '-q', '-b', 'main')
    git('add', '.'); git('commit', '-qm', 'fixture common ancestor')
    git('checkout', '-qb', 'feature')
    (root / 'head-only.txt').write_text('head')
    git('add', '.'); git('commit', '-qm', 'fixture PR head')
    head = git('rev-parse', 'HEAD')
    git('checkout', '-q', 'main')
    (root / 'base-only.txt').write_text('base')
    git('add', '.'); git('commit', '-qm', 'fixture base advance')
    base = git('rev-parse', 'HEAD')
    git('merge', '--no-ff', '-m', 'fixture synthetic merge', 'feature')
    checkout = git('rev-parse', 'HEAD')
    assert len({base, head, checkout}) == 3
    assert git('rev-list', '--parents', '-n', '1', 'HEAD').split() == [checkout, base, head]
    event_path = tmp_path / 'event.json'
    write_json(event_path, {'number': 1119, 'pull_request': {'head': {'sha': head}, 'base': {'sha': base}}})
    for key, value in {'GITHUB_EVENT_PATH': str(event_path), 'GITHUB_REPOSITORY': 'PRO-Robotech/kaname',
                       'GITHUB_SHA': checkout, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '2',
                       'GITHUB_JOB': 'stand-ceremony'}.items():
        monkeypatch.setenv(key, value)
    return root, original, private, cleaned


def test_original_names_proved_before_lossy_cleaning(world):
    root, original, private, cleaned = world
    assert helper.prove(root, original, private)
    state = read_json(private / 'state.json')
    assert state['verifierActualRC'] == 0 and state['census']['judged'] == 19
    receipt = helper.seal(root, original, private, cleaned)
    helper.validate_receipt(receipt, cleaned)
    assert receipt['census']['declared'] == receipt['census']['executed'] == 38
    assert all(row['sourceFingerprint'] == row['reportFingerprint'] for row in receipt['collections'])
    assert CANARY not in json.dumps(receipt)


def test_alias_swap_same_request_and_scripts_is_unjudged(world):
    root, original, private, cleaned = world
    path = original / (helper.STEMS[0] + '.json'); doc = read_json(path)
    first, second = doc['collection']['item'][0]['item']
    assert first['request'] == second['request'] and first.get('event') == second.get('event')
    first['name'], second['name'] = second['name'], first['name']
    write_json(path, doc)
    assert not helper.prove(root, original, private)
    assert read_json(private / 'state.json')['verifierActualRC'] == 3
    with pytest.raises(ValueError):
        helper.seal(root, original, private, cleaned)
    assert not (cleaned / 'preclean-execution-proof.json').exists()


@pytest.mark.parametrize('kind', ['missing-report', 'missing-source', 'wrong-stem', 'wrong-cursor'])
def test_missing_wrong_or_unjudged_input_is_rejected(world, kind):
    root, original, private, cleaned = world
    if kind == 'missing-report':
        (original / (helper.STEMS[0] + '.json')).unlink()
    elif kind == 'missing-source':
        (root / f'tests/newman/collections/{helper.STEMS[0]}.postman_collection.json').unlink()
    elif kind == 'wrong-stem':
        path = root / helper.WORKFLOW
        path.write_text(path.read_text().replace('--service authz-deny', '--service wrong-stem'))
    else:
        path = original / (helper.STEMS[0] + '.json'); doc = read_json(path)
        doc['run']['executions'][0]['cursor']['length'] = 999
        write_json(path, doc)
    assert not helper.prove(root, original, private)
    with pytest.raises(ValueError):
        helper.seal(root, original, private, cleaned)


@pytest.mark.parametrize('kind', ['failed', 'skipped', 'nonzero-newman'])
def test_numeric_green_cannot_hide_failed_or_skipped_assertions(world, kind):
    root, original, private, cleaned = world
    stem = helper.STEMS[0]; path = original / (stem + '.json'); doc = read_json(path)
    if kind == 'failed':
        doc['run']['stats']['assertions']['failed'] = 1
    elif kind == 'skipped':
        doc['run']['executions'][0]['assertions'][0]['skipped'] = True
    else:
        (original / (stem + '.rc')).write_text('1\n')
    write_json(path, doc)
    assert not helper.prove(root, original, private)


@pytest.mark.parametrize('kind', ['source', 'verifier', 'original', 'stdout'])
def test_preclean_bytes_must_remain_stable_until_seal(world, kind):
    root, original, private, cleaned = world
    assert helper.prove(root, original, private)
    path = {'source': root / f'tests/newman/collections/{helper.STEMS[0]}.postman_collection.json',
            'verifier': root / helper.VERIFIER, 'original': original / (helper.STEMS[0] + '.json'),
            'stdout': private / 'verifier.stdout'}[kind]
    path.write_bytes(path.read_bytes() + b'\n')
    with pytest.raises(ValueError):
        helper.seal(root, original, private, cleaned)
    assert not (cleaned / 'preclean-execution-proof.json').exists()


def test_postclean_hash_binding_detects_later_mutation(world):
    root, original, private, cleaned = world
    assert helper.prove(root, original, private)
    receipt = helper.seal(root, original, private, cleaned)
    path = cleaned / (helper.STEMS[0] + '.json'); path.write_bytes(path.read_bytes() + b'\n')
    with pytest.raises(ValueError):
        helper.validate_receipt(receipt, cleaned)


def test_public_schema_has_no_free_text_or_secret_slots(world):
    root, original, private, cleaned = world
    assert helper.prove(root, original, private)
    receipt = helper.seal(root, original, private, cleaned)
    mutations = []
    bad = copy.deepcopy(receipt); bad['token'] = CANARY; mutations.append(bad)
    bad = copy.deepcopy(receipt); bad['collections'][0]['request'] = CANARY; mutations.append(bad)
    bad = copy.deepcopy(receipt); bad['provenance']['jobKey'] = CANARY; mutations.append(bad)
    bad = copy.deepcopy(receipt); bad['verifierStdoutSHA256'] = CANARY; mutations.append(bad)
    bad = copy.deepcopy(receipt); bad['census']['judged'] = True; mutations.append(bad)
    for bad in mutations:
        with pytest.raises(ValueError):
            helper.validate_receipt(bad, cleaned)


def test_current_workflow_proves_then_redacts_then_seals():
    workflow = yaml.safe_load((ROOT / helper.WORKFLOW).read_text())
    steps = workflow['jobs']['stand-ceremony']['steps']
    proof = [i for i, step in enumerate(steps) if 'preclean-execution-proof.py prove' in step.get('run', '')]
    clean = [i for i, step in enumerate(steps) if 'preclean-execution-proof.py seal' in step.get('run', '')]
    assert len(proof) == len(clean) == 1 and proof[0] < clean[0]
    run = steps[clean[0]]['run']
    assert run.index('redact-newman-report.py --in') < run.index('preclean-execution-proof.py seal')
    assert steps[proof[0]]['if'] == 'always()'
    assert helper.declared_stems(ROOT) == list(helper.STEMS)
    checkouts = [step for step in steps if step.get('uses', '').startswith('actions/checkout@')]
    assert len(checkouts) == 1 and checkouts[0]['with']['fetch-depth'] == 2


def test_real_shallow_merge_depth1_refused_depth2_proved(world, tmp_path):
    root, original, private, cleaned = world
    event = read_json(Path(os.environ['GITHUB_EVENT_PATH']))
    head = event['pull_request']['head']['sha']; base = event['pull_request']['base']['sha']
    checkout = os.environ['GITHUB_SHA']
    clones = {}
    for depth in (1, 2):
        clone = tmp_path / f'checkout-depth{depth}'
        # file:// включает настоящий shallow transport; обычный local path проигнорировал бы depth.
        subprocess.run(['git', 'clone', '-q', '--depth', str(depth), '--branch', 'main', root.as_uri(), str(clone)],
                       check=True, capture_output=True)
        assert (clone / '.git/shallow').is_file()
        clones[depth] = clone
    parents1 = subprocess.check_output(['git', '-C', str(clones[1]), 'rev-list', '--parents', '-n', '1', 'HEAD'], text=True).split()
    assert parents1 == [checkout]
    rejected = tmp_path / 'private-depth1'
    assert not helper.prove(clones[1], original, rejected)
    assert read_json(rejected / 'state.json')['accepted'] is False
    parents2 = subprocess.check_output(['git', '-C', str(clones[2]), 'rev-list', '--parents', '-n', '1', 'HEAD'], text=True).split()
    assert parents2 == [checkout, base, head]
    subprocess.run(['git', '-C', str(clones[2]), 'cat-file', '-e', head + '^{commit}'], check=True, capture_output=True)
    accepted = tmp_path / 'private-depth2'
    assert helper.prove(clones[2], original, accepted)
    receipt = helper.seal(clones[2], original, accepted, cleaned)
    assert receipt['provenance']['checkoutKind'] == 'pr-merge'
    assert receipt['provenance']['checkoutParents'] == [base, head]
    assert receipt['provenance']['headSHA'] == head and receipt['provenance']['checkoutSHA'] == checkout


@pytest.mark.parametrize('kind', ['run-error', 'pending', 'stats-bool', 'stats-float',
                                  'wrong-item-id', 'wrong-item-name', 'duplicate-sdk-id',
                                  'empty-assertion', 'malformed-assertion', 'blank-assertion',
                                  'malformed-skipped', 'malformed-error'])
def test_terminal_integrity_rejects_even_if_canonical_coverage_is_zero(world, kind):
    root, original, private, cleaned = world
    path = original / (helper.STEMS[0] + '.json'); doc = read_json(path)
    run = doc['run']; execution = run['executions'][0]
    if kind == 'run-error':
        run['error'] = {'name': 'FixtureError', 'message': CANARY}
    elif kind == 'pending':
        run['stats']['testScripts']['pending'] = 1
    elif kind == 'stats-bool':
        run['stats']['scripts']['total'] = True
    elif kind == 'stats-float':
        run['stats']['items']['total'] = 2.0
    elif kind == 'wrong-item-id':
        execution['item']['id'] = str(uuid.uuid4())
    elif kind == 'wrong-item-name':
        execution['item']['name'] += '-wrong'
    elif kind == 'duplicate-sdk-id':
        leaves = doc['collection']['item'][0]['item']
        leaves[1]['id'] = leaves[0]['id']
    elif kind == 'empty-assertion':
        execution['assertions'][0] = {}
    elif kind == 'malformed-assertion':
        execution['assertions'][0] = {'assertion': 7, 'skipped': False}
    elif kind == 'blank-assertion':
        execution['assertions'][0]['assertion'] = '  '
    elif kind == 'malformed-skipped':
        execution['assertions'][0]['skipped'] = 0
    else:
        execution['assertions'][0]['error'] = False
    write_json(path, doc)
    assert not helper.prove(root, original, private)
    state = read_json(private / 'state.json')
    assert state['verifierActualRC'] == 0
    assert state['accepted'] is False
    with pytest.raises(ValueError):
        helper.seal(root, original, private, cleaned)
    assert not (cleaned / 'preclean-execution-proof.json').exists()


def test_repeated_poll_position_is_legal_without_script_total_equality(world):
    root, original, private, cleaned = world
    path = original / (helper.STEMS[0] + '.json'); doc = read_json(path)
    run = doc['run']
    run['executions'].append(copy.deepcopy(run['executions'][0]))
    run['stats']['requests']['total'] = run['stats']['assertions']['total'] = 3
    run['stats']['items']['total'] = 3
    run['stats']['scripts']['total'] = 12
    run['stats']['prerequestScripts']['total'] = run['stats']['testScripts']['total'] = 6
    write_json(path, doc)
    # Чистка в этой синтетической оси не исполняется; очищенные bytes связываются как данные.
    assert helper.prove(root, original, private)
    receipt = helper.seal(root, original, private, cleaned)
    row = receipt['collections'][0]
    assert row['requests'] == row['assertions'] == 3 and row['leaves'] == row['executed'] == 2
