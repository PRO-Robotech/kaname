#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Неизменный execution-verifier до чистки; после неё — безопасная связь hashes."""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

STEMS = (
    'authz-deny', 'iam-account', 'iam-account-redesign', 'iam-membership-mine',
    'iam-membership-read', 'iam-read-authz-vget', 'iam-user', 'iam-whoami',
    'rbac-subject-channel-equivalence', 'rbac-visibility-set',
    'iam-access-binding-account-scope', 'iam-access-binding-include-revoked',
    'iam-access-binding-revocation-reason', 'iam-role-rights-stay-named',
    'iam-grant-delegation', 'iam-authz-grant-check-propagation',
    'iam-service-account', 'iam-service-account-creator', 'kaname-cluster-admins',
)
WORKFLOW = '.github/workflows/e2e-newman.yml'
SELF = '.github/scripts/preclean-execution-proof.py'
VERIFIER = 'tests/newman/scripts/exec-coverage.py'
STEP = 'коллекции волны церемонии гоняются (числовой вердикт)'
ROW_KEYS = {'stem', 'sourceSHA256', 'originalReportSHA256', 'cleanedReportSHA256',
            'rcFileSHA256', 'newmanActualRC', 'sourceFingerprint', 'reportFingerprint',
            'leaves', 'executed', 'explainedSkips', 'requests', 'assertions',
            'failedAssertions', 'unanswered', 'failedScripts', 'skippedAssertions'}
PROVENANCE_KEYS = {'repository', 'PR', 'headSHA', 'baseSHA', 'runID', 'runAttempt',
                   'jobKey', 'checkoutSHA', 'checkoutTree', 'checkoutParents', 'checkoutKind'}
CENSUS_KEYS = {'matched', 'judged', 'notJudged', 'executed', 'declared',
               'recordedSkips', 'explainedSkips'}
PUBLIC_KEYS = {'schema', 'accepted', 'provenance', 'helperSHA256', 'workflowSHA256',
               'verifierSHA256', 'verifierActualRC', 'verifierStdoutSHA256',
               'verifierStderrSHA256', 'census', 'collections'}


def require(condition):
    if not condition:
        raise ValueError('preclean-proof rejected')


def integer(value, minimum=0):
    require(type(value) is int and value >= minimum)
    return value


def hex_value(value, length=64):
    require(type(value) is str and re.fullmatch(f'[0-9a-f]{{{length}}}', value) is not None)


def file_sha(path):
    require(path.is_file() and not path.is_symlink())
    return hashlib.sha256(path.read_bytes()).hexdigest()


def exclusive_json(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=True, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o600)


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], timeout=30).decode().strip()


def provenance(root):
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    pr = event.get('pull_request')
    head = pr['head']['sha'] if pr else os.environ['GITHUB_SHA']
    base = pr['base']['sha'] if pr else event.get('before') or git(root, 'rev-parse', 'origin/main')
    checkout = git(root, 'rev-parse', 'HEAD')
    parents = git(root, 'rev-list', '--parents', '-n', '1', 'HEAD').split()[1:]
    kind = 'head' if checkout == head else 'pr-merge'
    value = {'repository': os.environ['GITHUB_REPOSITORY'], 'PR': event['number'] if pr else 0,
             'headSHA': head, 'baseSHA': base, 'runID': int(os.environ['GITHUB_RUN_ID']),
             'runAttempt': int(os.environ['GITHUB_RUN_ATTEMPT']), 'jobKey': os.environ['GITHUB_JOB'],
             'checkoutSHA': checkout, 'checkoutTree': git(root, 'rev-parse', 'HEAD^{tree}'),
             'checkoutParents': parents, 'checkoutKind': kind}
    validate_provenance(value)
    return value


def validate_provenance(value):
    require(type(value) is dict and set(value) == PROVENANCE_KEYS)
    require(value['repository'] == 'PRO-Robotech/kaname' and value['jobKey'] == 'stand-ceremony')
    integer(value['PR']); integer(value['runID'], 1); integer(value['runAttempt'], 1)
    for key in ('headSHA', 'baseSHA', 'checkoutSHA', 'checkoutTree'):
        hex_value(value[key], 40)
    require(type(value['checkoutParents']) is list)
    for parent in value['checkoutParents']:
        hex_value(parent, 40)
    if value['checkoutKind'] == 'head':
        require(value['checkoutSHA'] == value['headSHA'])
    else:
        require(value['checkoutKind'] == 'pr-merge')
        require(value['checkoutParents'] == [value['baseSHA'], value['headSHA']])


def declared_stems(root):
    import yaml
    workflow = yaml.safe_load((root / WORKFLOW).read_text())
    steps = workflow['jobs']['stand-ceremony']['steps']
    runs = [step['run'] for step in steps if step.get('name') == STEP]
    require(len(runs) == 1)
    argv = shlex.split(runs[0].replace('\\\n', ' '))
    require('./scripts/run.sh' in argv and '--remint-bootstrap' in argv)
    stems = [argv[index + 1] for index, arg in enumerate(argv) if arg == '--service']
    require(tuple(stems) == STEMS and len(set(stems)) == 19)
    return stems


def bound_sources(root, identity, stems):
    paths = [SELF, WORKFLOW, VERIFIER] + [f'tests/newman/collections/{s}.postman_collection.json' for s in stems]
    result = {}
    for name in paths:
        actual = (root / name).read_bytes()
        committed = subprocess.check_output(['git', '-C', str(root), 'show', identity['headSHA'] + ':' + name], timeout=30)
        require(actual == committed)
        result[name] = file_sha(root / name)
    return result


def canonical_module(root):
    spec = importlib.util.spec_from_file_location('kaname_canonical_execution_coverage', root / VERIFIER)
    require(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec)
    old = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = old
    return module


def parse_census(text, stems):
    values = re.findall(r'^CENSUS: (\d+) collection\(s\) matched; judged (\d+); not judged (\d+) \(no usable report\)$', text, re.M)
    require(len(values) == 1)
    matched, judged, not_judged = map(int, values[0])
    require(matched == judged == len(stems) and not_judged == 0)
    total = re.findall(r'^TOTAL executed (\d+)/(\d+) \(', text, re.M)
    skips = re.findall(r'^SKIPS: (\d+) RECORDED-SKIP .*?, (\d+) explained-skip ', text, re.M)
    require(len(total) == len(skips) == 1)
    executed, declared = map(int, total[0]); recorded, explained = map(int, skips[0])
    require(recorded == 0 and executed > 0 and executed + explained == declared)
    per_stem = {}
    for stem in stems:
        lines = re.findall(r'^' + re.escape(stem) + r': executed (\d+)/(\d+) \([^\n]*$', text, re.M)
        require(len(lines) == 1)
        per_stem[stem] = tuple(map(int, lines[0]))
    return dict(zip(('matched', 'judged', 'notJudged', 'executed', 'declared', 'recordedSkips', 'explainedSkips'),
                    (matched, judged, not_judged, executed, declared, recorded, explained))), per_stem


def original_row(root, original, stem, module, executed):
    source_path = root / f'tests/newman/collections/{stem}.postman_collection.json'
    report_path, rc_path = original / f'{stem}.json', original / f'{stem}.rc'
    source = json.loads(source_path.read_bytes()); report = json.loads(report_path.read_bytes())
    require(type(report.get('collection')) is dict and type(report['collection'].get('item')) is list)
    source_fp, leaves = module._leaf_fingerprint(source['item'])
    report_fp, report_leaves = module._leaf_fingerprint(report['collection']['item'])
    require(leaves == report_leaves == executed[1] and leaves > 0 and source_fp == report_fp)
    rc_text = rc_path.read_text().strip()
    require(re.fullmatch('0', rc_text) is not None)
    run = report['run']
    require(type(run) is dict and run.get('error') is None)
    stats = run['stats']; executions = run['executions']
    require(type(stats) is dict and {'iterations', 'items', 'scripts', 'prerequestScripts', 'testScripts', 'requests', 'assertions'} <= set(stats))
    # Счётчики берутся из реальной SDK-формы; число scripts не равно числу requests по определению.
    for group in stats.values():
        require(type(group) is dict and {'total', 'failed', 'pending'} <= set(group))
        for count in group.values():
            integer(count)
        require(group['failed'] == group['pending'] == 0)
    require(type(executions) is list and executions and run['failures'] == [])
    embedded = list(module._iter_leaves(report['collection']['item']))
    sdk_ids = [leaf.get('id') for leaf in embedded]
    require(all(type(value) is str and value for value in sdk_ids))
    require(len(sdk_ids) == len(set(sdk_ids)) == leaves)
    require(all(type(leaf.get('name')) is str and leaf['name'].strip() for leaf in embedded))
    requests = integer(stats['requests']['total'], 1)
    assertions = integer(stats['assertions']['total'], 1)
    failed = integer(stats['assertions']['failed']); unanswered = integer(stats['requests']['failed'])
    scripts = integer(stats['testScripts']['failed']) + integer(stats['prerequestScripts']['failed'])
    require(failed == unanswered == scripts == 0)
    require(len(executions) == requests)
    for execution in executions:
        require(type(execution) is dict and type(execution.get('cursor')) is dict)
        cursor = execution['cursor']
        require(integer(cursor['length'], 1) == leaves)
        position = integer(cursor['position'])
        require(position < leaves)
        item = execution.get('item')
        require(type(item) is dict)
        require(item.get('id') == embedded[position]['id'] and item.get('name') == embedded[position]['name'])
        # Одна позиция может законно повторяться при poll; уникальны SDK IDs самих embedded leaves.
        require(type(execution.get('assertions', [])) is list)
    assertion_records = [a for ex in executions for a in ex.get('assertions', [])]
    for assertion in assertion_records:
        require(type(assertion) is dict)
        require(type(assertion.get('assertion')) is str and assertion['assertion'].strip())
        require(type(assertion.get('skipped', False)) is bool and assertion.get('skipped', False) is False)
        require(assertion.get('error') is None)
    skipped = sum(a.get('skipped') is True for a in assertion_records)
    require(skipped == 0 and not any(a.get('error') for a in assertion_records))
    require(len(assertion_records) == assertions)
    require(not any(ex.get('requestError') for ex in executions))
    return {'stem': stem, 'sourceSHA256': file_sha(source_path), 'originalReportSHA256': file_sha(report_path),
            'cleanedReportSHA256': None, 'rcFileSHA256': file_sha(rc_path), 'newmanActualRC': 0,
            'sourceFingerprint': source_fp, 'reportFingerprint': report_fp, 'leaves': leaves,
            'executed': executed[0], 'explainedSkips': leaves - executed[0], 'requests': requests,
            'assertions': assertions, 'failedAssertions': failed, 'unanswered': unanswered,
            'failedScripts': scripts, 'skippedAssertions': skipped}


def prove(root, original, private):
    private.mkdir(mode=0o700, parents=False, exist_ok=False)
    state = {'accepted': False, 'verifierActualRC': None}
    try:
        identity = provenance(root); stems = declared_stems(root)
        sources = bound_sources(root, identity, stems)
        state.update(provenance=identity, sources=sources)
        # Hash исходного отчёта снимается ДО CLI, затем проверяется после него.
        originals = [original / (stem + suffix) for stem in stems for suffix in ('.json', '.rc')]
        state['originalPins'] = {path.name: file_sha(path) if path.is_file() and not path.is_symlink() else None for path in originals}
        selected = private / 'collections'; selected.mkdir(mode=0o700)
        for stem in stems:
            (selected / f'{stem}.postman_collection.json').write_bytes((root / f'tests/newman/collections/{stem}.postman_collection.json').read_bytes())
        # Настоящий CLI, его source не изменяется; raw никогда не попадает в публичный каталог.
        with (private / 'verifier.stdout').open('xb') as stdout, (private / 'verifier.stderr').open('xb') as stderr:
            process = subprocess.run([sys.executable, str(root / VERIFIER), '--collections-glob', str(selected / '*.postman_collection.json'), '--out-dir', str(original)],
                                     cwd=root, stdout=stdout, stderr=stderr, timeout=180)
            state['verifierActualRC'] = process.returncode
            for stream in (stdout, stderr):
                stream.flush(); os.fsync(stream.fileno())
        state['verifierStdoutSHA256'] = file_sha(private / 'verifier.stdout')
        state['verifierStderrSHA256'] = file_sha(private / 'verifier.stderr')
        require(type(state['verifierActualRC']) is int and state['verifierActualRC'] == 0)
        require(all(value is not None for value in state['originalPins'].values()))
        require(all(file_sha(original / name) == value for name, value in state['originalPins'].items()))
        require(provenance(root) == identity)
        census, per_stem = parse_census((private / 'verifier.stdout').read_text(), stems)
        module = canonical_module(root)
        rows = [original_row(root, original, stem, module, per_stem[stem]) for stem in stems]
        require(sources == bound_sources(root, identity, stems))
        state.update(census=census, collections=rows, accepted=True)
    except Exception as exc:
        state['rejectedType'] = type(exc).__name__
    finally:
        exclusive_json(private / 'state.json', state)
    return state['accepted']


def validate_receipt(receipt, cleaned=None):
    require(type(receipt) is dict and set(receipt) == PUBLIC_KEYS)
    require(receipt['schema'] == 'preclean-execution-v1' and receipt['accepted'] is True)
    validate_provenance(receipt['provenance'])
    for key in ('helperSHA256', 'workflowSHA256', 'verifierSHA256', 'verifierStdoutSHA256', 'verifierStderrSHA256'):
        hex_value(receipt[key])
    require(integer(receipt['verifierActualRC']) == 0)
    census = receipt['census']; require(type(census) is dict and set(census) == CENSUS_KEYS)
    for value in census.values(): integer(value)
    require(census['matched'] == census['judged'] == 19 and census['notJudged'] == census['recordedSkips'] == 0)
    require(census['executed'] > 0 and census['executed'] + census['explainedSkips'] == census['declared'])
    rows = receipt['collections']; require(type(rows) is list and len(rows) == 19)
    require([row.get('stem') for row in rows] == list(STEMS))
    for row in rows:
        require(type(row) is dict and set(row) == ROW_KEYS)
        for key in ('sourceSHA256', 'originalReportSHA256', 'cleanedReportSHA256', 'rcFileSHA256'): hex_value(row[key])
        hex_value(row['sourceFingerprint'], 16); hex_value(row['reportFingerprint'], 16)
        require(row['sourceFingerprint'] == row['reportFingerprint'])
        for key in ('newmanActualRC', 'leaves', 'executed', 'explainedSkips', 'requests', 'assertions', 'failedAssertions', 'unanswered', 'failedScripts', 'skippedAssertions'): integer(row[key])
        require(row['leaves'] > 0 and row['requests'] > 0 and row['assertions'] > 0)
        require(row['executed'] + row['explainedSkips'] == row['leaves'])
        require(row['newmanActualRC'] == row['failedAssertions'] == row['unanswered'] == row['failedScripts'] == row['skippedAssertions'] == 0)
        if cleaned is not None:
            require(file_sha(cleaned / (row['stem'] + '.json')) == row['cleanedReportSHA256'])
    require(sum(row['leaves'] for row in rows) == census['declared'])
    require(sum(row['executed'] for row in rows) == census['executed'])
    require(sum(row['explainedSkips'] for row in rows) == census['explainedSkips'])


def seal(root, original, private, cleaned):
    state = json.loads((private / 'state.json').read_bytes())
    require(state['accepted'] is True and 'rejectedType' not in state)
    require(state['provenance'] == provenance(root))
    require(all(value is not None and file_sha(original / name) == value for name, value in state['originalPins'].items()))
    require(state['sources'] == bound_sources(root, state['provenance'], declared_stems(root)))
    for key, name in (('verifierStdoutSHA256', 'verifier.stdout'), ('verifierStderrSHA256', 'verifier.stderr')):
        require(file_sha(private / name) == state[key])
    require(integer(state['verifierActualRC']) == 0)
    census, per_stem = parse_census((private / 'verifier.stdout').read_text(), list(STEMS))
    require(state['census'] == census)
    receipt = {key: copy.deepcopy(state[key]) for key in ('provenance', 'verifierActualRC', 'verifierStdoutSHA256', 'verifierStderrSHA256', 'census', 'collections')}
    receipt.update(schema='preclean-execution-v1', accepted=True, helperSHA256=state['sources'][SELF], workflowSHA256=state['sources'][WORKFLOW], verifierSHA256=state['sources'][VERIFIER])
    module = canonical_module(root)
    for row in receipt['collections']:
        require(row == original_row(root, original, row['stem'], module, per_stem[row['stem']]))
        row['cleanedReportSHA256'] = file_sha(cleaned / (row['stem'] + '.json'))
    validate_receipt(receipt, cleaned)
    target = cleaned / 'preclean-execution-proof.json'
    exclusive_json(target, receipt)
    try:
        validate_receipt(receipt, cleaned)
    except Exception:
        target.unlink()
        raise
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prove', 'seal'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--original', type=Path, required=True)
    parser.add_argument('--private', type=Path, required=True)
    parser.add_argument('--cleaned', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.action == 'prove':
            accepted = prove(args.root.resolve(), args.original.resolve(), args.private.resolve())
        else:
            require(args.cleaned is not None)
            seal(args.root.resolve(), args.original.resolve(), args.private.resolve(), args.cleaned.resolve())
            accepted = True
    except Exception:
        accepted = False
    # Ни исключения, ни canonical raw не печатаются: там могут быть исходные секреты.
    print('preclean execution proof: ' + ('accepted' if accepted else 'rejected'))
    return 0 if accepted else 1


if __name__ == '__main__':
    sys.exit(main())
