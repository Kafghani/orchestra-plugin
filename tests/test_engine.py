import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / 'plugins/orchestra/scripts'
sys.path.insert(0, str(SCRIPTS))
from pathlib import Path

from orchestra_core.engine import AUTONOMY_FIXED, Engine, EngineError, autonomy_preconditions

STATE_2_3 = pathlib.Path(__file__).resolve().parent / 'fixtures/state-2.3.json'
STATE_2_4 = pathlib.Path(__file__).resolve().parent / 'fixtures/state-2.4.json'


def load_2_3_state(root, repo, name='state-2.3'):
    """A state.json written by the 2.3 engine (`start`, no policy), bound to `repo`; returns (state dir, lease)."""
    data = json.loads(STATE_2_3.read_text())
    data['repo'] = str(pathlib.Path(repo).resolve())
    state = pathlib.Path(root) / name
    state.mkdir()
    (state / 'state.json').write_text(json.dumps(data))
    return state, data['session']['lease']


def load_2_4_state(root, repo, name='state-2.4'):
    """A state.json written by the 2.4 engine (`start --items 3`), bound to `repo` and its HEAD; returns (state dir, lease)."""
    data = json.loads(STATE_2_4.read_text())
    data['repo'] = str(pathlib.Path(repo).resolve())
    data['session']['base'] = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
    state = pathlib.Path(root) / name
    state.mkdir()
    (state / 'state.json').write_text(json.dumps(data))
    return state, data['session']['lease']


def done(text='done', checks=None, criteria=None):
    """A builder report body with its single SELF_REVIEW line."""
    review = {'checks': checks if checks is not None else [{'command': 'python3 -m unittest', 'exit_code': 0}],
              'criteria': criteria if criteria is not None else [{'criterion': 'check behavior', 'met': True, 'evidence': 'checked'}]}
    return text + '\nARTIFACT: fixture\nSELF_REVIEW: ' + json.dumps(review)


class EngineFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='engine with spaces ', ignore_cleanup_errors=os.name == 'nt')
        self.root = pathlib.Path(self.tmp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'user.name', 'Test')
        (self.repo / 'a').write_text('initial')
        self.git('add', 'a')
        self.git('commit', '-qm', 'initial')
        self.engine = Engine(self.root / 'state', self.repo)
        self.lease = self.engine.open_session('main')

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], text=True).strip()

    def allow_review(self, *reviewers):
        """A non-final receipt is recorded only from a critic card's worker (contract item 4): give each name one."""
        for name in reviewers or ('reviewer',):
            card = 'critic-' + name
            if any(t['role'] == 'critic' and t.get('worker') == name for t in self.engine.status()['tasks'].values()):
                continue
            self.task(card, role='critic', mode='judge', files=[])
            token = self.engine.dispatch('main', self.lease, card, name)
            self.engine.report(name, token, 'Judged.')
            self.engine.accept('main', self.lease, card)

    def task(self, name='a', **kw):
        task = dict(id=name, role='builder', mode='implementation', inputs=['spec'], acceptance=['check behavior'], files=[name], resources=[], dependencies=[])
        task.update(kw)
        self.engine.add_task('main', self.lease, task)

    def review(self, path, reviewer='reviewer', categories=None, tasks=None, findings=None, final=False, engine=None,
               task_findings=None, repair_check=None, cleared=None):
        engine = engine or self.engine
        artifact = engine.artifact() if final or not tasks else engine.artifact(engine.scope_for(tasks))
        body = dict(reviewer=reviewer, categories=categories or ['correctness'],
                    tasks=tasks or [], findings=findings or [], final=final,
                    issues=[dict(text=f, severity='blocking', impact='Fixture impact: a named requirement is unmet.')
                            for f in findings or []],
                    verdict='BLOCKED' if findings else 'CLEAN', artifact=artifact,
                    summary='Behavior checked against acceptance criteria.')
        if task_findings is not None:
            body['task_findings'] = task_findings
        if repair_check is not None:
            body['repair_check'] = repair_check
        if cleared is not None:
            body['cleared'] = cleared
        path.write_text(json.dumps(body))


class EngineTests(EngineFixture):
    def test_inline_and_worker_execution_share_ownership(self):
        self.task('inline')
        self.task('parallel')
        self.task('collision', files=['inline'])
        token = self.engine.start_inline('main', self.lease, 'inline')
        self.engine.dispatch('main', self.lease, 'parallel', 'worker')
        with self.assertRaises(EngineError):
            self.engine.dispatch('main', self.lease, 'collision', 'other')
        self.engine.report('main', token, done('Inline implementation checked'))
        self.assertTrue(self.engine.status()['tasks']['inline']['inline'])
        self.engine.accept('main', self.lease, 'inline')

    def test_inline_cannot_replace_independent_review_or_survive_interruption(self):
        self.task('built')
        self.task('review', role='code-reviewer', mode='final', review_of=['built'])
        with self.assertRaises(EngineError):
            self.engine.start_inline('main', self.lease, 'review')
        self.task('inline')
        token = self.engine.start_inline('main', self.lease, 'inline')
        self.engine.interrupt('main', self.lease)
        with self.assertRaises(EngineError):
            self.engine.report('main', token, done('Late inline result'))

    def test_invalid_tasks_and_capacity(self):
        for kw in [dict(role='unknown'), dict(mode='unknown'), dict(acceptance=[]), dict(files=['../escape']), dict(dependencies=['missing'])]:
            with self.assertRaises(EngineError):
                self.task(**kw)
        self.task()
        self.task('b', files=['a/child'])
        self.engine.dispatch('main', self.lease, 'a', 'worker')
        self.assertEqual([], self.engine.ready('main', self.lease))
        with self.assertRaises(EngineError):
            self.engine.dispatch('main', self.lease, 'b', 'other')

    def test_report_needs_coordinator_accept(self):
        self.task()
        token = self.engine.dispatch('main', self.lease, 'a', 'worker')
        with self.assertRaises(EngineError):
            self.engine.report('worker', token, '')
        self.engine.report('worker', token, done('implemented'))
        with self.assertRaises(EngineError):
            self.engine.accept('main', 'not-the-lease', 'a')
        self.engine.accept('main', self.lease, 'a')  # a builder card needs no independent review
        self.assertEqual('accepted', self.engine.status()['tasks']['a']['state'])

    def test_interrupt_rejects_late_report(self):
        self.task()
        token = self.engine.dispatch('main', self.lease, 'a', 'worker')
        self.engine.interrupt('main', self.lease)
        with self.assertRaises(EngineError):
            self.engine.report('worker', token, done('done'))
        with self.assertRaises(EngineError):
            self.engine.ready('main', self.lease)

    def test_artifact_content_and_policy_binding(self):
        before = self.engine.artifact()
        (self.repo / 'new').write_text('one')
        one = self.engine.artifact()
        (self.repo / 'new').write_text('two')
        self.assertNotEqual(before, one)
        self.assertNotEqual(one, self.engine.artifact())
        with self.assertRaises(EngineError):
            Engine(self.root / 'state', self.repo, {'max_workers': 1}).ready('main', self.lease)

    def test_gate_actual_exit_and_mutation(self):
        good = self.engine.run_gate('main', self.lease, 'good', [sys.executable, '-c', 'print("ok")'])
        self.assertTrue(good['passed'])
        bad = self.engine.run_gate('main', self.lease, 'bad', [sys.executable, '-c', 'raise SystemExit(3)'])
        self.assertEqual(3, bad['exit_code'])
        self.assertFalse(bad['passed'])
        changed = self.engine.run_gate('main', self.lease, 'mutation', [sys.executable, '-c', 'open("a","w").write("changed")'])
        self.assertFalse(changed['passed'])
        with self.assertRaises(EngineError):
            self.engine.run_gate('main', self.lease, 'fake', 'true')

    def test_release_requires_complete_current_evidence(self):
        policy = dict(required_checks=[dict(name='unit', argv=[sys.executable, '-c', 'print("passed")'])], release=dict(enabled=True, authorization='user request', remote='devops', target='main', argv=['git', 'push', 'devops', 'HEAD:main']))
        engine = Engine(self.root / 'release-state', self.repo, policy)
        lease = engine.open_session('main')
        with self.assertRaises(EngineError):
            engine.release_permit('main', lease, 'devops', 'main')
        report = self.root / 'final.txt'
        report.write_text('Independent whole artifact review: clean.')
        categories = ['requirements', 'correctness', 'security', 'tests', 'architecture', 'standards', 'cleanup']
        self.review(report, categories=categories, final=True, engine=engine)
        engine.record_review('main', lease, 'reviewer', report, categories, final=True)
        engine.run_gate('main', lease, 'unit', [sys.executable, '-c', 'print("passed")'])
        with self.assertRaises(EngineError):
            engine.check_release('devops', 'main')
        permit = engine.release_permit('main', lease, 'devops', 'main')
        self.assertEqual('release', permit['action'])
        self.assertEqual(permit, engine.check_release('devops', 'main'))
        with self.assertRaises(EngineError):
            engine.check_release('devops', 'main', argv=['git', 'push', 'devops', 'other'])
        with self.assertRaises(EngineError):
            engine.release_permit('main', lease, 'origin', 'main')
        report.write_text('altered')
        with self.assertRaises(EngineError):
            engine.release_permit('main', lease, 'devops', 'main')

class MoreEngineTests(EngineFixture):
    def test_continuous_ready_and_dependency(self):
        self.task()
        self.task('b')
        self.task('c', dependencies=['a'])
        token = self.engine.dispatch('main', self.lease, 'a', 'builder-a')
        self.assertEqual(['b'], self.engine.ready('main', self.lease))
        self.engine.report('builder-a', token, done('built a'))
        self.engine.accept('main', self.lease, 'a')
        self.assertEqual(['b', 'c'], self.engine.ready('main', self.lease))

    def test_stale_review_and_gate_log(self):
        self.task()
        token = self.engine.dispatch('main', self.lease, 'a', 'builder')
        self.engine.report('builder', token, done('done'))
        (self.repo / 'a').write_text('new state')
        with self.assertRaisesRegex(EngineError, 'Reported artifact is stale'):
            self.engine.accept('main', self.lease, 'a')
        gate = self.engine.run_gate('main', self.lease, 'check', [sys.executable, '-c', 'print("ok")'])
        pathlib.Path(gate['path']).write_text('altered')
        self.assertFalse(self.engine._intact(gate))

    def test_repair_needs_findings(self):
        with self.assertRaises(EngineError):
            self.task(mode='repair')
        self.task()
        token = self.engine.dispatch('main', self.lease, 'a', 'builder')
        self.engine.report('builder', token, done('done'))
        self.allow_review()
        report = self.root / 'review'
        self.review(report, tasks=['a'], findings=['Behavior fails for empty input'])
        self.engine.record_review('main', self.lease, 'reviewer', report, ['correctness'], ['a'], findings=['Behavior fails for empty input'])
        with self.assertRaises(EngineError):
            self.engine.accept('main', self.lease, 'a')
        self.task('repair', mode='repair', files=['repair'], repair_of='a')

    def test_review_metadata_and_nonbuilder_accept(self):
        self.task(role='investigator', mode='code')
        token = self.engine.dispatch('main', self.lease, 'a', 'investigator')
        self.engine.report('investigator', token, done('Code symbols inspected; evidence attached.'))
        self.engine.accept('main', self.lease, 'a')
        report = self.root / 'review'
        report.write_text('BLOCKED')
        with self.assertRaises(EngineError):
            self.engine.record_review('main', self.lease, 'reviewer', report, ['correctness'], ['a'])
        self.review(report, tasks=['a'])
        body = json.loads(report.read_text())
        body['verdict'] = 'BLOCKED'
        report.write_text(json.dumps(body))
        with self.assertRaises(EngineError):
            self.engine.record_review('main', self.lease, 'reviewer', report, ['correctness'], ['a'])

    def test_lock_preserves_concurrent_cards(self):
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda n: self.task('task-' + str(n)), range(12)))
        self.assertEqual(12, len(self.engine.status()['tasks']))

class IntegrationRepairTests(EngineFixture):
    def test_canonical_modes(self):
        for role, mode in [('designer-planner', 'product'), ('critic', 'surface'), ('critic', 'scope'),
                           ('operator', 'gate'), ('operator', 'cleanup'), ('operator', 'release')]:
            name = role + '-' + mode
            self.task(name, role=role, mode=mode)
            self.engine.dispatch('main', self.lease, name, name + '-worker')
        with self.assertRaises(EngineError):
            self.task('old-mode', role='operator', mode='default')

    def test_old_role_names_are_unavailable(self):
        for role, mode in [('founder-mind', 'audit'), ('red-teamer', 'scope'), ('auditor', 'spec'),
                           ('gatekeeper', 'checks'), ('janitor', 'hygiene'), ('releaser', 'release')]:
            with self.assertRaises(EngineError, msg=role):
                self.task(role, role=role, mode=mode)

    def test_builder_cleanup_needs_no_repair_of(self):
        self.task('clean', mode='cleanup')
        self.engine.dispatch('main', self.lease, 'clean', 'cleanup-worker')

    def test_critic_review_of_and_no_inline_execution(self):
        self.task('B1')
        self.task('C1', role='critic', mode='spec', files=[], review_of=['B1'])
        self.task('C2', role='critic', mode='judge', files=[])
        with self.assertRaises(EngineError):
            self.engine.start_inline('main', self.lease, 'C2')
        token = self.engine.dispatch('main', self.lease, 'B1', 'builder')
        self.engine.report('builder', token, done('Built'))
        self.assertIn('C1', self.engine.ready('main', self.lease))
        modes = {'investigator': 'code', 'designer-planner': 'plan', 'operator': 'gate', 'builder': 'implementation'}
        for role, mode in modes.items():
            with self.assertRaises(EngineError, msg=role):
                self.task('bad-' + role, role=role, mode=mode, review_of=['B1'])

    def test_gate_guard_and_timeout(self):
        for argv in [['git', 'reset', '--hard'], ['git', 'push', 'origin', 'main'], ['bash', '-c', 'git stash']]:
            with self.assertRaises(EngineError):
                self.engine.run_gate('main', self.lease, 'unsafe', argv)
        engine = Engine(self.root / 'bounded', self.repo, {'gate_timeout_seconds': 0.05})
        lease = engine.open_session('main')
        receipt = engine.run_gate('main', lease, 'hang', [sys.executable, '-c', 'import time; time.sleep(10)'])
        self.assertEqual(124, receipt['exit_code'])
        self.assertFalse(receipt['passed'])

    def test_gate_timeout_overrides_the_policy_for_one_run(self):
        receipt = self.engine.run_gate('main', self.lease, 'hang', [sys.executable, '-c', 'import time; time.sleep(10)'],
                                       timeout=0.05)
        self.assertEqual(124, receipt['exit_code'])
        receipt = self.engine.run_gate('main', self.lease, 'quick', [sys.executable, '-c', 'pass'], timeout=30)
        self.assertTrue(receipt['passed'])
        for timeout in (0, -1, float('nan'), float('inf'), True, '5'):
            with self.subTest(timeout=timeout), self.assertRaisesRegex(EngineError, 'Gate timeout must be positive and finite'):
                self.engine.run_gate('main', self.lease, 'bad', [sys.executable, '-c', 'pass'], timeout=timeout)

    def test_bad_state_is_engine_error(self):
        for value in [[], {}, {'repo': str(self.repo)}, {'version': 1, 'repo': str(self.repo), 'policy': self.engine.policy_hash, 'tasks': []}]:
            self.engine.state_path.write_text(json.dumps(value))
            with self.assertRaises(EngineError):
                self.engine.status()
        self.engine.state_path.write_text('{')
        with self.assertRaises(EngineError):
            self.engine.status()

    def test_final_review_requires_explicit_task_coverage(self):
        self.task(role='investigator', mode='code')
        token = self.engine.dispatch('main', self.lease, 'a', 'worker')
        self.engine.report('worker', token, done('checked'))
        self.engine.accept('main', self.lease, 'a')
        report = self.root / 'final.json'
        self.review(report, final=True)
        with self.assertRaises(EngineError):
            self.engine.record_review('main', self.lease, 'reviewer', report, ['correctness'], final=True)

    def package_copy(self):
        import shutil
        package = self.root / 'package'
        shutil.copytree(pathlib.Path(__file__).resolve().parents[1] / 'plugins/orchestra', package)
        return package

    def test_method_missing_and_changed_contract_invalidates_run(self):
        from unittest.mock import patch
        package = self.package_copy()
        with patch('orchestra_core.engine.PACKAGE_ROOT', package):
            engine = Engine(self.root / 'contracts', self.repo)
            lease = engine.open_session('main')
            task = dict(id='a', role='builder', mode='implementation', inputs=['https://example.com'], acceptance=['done'], files=['a'], resources=[], dependencies=[])
            engine.add_task('main', lease, task)
            method = package / 'skills/orchestra-build/SKILL.md'
            # An edited method keeps the live run (SPEC 11.1 item 5).
            method.write_text(method.read_text() + '\nNew binding rule.\n')
            engine.dispatch('main', lease, 'a', 'worker')
            self.assertEqual('running', Engine(self.root / 'contracts', self.repo).status()['tasks']['a']['state'])
            # A missing method still fails validation.
            method.unlink()
            with self.assertRaises(EngineError):
                engine.status()
            with self.assertRaises(EngineError):
                Engine(self.root / 'new-contracts', self.repo)

    def test_added_mode_invalidates_run(self):
        from unittest.mock import patch
        package = self.package_copy()
        with patch('orchestra_core.engine.PACKAGE_ROOT', package):
            engine = Engine(self.root / 'contracts', self.repo)
            lease = engine.open_session('main')
            roles = json.loads((package / 'config/roles.json').read_text())
            next(r for r in roles['roles'] if r['id'] == 'builder')['modes'].append('extra-mode')
            (package / 'config/roles.json').write_text(json.dumps(roles))
            with self.assertRaisesRegex(EngineError, 'start a new run'):
                engine.status()
            with self.assertRaisesRegex(EngineError, 'start a new run'):
                engine.add_task('main', lease, dict(id='a', role='builder', mode='implementation', inputs=['x'], acceptance=['y'], files=['a'], resources=[], dependencies=[]))

    def test_added_orchestrator_mode_invalidates_run(self):
        from unittest.mock import patch
        package = self.package_copy()
        with patch('orchestra_core.engine.PACKAGE_ROOT', package):
            engine = Engine(self.root / 'contracts', self.repo)
            engine.open_session('main')
            roles = json.loads((package / 'config/roles.json').read_text())
            next(r for r in roles['roles'] if r['id'] == 'orchestrator')['modes'].append('extra-mode')
            (package / 'config/roles.json').write_text(json.dumps(roles))
            with self.assertRaisesRegex(EngineError, 'start a new run'):
                engine.status()

    def test_status_has_no_lease_key_anywhere(self):
        self.task('a')
        token = self.engine.dispatch('main', self.lease, 'a', 'worker')
        self.assertNotIn('"lease"', json.dumps(self.engine.status()))
        self.assertTrue(self.engine.status()['session']['active'])
        self.assertEqual('running', self.engine.status()['tasks']['a']['state'])
        # The stored state keeps both leases; redaction is on the read path only.
        raw = json.loads(self.engine.state_path.read_text())
        self.assertEqual(self.lease, raw['session']['lease'])
        self.assertEqual(self.lease, raw['tasks']['a']['lease'])
        self.engine.report('worker', token, done('checked'))

    def test_narrowed_categories_accepted_and_empty_or_unknown_rejected(self):
        for bad in ([], ['nonsense'], ['correctness', 'nonsense'], 'correctness'):
            with self.assertRaises(EngineError):
                Engine(self.root / 'bad', self.repo, {'required_review_categories': bad})
        def accepted(engine, lease):
            task = dict(id='a', role='investigator', mode='code', inputs=['spec'], acceptance=['check'], files=['a'], resources=[], dependencies=[])
            engine.add_task('main', lease, task)
            engine.report('worker', engine.dispatch('main', lease, 'a', 'worker'), done('checked'))
            engine.accept('main', lease, 'a')

        report = self.root / 'final.json'
        policy = {'required_review_categories': ['correctness', 'tests']}
        engine = Engine(self.root / 'narrow', self.repo, policy)
        lease = engine.open_session('main')
        accepted(engine, lease)
        self.review(report, categories=['correctness', 'tests'], tasks=['a'], final=True, engine=engine)
        engine.record_review('main', lease, 'reviewer', report, ['correctness', 'tests'], ['a'], final=True)
        engine.check_completion('main', lease)
        # A narrowed policy still demands its own categories.
        engine2 = Engine(self.root / 'narrow2', self.repo, policy)
        lease2 = engine2.open_session('main')
        accepted(engine2, lease2)
        self.review(report, categories=['correctness'], tasks=['a'], final=True, engine=engine2)
        engine2.record_review('main', lease2, 'reviewer', report, ['correctness'], ['a'], final=True)
        with self.assertRaisesRegex(EngineError, 'coverage'):
            engine2.check_completion('main', lease2)

    def test_old_policy_with_removed_keys_still_loads(self):
        engine = Engine(self.root / 'old', self.repo, {'reserved_ports': [1], 'denied_tools': ['x']})
        engine.open_session('main')

    def test_invalid_timeout_and_optional_brief(self):
        for timeout in [0, -1, True, '300', float('inf')]:
            with self.assertRaises(EngineError):
                Engine(self.root / 'invalid', self.repo, {'gate_timeout_seconds': timeout})
        for values in [dict(objective=' '), dict(brief='missing'), dict(inputs=[' '])]:
            with self.assertRaises(EngineError):
                self.task(**values)
        brief = self.root / 'brief.md'
        brief.write_text('Mode: implementation\nObjective and bounded acceptance criteria.\n## Keep\nnone\n## Remove\nnone\n')
        self.task(brief=str(brief))
        brief.unlink()
        with self.assertRaises(EngineError):
            self.engine.dispatch('main', self.lease, 'a', 'worker')

    def test_brief_file_needs_the_cards_mode_line(self):
        cases = {'no-mode.md': 'Objective and bounded acceptance criteria.',
                 'wrong-mode.md': 'Mode: repair\nObjective.',
                 'inline-mention.md': 'The card runs Mode: implementation somewhere in prose.',
                 'other-prefix.md': 'Mode: implementation-extra\nObjective.'}
        for name, text in cases.items():
            brief = self.root / name
            brief.write_text(text)
            with self.assertRaises(EngineError, msg=name):
                self.task(name, brief=str(brief))
        ok = self.root / 'ok.md'
        ok.write_text('# Brief\nMode: implementation\nObjective.\n## Keep\nnone\n## Remove\nnone\n')
        self.task('with-brief', brief=str(ok))
        self.task('without-brief')
        cleanup = self.root / 'cleanup.md'
        cleanup.write_text('Mode: cleanup\n## Keep\nnone\n## Remove\nnone\n')
        self.task('cleanup-brief', mode='cleanup', brief=str(cleanup))

    def test_scanner_availability_and_required_release_evidence(self):
        receipt = self.engine.run_secret_scan('main', self.lease)
        self.assertEqual(126, receipt['exit_code'])
        self.assertFalse(receipt['passed'])
        command = [sys.executable, '-c', 'print("scanned")']
        policy = dict(required_checks=[dict(name='unit', argv=command)],
                      secret_scan=dict(required=True, argv=command),
                      release=dict(enabled=True, authorization='user', remote='origin', target='main', argv=['git', 'push', 'origin', 'HEAD:main']))
        engine = Engine(self.root / 'scanner', self.repo, policy)
        lease = engine.open_session('main')
        report = self.root / 'final.json'
        from orchestra_core.engine import CATEGORIES
        self.review(report, categories=CATEGORIES, final=True, engine=engine)
        engine.record_review('main', lease, 'reviewer', report, CATEGORIES, final=True)
        engine.run_gate('main', lease, 'unit', command)
        with self.assertRaisesRegex(EngineError, 'secret-scan'):
            engine.release_permit('main', lease, 'origin', 'main')
        engine.run_secret_scan('main', lease)
        engine.release_permit('main', lease, 'origin', 'main')
        (self.repo / 'new').write_text('uncommitted')
        with self.assertRaisesRegex(EngineError, 'clean working tree'):
            engine.release_permit('main', lease, 'origin', 'main')
        policy['secret_scan']['argv'] = []
        engine = Engine(self.root / 'missing-scanner', self.repo, policy)
        lease = engine.open_session('main')
        with self.assertRaisesRegex(EngineError, 'unavailable'):
            engine.run_secret_scan('main', lease)


class CompletionTests(EngineFixture):
    def test_finish_needs_final_current_review_and_configured_gates(self):
        from orchestra_core.engine import CATEGORIES
        command = [sys.executable, '-c', 'print("checked")']
        self.engine = Engine(self.root / 'completion', self.repo,
                             dict(required_checks=[dict(name='unit', argv=command)],
                                  secret_scan=dict(required=True, argv=command)))
        self.lease = self.engine.open_session('main')
        self.task(role='investigator', mode='code')
        with self.assertRaises(EngineError):
            self.engine.close_session('main', self.lease)
        token = self.engine.dispatch('main', self.lease, 'a', 'worker')
        self.engine.report('worker', token, done('checked'))
        self.engine.accept('main', self.lease, 'a')
        with self.assertRaisesRegex(EngineError, 'final review'):
            self.engine.close_session('main', self.lease)
        report = self.root / 'final.json'
        self.review(report, categories=CATEGORIES, tasks=['a'], final=True)
        self.engine.record_review('main', self.lease, 'reviewer', report, CATEGORIES, ['a'], final=True)
        with self.assertRaisesRegex(EngineError, 'unit'):
            self.engine.check_completion('main', self.lease)
        self.engine.run_gate('main', self.lease, 'unit', command)
        with self.assertRaisesRegex(EngineError, 'secret-scan'):
            self.engine.close_session('main', self.lease)
        self.engine.run_secret_scan('main', self.lease)
        before = self.engine.state_path.read_bytes()
        self.engine.check_completion('main', self.lease)
        self.assertEqual(before, self.engine.state_path.read_bytes())
        report.write_text('altered')
        with self.assertRaisesRegex(EngineError, 'final review'):
            self.engine.close_session('main', self.lease)
        self.assertTrue(self.engine.status()['session']['active'])
        self.review(report, categories=CATEGORIES, tasks=['a'], final=True)
        self.engine.close_session('main', self.lease)
        state = self.engine.status()
        self.assertFalse(state['session']['active'])
        self.assertEqual('completed', state['session']['outcome'])
        self.assertEqual([], state['permits'])
        self.assertIsNone(state['autonomy'])

    def test_finish_without_configured_checks_still_needs_final_review(self):
        from orchestra_core.engine import CATEGORIES
        self.task(role='investigator', mode='code')
        token = self.engine.dispatch('main', self.lease, 'a', 'worker')
        self.engine.report('worker', token, done('checked'))
        self.engine.accept('main', self.lease, 'a')
        with self.assertRaises(EngineError):
            self.engine.check_completion('main', self.lease)
        report = self.root / 'final.json'
        self.review(report, categories=CATEGORIES, tasks=['a'], final=True)
        self.engine.record_review('main', self.lease, 'reviewer', report, CATEGORIES, ['a'], final=True)
        self.engine.close_session('main', self.lease)

    def test_empty_run_can_close_and_interrupt_is_distinct(self):
        self.engine.close_session('main', self.lease)
        self.assertEqual('completed', self.engine.status()['session']['outcome'])
        lease = self.engine.open_session('main')
        self.engine.interrupt('main', lease)
        self.assertNotEqual('completed', self.engine.status()['session'].get('outcome'))


class FinalBlockerTests(EngineFixture):
    def record(self, name, tasks, categories=None, findings=None, final=False, task_findings=None, repair_check=None):
        from orchestra_core.engine import CATEGORIES
        categories = categories or CATEGORIES
        if final:  # the final review covers every pre-release card, the critic cards of earlier receipts included
            tasks = [i for i, t in self.engine.status()['tasks'].items() if not (t['role'] == 'operator' and t['mode'] == 'release')]
        else:
            self.allow_review(name)
        path = self.root / (name + '.json')
        self.review(path, reviewer=name, tasks=tasks, categories=categories, findings=findings, final=final,
                    task_findings=task_findings, repair_check=repair_check)
        return self.engine.record_review('main', self.lease, name, path, categories,
                                         tasks, final=final, findings=findings)

    def release_setup(self, argv=None):
        command = [sys.executable, '-c', 'print("checked")']
        self.engine = Engine(self.root / 'release', self.repo, dict(
            max_workers=1, required_checks=[dict(name='unit', argv=command)],
            release=dict(enabled=True, authorization='user', remote='authorized', target='main',
                         argv=argv or ['git', 'push', 'authorized', 'HEAD:main'])))
        self.lease = self.engine.open_session('main')
        self.engine.run_gate('main', self.lease, 'unit', command)

    def test_repair_transfers_reservations_and_retains_history(self):
        self.release_setup()
        self.task('B1', files=['a'])
        self.task('D1', files=['d'], dependencies=['B1'], role='investigator', mode='code')
        token = self.engine.dispatch('main', self.lease, 'B1', 'first-builder')
        self.engine.report('first-builder', token, done('Original result'))
        self.record('blocked', ['B1'], findings=['Incorrect empty input'])
        self.task('R1', mode='repair', repair_of='B1', files=['a'])
        self.assertEqual(['R1'], self.engine.ready('main', self.lease))
        repair_token = self.engine.dispatch('main', self.lease, 'R1', 'repair-builder')
        with self.assertRaises(EngineError):
            self.engine.report('first-builder', token, done('late original report'))
        self.engine.report('repair-builder', repair_token, done('Repaired behavior'))
        self.record('clean', ['B1', 'R1'])
        with self.assertRaises(EngineError):
            self.engine.accept('main', self.lease, 'B1')
        self.engine.accept('main', self.lease, 'R1')
        self.engine.accept('main', self.lease, 'B1')
        state = self.engine.status()
        self.assertTrue(state['tasks']['B1']['report'].startswith('Original result'))
        self.assertEqual('first-builder', state['tasks']['B1']['worker'])
        self.assertEqual(['Incorrect empty input'], state['reviews'][0]['findings'])
        self.assertEqual(['D1'], self.engine.ready('main', self.lease))
        token = self.engine.dispatch('main', self.lease, 'D1', 'investigator')
        self.engine.report('investigator', token, done('Dependent completed'))
        self.engine.accept('main', self.lease, 'D1')
        self.record('final', ['B1', 'R1', 'D1'], final=True)
        self.engine.release_permit('main', self.lease, 'authorized', 'main')

    def test_latest_final_blocked_revokes_old_clean_and_permit(self):
        self.release_setup()
        self.record('clean-final', [], final=True)
        self.engine.release_permit('main', self.lease, 'authorized', 'main')
        self.record('blocked-final', [], categories=['security'], findings=['Credential leak'], final=True)
        with self.assertRaises(EngineError):
            self.engine.check_completion('main', self.lease)
        with self.assertRaises(EngineError):
            self.engine.check_release('authorized', 'main')
        self.record('unrelated-final', [], categories=['tests'], final=True)
        with self.assertRaises(EngineError):
            self.engine.release_permit('main', self.lease, 'authorized', 'main')
        self.record('resolved-final', [], categories=['security'], final=True)
        self.engine.release_permit('main', self.lease, 'authorized', 'main')

    def test_latest_blocked_receipt_prevents_accept_and_completion(self):
        self.task()
        token = self.engine.dispatch('main', self.lease, 'a', 'worker')
        self.engine.report('worker', token, done('done'))
        self.record('clean', ['a'])
        self.record('blocked', ['a'], categories=['security'], findings=['unsafe'])
        with self.assertRaises(EngineError):
            self.engine.accept('main', self.lease, 'a')
        self.record('resolved', ['a'], categories=['security'])
        self.engine.accept('main', self.lease, 'a')
        self.record('final', ['a'], final=True)
        self.record('later-checkpoint', ['a'], categories=['tests'], findings=['failing'])
        with self.assertRaises(EngineError):
            self.engine.check_completion('main', self.lease)

    def test_state_cannot_be_inside_plugin_or_via_symlink(self):
        from unittest.mock import patch
        package = self.root / 'plugin'
        package.mkdir()
        alias = self.root / 'alias'
        alias.symlink_to(package, target_is_directory=True)
        from orchestra_core.engine import _contracts
        contracts = _contracts()
        with patch('orchestra_core.engine.PACKAGE_ROOT', package), patch('orchestra_core.engine._contracts', return_value=contracts):
            for path in [package / 'state', alias / 'nested' / 'state', package]:
                with self.assertRaises(EngineError):
                    Engine(path, self.repo)
        self.assertEqual([], list(package.iterdir()))

    def test_release_rejects_known_git_destination_mismatch(self):
        self.release_setup(['git', 'push', 'authorized', 'HEAD:other'])
        self.record('final', [], final=True)
        with self.assertRaises(EngineError):
            self.engine.release_permit('main', self.lease, 'authorized', 'main')

    def test_review_card_uses_reported_work_without_consuming_writer_capacity(self):
        self.release_setup()
        self.task('B1', files=['a'])
        self.task('V1', role='critic', mode='judge', files=['a'], review_of=['B1'])
        self.assertEqual(['B1'], self.engine.ready('main', self.lease))
        token = self.engine.dispatch('main', self.lease, 'B1', 'builder')
        self.engine.report('builder', token, done('Built'))
        self.assertEqual(['V1'], self.engine.ready('main', self.lease))
        token = self.engine.dispatch('main', self.lease, 'V1', 'review-worker')
        self.engine.report('review-worker', token, done('Reviewed builder output'))
        self.record('review-worker', ['B1'])
        self.engine.accept('main', self.lease, 'V1')
        self.engine.accept('main', self.lease, 'B1')
        self.record('review-worker', [], final=True)
        self.engine.check_completion('main', self.lease)

    def test_second_repair_suspends_entire_same_file_chain(self):
        self.release_setup()
        self.task('B1', files=['a'])
        token = self.engine.dispatch('main', self.lease, 'B1', 'worker1')
        self.engine.report('worker1', token, done('First implementation'))
        self.record('blocked1', ['B1'], findings=['bug1'])
        self.task('R1', mode='repair', repair_of='B1', files=['a'])
        token = self.engine.dispatch('main', self.lease, 'R1', 'worker2')
        self.engine.report('worker2', token, done('First repair'))
        self.record('blocked2', ['B1', 'R1'], findings=['bug2'], task_findings={'R1': ['bug2']})
        self.engine.hold('main', self.lease, 'R1', 'bug2 persists after the first repair')
        self.task('R2', mode='repair', repair_of='R1', files=['a'])
        self.assertEqual(['R2'], self.engine.ready('main', self.lease))
        token = self.engine.dispatch('main', self.lease, 'R2', 'worker3')
        self.engine.report('worker3', token, done('Second repair'))
        self.record('clean2', ['R1', 'R2'])
        for name in ['R2', 'R1']:
            self.engine.accept('main', self.lease, name)
        self.engine.accept('main', self.lease, 'B1')  # the accepted repair chain carries the original
        self.assertTrue(all(t['state'] == 'accepted' for t in self.engine.status()['tasks'].values()))

    def test_review_targets_reject_wrong_role_and_dependency_cycle(self):
        self.task('B1')
        for values in [dict(review_of=['missing']), dict(review_of=['B1']),
                       dict(role='code-reviewer', mode='checkpoint', review_of=['B1'], dependencies=['B1']),
                       dict(role='code-reviewer', mode='checkpoint', review_of=[{}])]:
            with self.assertRaises(EngineError):
                self.task('invalid', **values)

    def test_add_refuses_code_reviewer_without_review_of(self):
        self.task('B1')
        for values in [dict(), dict(review_of=[]), dict(dependencies=['B1'])]:
            with self.subTest(values), self.assertRaisesRegex(EngineError, 'review_of'):
                self.task('R1', role='code-reviewer', mode='final', **values)

    def test_builder_accepts_without_independent_review(self):
        for name, extra in (('a', {}), ('b', dict(review_required=True)), ('c', dict(review_required=False))):
            self.task(name, **extra)
            token = self.engine.dispatch('main', self.lease, name, 'worker-' + name)
            self.engine.report('worker-' + name, token, done('done'))
            self.engine.accept('main', self.lease, name)
            self.assertEqual('accepted', self.engine.status()['tasks'][name]['state'])
        self.assertEqual([], self.engine.status()['reviews'])

    def test_repair_survives_interrupt_and_preserves_original_reservation(self):
        self.release_setup()
        self.task('B1', files=['a'])
        token = self.engine.dispatch('main', self.lease, 'B1', 'builder')
        self.engine.report('builder', token, done('Original result'))
        self.record('blocked', ['B1'], findings=['bug'])
        self.task('R1', mode='repair', repair_of='B1', files=['a'])
        self.task('outsider', files=['a'])
        self.assertEqual(['R1'], self.engine.ready('main', self.lease))
        token = self.engine.dispatch('main', self.lease, 'R1', 'repairer')
        self.engine.interrupt('main', self.lease)
        self.lease = self.engine.open_session('main')
        self.assertEqual(['R1'], self.engine.ready('main', self.lease))
        token = self.engine.dispatch('main', self.lease, 'R1', 'repairer2')
        self.engine.report('repairer2', token, done('Repair result'))
        self.engine.interrupt('main', self.lease)
        self.lease = self.engine.open_session('main')
        self.record('clean', ['B1', 'R1'])
        self.engine.accept('main', self.lease, 'R1')
        self.engine.accept('main', self.lease, 'B1')
        self.assertEqual(['outsider'], self.engine.ready('main', self.lease))

    def test_operator_release_card_runs_after_pre_release_review_then_closes(self):
        self.release_setup()
        self.task('B1', files=['a'])
        self.task('L1', role='operator', mode='release', files=[], dependencies=['B1'])
        token = self.engine.dispatch('main', self.lease, 'B1', 'builder')
        self.engine.report('builder', token, done('Built'))
        self.record('checkpoint', ['B1'])
        self.engine.accept('main', self.lease, 'B1')
        self.record('final', ['B1'], final=True)
        with self.assertRaises(EngineError):
            self.engine.release_permit('main', self.lease, 'authorized', 'main')
        with self.assertRaises(EngineError):
            self.task('L2', role='operator', mode='release', files=[])
        token = self.engine.dispatch('main', self.lease, 'L1', 'release-worker')
        permit = self.engine.release_permit('main', self.lease, 'authorized', 'main')
        self.assertEqual(permit, self.engine.check_release('authorized', 'main'))
        with self.assertRaises(EngineError):
            self.engine.check_completion('main', self.lease)
        self.engine.report('release-worker', token, done('Release command completed; observed remote evidence attached'))
        self.engine.accept('main', self.lease, 'L1')
        self.engine.close_session('main', self.lease)

    def test_release_exemption_never_skips_queued_builder(self):
        self.release_setup()
        self.task('B1', files=['a'])
        self.task('L1', role='operator', mode='release', files=[])
        with self.assertRaises(EngineError):
            self.record('too-early', ['B1'], final=True)
        with self.assertRaises(EngineError):
            self.engine.release_permit('main', self.lease, 'authorized', 'main')

    def test_ownership_rejects_globs(self):
        for path in ['src/**', 'file?.py', 'src/[ab].py']:
            with self.assertRaises(EngineError):
                self.task(files=[path])

    def test_git_release_rejects_dry_run_multiple_and_unknown_destinations(self):
        for argv in [
            ['git', 'push', '--dry-run', 'authorized', 'HEAD:main'],
            ['git', 'push', 'authorized', 'HEAD:main', 'HEAD:other'],
            ['git', '-C', str(self.repo), 'push', 'authorized', 'HEAD:main'],
            ['git', 'push', 'other-remote', 'HEAD:main'],
        ]:
            with self.subTest(argv=argv):
                self.release_setup(argv)
                self.record('final-' + str(len(argv)), [], final=True)
                with self.assertRaises(EngineError):
                    self.engine.release_permit('main', self.lease, 'authorized', 'main')
                self.engine.interrupt('main', self.lease)
                # Each recipe has a different policy and needs separate durable state.
                self.engine.state_path.unlink()

    def test_git_release_source_must_be_reviewed_head(self):
        self.git('branch', 'unchecked')
        (self.repo / 'a').write_text('reviewed current commit')
        self.git('add', 'a')
        self.git('commit', '-qm', 'reviewed commit')
        self.release_setup(['git', 'push', 'authorized', 'unchecked:main'])
        self.record('final', [], final=True)
        with self.assertRaises(EngineError):
            self.engine.release_permit('main', self.lease, 'authorized', 'main')

    def test_git_release_rechecks_source_after_permit(self):
        old = self.git('rev-parse', 'HEAD')
        (self.repo / 'a').write_text('reviewed current commit')
        self.git('add', 'a')
        self.git('commit', '-qm', 'reviewed commit')
        self.git('branch', 'candidate')
        self.release_setup(['git', 'push', 'authorized', 'candidate:main'])
        self.record('final', [], final=True)
        permit = self.engine.release_permit('main', self.lease, 'authorized', 'main')
        self.assertEqual(permit, self.engine.check_release('authorized', 'main'))
        self.git('update-ref', 'refs/heads/candidate', old)
        with self.assertRaises(EngineError):
            self.engine.check_release('authorized', 'main')

    def test_altered_latest_final_review_cannot_restore_older_approval(self):
        self.release_setup()
        self.record('old-clean', [], final=True)
        self.engine.release_permit('main', self.lease, 'authorized', 'main')
        for field in ['source', 'path']:
            for findings in [['new blocker'], []]:
                with self.subTest(field=field, findings=findings):
                    latest = self.record('latest-' + field, [], categories=['security'],
                                         findings=findings, final=True)
                    pathlib.Path(latest[field]).write_text('altered evidence')
                    for check in [lambda: self.engine.check_completion('main', self.lease),
                                  lambda: self.engine.check_release('authorized', 'main'),
                                  lambda: self.engine.release_permit('main', self.lease, 'authorized', 'main')]:
                        with self.assertRaises(EngineError):
                            check()
                    self.record('replacement-' + field, [], categories=['security'], final=True)
                    self.engine.check_release('authorized', 'main')

    def test_altered_latest_receipt_cannot_restore_older_approval(self):
        self.task()
        token = self.engine.dispatch('main', self.lease, 'a', 'worker')
        self.engine.report('worker', token, done('done'))
        self.record('old-clean', ['a'])
        latest = self.record('latest-blocked', ['a'], categories=['security'], findings=['unsafe'])
        pathlib.Path(latest['source']).unlink()
        with self.assertRaises(EngineError):
            self.engine.accept('main', self.lease, 'a')
        self.record('replacement', ['a'], categories=['security'])
        self.engine.accept('main', self.lease, 'a')

    def test_known_git_release_rejects_wrappers_and_context_redirection(self):
        other = self.root / 'other-repo'
        subprocess.check_call(['git', 'clone', '-q', str(self.repo), str(other)])
        push = ['git', 'push', 'authorized', 'HEAD:main']
        recipes = [
            ['env', '-C', str(other), *push],
            ['env', '--chdir', str(other), *push],
            ['env', 'GIT_DIR=' + str(other / '.git'), *push],
            ['env', 'GIT_WORK_TREE=' + str(other), *push],
            ['GIT_DIR=' + str(other / '.git'), *push],
            ['env', *push],
            ['sh', '-c', 'git push authorized HEAD:main'],
            ['git', '-c', 'core.worktree=' + str(other), *push[1:]],
            ['git', 'push', '--repo=' + str(other), 'authorized', 'HEAD:main'],
            ['git', 'push', '--repo', str(other), 'authorized', 'HEAD:main'],
        ]
        for recipe in recipes:
            with self.subTest(recipe=recipe):
                (self.root / 'release' / 'state.json').unlink(missing_ok=True)
                self.release_setup(recipe)
                self.record('final', [], final=True)
                with self.assertRaises(EngineError):
                    self.engine.release_permit('main', self.lease, 'authorized', 'main')
                self.engine.interrupt('main', self.lease)
                self.engine.state_path.unlink()

    def test_known_git_release_accepts_only_engine_git_executable(self):
        import shutil
        git = str(pathlib.Path(shutil.which('git')).resolve())
        remote = self.root / 'remote.git'
        subprocess.run(['git', 'init', '--bare', '-q', str(remote)], check=True, capture_output=True)
        self.git('remote', 'add', 'authorized', str(remote))
        alternate = self.root / 'alternate' / 'git'
        alternate.parent.mkdir()
        alternate.write_text('#!/bin/sh\nexit 0\n')
        alternate.chmod(0o755)
        for executable in ['git', git, str(alternate)]:
            with self.subTest(executable=executable):
                self.release_setup([executable, 'push', 'authorized', 'HEAD:main'])
                self.record('final', [], final=True)
                if executable == str(alternate):
                    with self.assertRaises(EngineError):
                        self.engine.release_permit('main', self.lease, 'authorized', 'main')
                else:
                    permit = self.engine.release_permit('main', self.lease, 'authorized', 'main')
                    self.assertEqual(permit, self.engine.check_release('authorized', 'main'))
                    subprocess.run(self.engine.policy['release']['argv'], cwd=self.repo, check=True, capture_output=True)
                    pushed = subprocess.check_output(['git', '--git-dir', str(remote), 'rev-parse', 'refs/heads/main'], text=True).strip()
                    self.assertEqual(self.git('rev-parse', 'HEAD'), pushed)
                self.engine.interrupt('main', self.lease)
                self.engine.state_path.unlink()

    def test_public_lease_validation(self):
        self.engine.validate_lease('main', self.lease)
        for actor, lease in [('worker', self.lease), ('main', 'stale')]:
            with self.assertRaises(EngineError):
                self.engine.validate_lease(actor, lease)
        self.engine.interrupt('main', self.lease)
        with self.assertRaises(EngineError):
            self.engine.validate_lease('main', self.lease)


class HarnessSessionTests(EngineFixture):
    """B-F5: harness-session binding, release on session end, rebind. The clock is injected."""

    def setUp(self):
        super().setUp()
        self.now = [1000.0]
        self.engine.interrupt('main', self.lease)
        self.engine = Engine(self.root / 'state', self.repo, clock=lambda: self.now[0])
        self.rebound()

    def rebound(self):
        """A fresh active run bound to harness session S."""
        self.now[0] = 1000.0
        if self.engine.status()['session']['active']:
            self.engine.interrupt('main', self.raw_lease())
        self.lease = self.engine.open_session('main', harness_session='S')

    def session(self):
        return self.engine.status()['session']

    def raw_lease(self):
        return json.loads(self.engine.state_path.read_text())['session']['lease']

    def test_interrupt_active_needs_no_lease_and_is_idempotent(self):
        self.assertTrue(self.engine.interrupt_active())
        self.assertFalse(self.session()['active'])
        self.assertFalse(self.engine.interrupt_active())
        with self.assertRaisesRegex(EngineError, 'lease'):
            self.engine.validate_lease('main', self.lease)

    def test_interrupt_active_clears_permits_and_autonomy(self):
        state = json.loads(self.engine.state_path.read_text())
        state['permits'] = [dict(id='p', action='release', remote='r', target='t', argv=[], artifact={}, lease=self.lease)]
        self.engine.state_path.write_text(json.dumps(state))
        self.engine.interrupt_active()
        state = self.engine.status()
        self.assertEqual((state['permits'], state['autonomy']), ([], None))
        self.assertEqual(json.loads(self.engine.state_path.read_text())['permits'], [])

    def test_end_writes_wait_for_a_lock_held_past_lock_wait(self):
        """Interrupt and SessionEnd records survive a busy lock: they wait instead of raising StateBusy."""
        from orchestra_core import portable as fcntl
        import threading
        for method, args, reason in [('interrupt_active', (), 'interrupted'), ('end_harness_session', ('S',), 'ended')]:
            with self.subTest(method=method):
                self.rebound()
                hook_engine = Engine(self.root / 'state', self.repo, clock=lambda: self.now[0], lock_wait=0.2)
                handle = (self.root / 'state' / 'state.lock').open('a+')
                self.addCleanup(handle.close)
                fcntl.flock(handle, fcntl.LOCK_EX)
                timer = threading.Timer(0.8, fcntl.flock, [handle, fcntl.LOCK_UN])
                timer.start()
                self.addCleanup(timer.cancel)
                self.assertTrue(getattr(hook_engine, method)(*args))
                self.assertFalse(self.session()['active'])
                self.assertEqual(self.engine.status()['last_brief']['reason'], reason)

    def test_interrupt_active_on_inactive_run_leaves_state_unwritten(self):
        self.engine.interrupt_active()
        before = self.stat()
        self.assertFalse(self.engine.interrupt_active())
        self.assertEqual(before, self.stat())

    def test_interrupt_active_with_no_state_file_does_not_create_one(self):
        engine = Engine(self.root / 'fresh', self.repo)
        self.assertFalse(engine.interrupt_active())
        self.assertFalse(engine.state_path.exists())

    def stat(self):
        info = self.engine.state_path.stat()
        return (info.st_ino, info.st_mtime_ns)

    def test_no_op_session_end_and_rebind_do_not_rewrite_state(self):
        before = self.stat()
        self.assertFalse(self.engine.end_harness_session('other'))
        self.assertFalse(self.engine.mark_harness_rebind('other'))
        self.assertEqual(before, self.stat())
        self.engine.interrupt_active()
        before = self.stat()
        self.assertFalse(self.engine.end_harness_session('S'))
        self.assertFalse(self.engine.mark_harness_rebind('S'))
        self.assertEqual(before, self.stat())
        self.engine.open_session('main')  # unbound run
        before = self.stat()
        self.assertFalse(self.engine.end_harness_session('S'))
        self.assertFalse(self.engine.mark_harness_rebind('S'))
        self.assertEqual(before, self.stat())

    def test_matching_session_end_still_writes(self):
        before = self.stat()
        self.assertTrue(self.engine.end_harness_session('S'))
        self.assertNotEqual(before, self.stat())

    def test_open_session_records_harness_session_and_keeps_it_optional(self):
        self.assertEqual(self.session()['harness_session'], 'S')
        self.engine.interrupt('main', self.lease)
        self.engine.open_session('main')
        self.assertNotIn('harness_session', self.session())
        self.engine.interrupt('main', self.raw_lease())
        for bad in ('', 5, True):
            with self.assertRaises(EngineError):
                self.engine.open_session('main', harness_session=bad)

    def test_end_harness_session_does_what_interrupt_does_and_is_idempotent(self):
        self.assertTrue(self.engine.end_harness_session('S'))
        session = self.session()
        self.assertFalse(session['active'])
        self.assertEqual(session['outcome'], 'ended')
        self.assertEqual(session['harness_session'], 'S')
        state = self.engine.status()
        self.assertEqual((state['permits'], state['autonomy']), ([], None))
        self.assertFalse(self.engine.end_harness_session('S'))
        self.assertFalse(self.session()['active'])

    def test_end_harness_session_ignores_other_ids_and_unbound_runs(self):
        self.assertFalse(self.engine.end_harness_session('other'))
        self.assertTrue(self.session()['active'])
        self.engine.interrupt('main', self.lease)
        self.engine.open_session('main')
        self.assertFalse(self.engine.end_harness_session('S'))
        self.assertTrue(self.session()['active'])

    def test_mark_rebind_records_only_for_the_bound_id(self):
        self.assertFalse(self.engine.mark_harness_rebind('other'))
        self.assertNotIn('pending_rebind', self.session())
        self.assertTrue(self.engine.mark_harness_rebind('S'))
        self.assertEqual(self.session()['pending_rebind'], {'from': 'S', 'at': 1000.0})
        self.assertTrue(self.session()['active'])

    def test_apply_rebind_binds_once_inside_the_window(self):
        self.engine.mark_harness_rebind('S')
        self.now[0] = 1000.5
        self.assertTrue(self.engine.apply_harness_rebind('S2'))
        self.assertEqual(self.session()['harness_session'], 'S2')
        self.assertNotIn('pending_rebind', self.session())
        self.assertFalse(self.engine.apply_harness_rebind('S3'))
        self.assertEqual(self.session()['harness_session'], 'S2')

    def test_apply_rebind_window_edges_and_stale_entries(self):
        for offset, applied in [(0, True), (60, True), (60.5, False), (-1, False)]:
            with self.subTest(offset=offset):
                self.rebound()
                self.engine.mark_harness_rebind('S')
                self.now[0] = 1000.0 + offset
                self.assertEqual(self.engine.apply_harness_rebind('S2'), applied)
                self.assertNotIn('pending_rebind', self.session())
                self.assertEqual(self.session()['harness_session'], 'S2' if applied else 'S')

    def test_apply_rebind_without_pending_changes_nothing(self):
        before = self.engine.state_path.read_bytes()
        self.assertFalse(self.engine.apply_harness_rebind('S2'))
        self.assertEqual(self.engine.state_path.read_bytes(), before)

    def test_release_removes_pending_rebind_and_keeps_harness_session(self):
        self.engine.mark_harness_rebind('S')
        self.assertTrue(self.engine.end_harness_session('S'))
        self.assertNotIn('pending_rebind', self.session())
        self.assertEqual(self.session()['harness_session'], 'S')

    def test_malformed_harness_fields_are_rejected(self):
        state = json.loads(self.engine.state_path.read_text())
        for patch in [{'harness_session': 3}, {'harness_session': ''}, {'pending_rebind': 'x'},
                      {'pending_rebind': {'from': 'S', 'at': 'now'}}, {'pending_rebind': {'from': 'S', 'at': True}}]:
            with self.subTest(patch=patch):
                bad = json.loads(json.dumps(state))
                bad['session'].update(patch)
                self.engine.state_path.write_text(json.dumps(bad))
                with self.assertRaises(EngineError):
                    self.engine.status()



class ScopedEvidenceTests(EngineFixture):
    def setUp(self):
        super().setUp()
        for name in ('b', 'c'):
            (self.repo / name).write_text('initial')
        self.git('add', 'b', 'c')
        self.git('commit', '-qm', 'more')
        self.engine = Engine(self.root / 'state2', self.repo)
        self.lease = self.engine.open_session('main')
        self.allow_review()

    def reported(self, name='a', **kw):
        if 'role' not in kw:  # a builder needs no independent review; a card that asks for one does
            kw.update(role='investigator', mode='code', review_required=True)
        self.task(name, **kw)
        self.engine.report('w' + name, self.engine.dispatch('main', self.lease, name, 'w' + name), done('checked'))

    def checkpoint(self, name='a', findings=None):
        report = self.root / (name + '-review.json')
        self.review(report, tasks=[name], findings=findings)
        return self.engine.record_review('main', self.lease, 'reviewer', report, ['correctness'], [name], findings=findings)

    def test_scoped_artifact_binds_scope_and_ignores_outside_edits(self):
        base = self.engine.artifact(['a'])
        self.assertEqual(['a'], base['scope'])
        self.assertNotIn('scope', self.engine.artifact())
        (self.repo / 'b').write_text('sibling edit')
        (self.repo / 'new-untracked').write_text('x')
        self.assertEqual(base, self.engine.artifact(['a']))
        self.assertNotEqual(self.engine.artifact(), self.engine.artifact(['a']))
        (self.repo / 'a').write_text('inside edit')
        self.assertNotEqual(base, self.engine.artifact(['a']))

    def test_scoped_artifact_directory_scope_covers_children(self):
        (self.repo / 'd').mkdir()
        (self.repo / 'd' / 'f').write_text('1')
        base = self.engine.artifact(['d'])
        (self.repo / 'd' / 'f').write_text('2')
        self.assertNotEqual(base, self.engine.artifact(['d']))

    def test_edit_outside_scope_keeps_scoped_verdict_current(self):
        self.reported('a')
        self.checkpoint('a')
        (self.repo / 'b').write_text('sibling uncommitted edit')
        self.engine.accept('main', self.lease, 'a')
        self.assertEqual('accepted', self.engine.status()['tasks']['a']['state'])

    def test_edit_inside_scope_stales_scoped_verdict(self):
        self.reported('a')
        self.checkpoint('a')
        (self.repo / 'a').write_text('edited after review')
        with self.assertRaisesRegex(EngineError, 'independent review'):
            self.engine.accept('main', self.lease, 'a')

    def test_new_commit_stales_scoped_verdict(self):
        self.reported('a')
        self.checkpoint('a')
        (self.repo / 'b').write_text('committed elsewhere')
        self.git('commit', '-qam', 'elsewhere')
        with self.assertRaisesRegex(EngineError, 'independent review'):
            self.engine.accept('main', self.lease, 'a')

    def test_scoped_report_artifact_survives_outside_edit_and_stales_inside(self):
        self.reported('r', role='investigator', mode='code', files=['b'])
        self.assertEqual(['b'], self.engine.status()['tasks']['r']['report_artifact']['scope'])
        (self.repo / 'a').write_text('outside edit')
        self.engine.accept('main', self.lease, 'r')
        self.reported('s', role='investigator', mode='code', files=['c'])
        (self.repo / 'c').write_text('inside edit')
        with self.assertRaisesRegex(EngineError, 'stale'):
            self.engine.accept('main', self.lease, 's')

    def test_review_receipt_stores_scope_union_of_covered_tasks(self):
        self.reported('a')
        self.reported('b')
        report = self.root / 'union.json'
        self.review(report, tasks=['a', 'b'])
        receipt = self.engine.record_review('main', self.lease, 'reviewer', report, ['correctness'], ['a', 'b'])
        self.assertEqual(['a', 'b'], receipt['scope'])
        self.assertEqual(['a', 'b'], receipt['artifact']['scope'])

    def test_review_with_wrong_scope_is_rejected(self):
        self.reported('a')
        report = self.root / 'whole.json'
        self.review(report, tasks=['a'], final=True)  # whole-repo artifact
        report.write_text(json.dumps({**json.loads(report.read_text()), 'final': False}))
        with self.assertRaisesRegex(EngineError, 'does not match'):
            self.engine.record_review('main', self.lease, 'reviewer', report, ['correctness'], ['a'])

    def test_repair_chain_files_join_the_scope(self):
        self.reported('a', role='builder', mode='implementation')
        self.checkpoint('a', findings=['bug'])
        self.task('fix', mode='repair', repair_of='a', files=['c'])
        self.assertEqual(['a', 'c'], self.engine.scope_for(['fix']))

    def test_stale_newer_blocked_receipt_does_not_restore_older_clean(self):
        self.reported('a')
        self.reported('b')
        self.checkpoint('a')
        report = self.root / 'wide.json'
        self.review(report, tasks=['a', 'b'], findings=['bug in a'])
        self.engine.record_review('main', self.lease, 'reviewer', report, ['correctness'], ['a', 'b'], findings=['bug in a'])
        with self.assertRaisesRegex(EngineError, 'findings'):
            self.engine.accept('main', self.lease, 'a')
        (self.repo / 'b').write_text('edit inside the newer scope only')
        with self.assertRaises(EngineError):
            self.engine.accept('main', self.lease, 'a')
        self.assertEqual('reported', self.engine.status()['tasks']['a']['state'])

    def test_stale_final_blocked_receipt_does_not_restore_scoped_clean(self):
        self.reported('a')
        self.checkpoint('a')
        report = self.root / 'final-blocked.json'
        ids = sorted(self.engine.status()['tasks'])
        self.review(report, reviewer='final-reviewer', tasks=ids, findings=['bug in a'], final=True,
                    task_findings={'a': ['bug in a'], 'critic-reviewer': []})
        receipt = self.engine.record_review('main', self.lease, 'final-reviewer', report, ['correctness'], ids, final=True, findings=['bug in a'])
        self.assertIsNone(receipt['scope'])
        with self.assertRaisesRegex(EngineError, 'findings'):
            self.engine.accept('main', self.lease, 'a')
        (self.repo / 'b').write_text('edit outside the checkpoint scope')
        with self.assertRaises(EngineError):
            self.engine.accept('main', self.lease, 'a')
        self.assertEqual('reported', self.engine.status()['tasks']['a']['state'])

    def receipt(self, name, tasks, categories, findings=None):
        report = self.root / (name + '.json')
        self.review(report, tasks=tasks, categories=categories, findings=findings)
        return self.engine.record_review('main', self.lease, 'reviewer', report, categories, tasks, findings=findings)

    def test_cross_category_stale_blocked(self):
        # O22: a stale non-CLEAN newest receipt voids every category for the tasks it covers.
        self.reported('a')
        self.reported('b')
        self.receipt('r1', ['a'], ['correctness', 'security'])
        self.receipt('r2', ['a', 'b'], ['correctness'], findings=['bug in a'])
        with self.assertRaisesRegex(EngineError, 'findings'):
            self.engine.accept('main', self.lease, 'a')
        (self.repo / 'b').write_text('edit inside the blocking scope only')
        with self.assertRaisesRegex(EngineError, 'needs current independent review'):
            self.engine.accept('main', self.lease, 'a')
        self.assertEqual('reported', self.engine.status()['tasks']['a']['state'])

    def test_disjoint_category_stale_blocked(self):
        self.reported('a')
        self.reported('b')
        self.receipt('r1', ['a'], ['security'])
        self.receipt('r2', ['a', 'b'], ['correctness'], findings=['bug in a'])
        (self.repo / 'b').write_text('edit inside the blocking scope only')
        with self.assertRaisesRegex(EngineError, 'needs current independent review'):
            self.engine.accept('main', self.lease, 'a')
        self.assertEqual('reported', self.engine.status()['tasks']['a']['state'])

    def test_stale_clean_newest_only_removes_its_own_category(self):
        self.reported('a')
        self.reported('b')
        self.receipt('r1', ['a'], ['security'])
        self.receipt('r2', ['a', 'b'], ['correctness'])
        (self.repo / 'b').write_text('edit inside the clean wide scope only')
        self.engine.accept('main', self.lease, 'a')
        self.assertEqual('accepted', self.engine.status()['tasks']['a']['state'])

    def test_newer_receipt_lifts_stale_blocked_void(self):
        self.reported('a')
        self.reported('b')
        self.receipt('r1', ['a'], ['security'])
        self.receipt('r2', ['a', 'b'], ['correctness'], findings=['bug in a'])
        (self.repo / 'b').write_text('edit inside the blocking scope only')
        self.receipt('r3', ['a', 'b'], ['correctness'])
        self.engine.accept('main', self.lease, 'a')
        self.assertEqual('accepted', self.engine.status()['tasks']['a']['state'])

    def test_review_covering_a_no_file_task_uses_whole_repo_artifact(self):
        self.reported('a')
        self.reported('n', files=[])
        self.assertIsNone(self.engine.scope_for(['a', 'n']))
        report = self.root / 'mixed.json'
        self.review(report, tasks=['a', 'n'])
        receipt = self.engine.record_review('main', self.lease, 'reviewer', report, ['correctness'], ['a', 'n'])
        self.assertIsNone(receipt['scope'])
        self.assertNotIn('scope', receipt['artifact'])
        (self.repo / 'b').write_text('edit outside [a]')
        with self.assertRaisesRegex(EngineError, 'independent review'):
            self.engine.accept('main', self.lease, 'n')
        with self.assertRaisesRegex(EngineError, 'independent review'):
            self.engine.accept('main', self.lease, 'a')

    def test_task_without_reserved_files_gets_whole_repo_artifact(self):
        self.reported('n', role='investigator', mode='code', files=[])
        self.assertIsNone(self.engine.scope_for(['n']))
        task = self.engine.status()['tasks']['n']
        self.assertNotIn('scope', task['report_artifact'])
        self.assertEqual(self.engine.artifact(), task['report_artifact'])
        (self.repo / 'b').write_text('any edit')
        with self.assertRaisesRegex(EngineError, 'stale'):
            self.engine.accept('main', self.lease, 'n')

    def test_final_review_still_binds_whole_repo(self):
        self.reported('a')
        self.checkpoint('a')
        self.engine.accept('main', self.lease, 'a')
        cats = ['requirements', 'correctness', 'security', 'tests', 'architecture', 'standards', 'cleanup']
        report = self.root / 'final.json'
        ids = sorted(self.engine.status()['tasks'])
        self.review(report, reviewer='final-reviewer', categories=cats, tasks=ids, final=True)
        receipt = self.engine.record_review('main', self.lease, 'final-reviewer', report, cats, ids, final=True)
        self.assertNotIn('scope', receipt['artifact'])
        self.assertIsNone(receipt.get('scope'))
        (self.repo / 'b').write_text('outside edit stales final evidence')
        with self.assertRaises(EngineError):
            self.engine.check_completion('main', self.lease)


T0 = 1_800_000_000.0  # 2027-01-15T08:00:00Z; the injected clock never sleeps
PASS_ARGV = [sys.executable, '-c', 'print("ok")']


def iso(ts):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


ALL_CATEGORIES = ['requirements', 'correctness', 'security', 'tests', 'architecture', 'standards', 'cleanup']


class AutonomyFixture(EngineFixture):
    """Engine on an injected clock; nothing sleeps."""

    def setUp(self):
        super().setUp()
        self.now = [T0]
        self.state = self.root / 'state'
        self.engine = Engine(self.state, self.repo, clock=lambda: self.now[0])

    def fresh(self, policy):
        shutil.rmtree(self.state)
        self.engine = Engine(self.state, self.repo, policy, clock=lambda: self.now[0])
        self.lease = self.engine.open_session('main')

    def ledger(self, goal='ship the fixture', passes=None, stalls=None, deadline=None, checks=None, boundaries=None, extra=''):
        checks = ['fixture: ' + shlex.join(PASS_ARGV)] if checks is None else checks
        caps = [line for line in ('max_passes: ' + passes if passes is not None else None,
                                  'max_stalls: ' + stalls if stalls is not None else None) if line]
        text = ['# Autonomy ledger', '', 'goal: ' + goal, *caps,
                'deadline: ' + (deadline or iso(T0 + 3600)), '', '## Completion checks', '', *checks, '',
                '## Approval boundaries', '', *(AUTONOMY_FIXED if boundaries is None else boundaries), extra]
        (self.state / 'autonomy.md').write_text('\n'.join(text) + '\n')

    def arm(self, **kw):
        self.ledger(**kw)
        return self.engine.arm_autonomy()

    def auto(self):
        return self.engine.status()['autonomy']

    def accept_card(self, name):
        self.task(name, role='investigator', mode='code')
        token = self.engine.dispatch('main', self.lease, name, 'w-' + name)
        self.engine.report('w-' + name, token, 'Inspected ' + name + '.')
        self.engine.accept('main', self.lease, name)

    def final_review(self):
        """An all-category final review of every card, on the current artifact (SPEC 5.8 item 3)."""
        ids = sorted(self.engine.status()['tasks'])
        path = self.root / ('final-%d.json' % len(ids))
        self.review(path, reviewer='reviewer', tasks=ids, categories=ALL_CATEGORIES, final=True)
        self.engine.record_review('main', self.lease, 'reviewer', path, ALL_CATEGORIES, ids, final=True)

    def stops(self, n):
        """n Stops, each preceded by a newly accepted card so the loop never stalls."""
        for i in range(n):
            self.accept_card('prog-%d-%d' % (len(self.engine.status()['tasks']), i))
            self.assertIsInstance(self.engine.hook_stop(), str)


class AutonomyArmTests(AutonomyFixture):
    def test_arm_refuses_without_an_active_run(self):
        fresh = Engine(self.root / 'other-state', self.repo)
        with self.assertRaisesRegex(EngineError, 'run'):
            fresh.arm_autonomy()
        self.assertFalse((self.root / 'other-state' / 'state.json').exists())
        self.engine.interrupt('main', self.lease)
        self.ledger()
        with self.assertRaisesRegex(EngineError, 'run'):
            self.engine.arm_autonomy()

    def test_missing_ledger_writes_the_template_and_refuses(self):
        with self.assertRaisesRegex(EngineError, 'fill the ledger, then arm again') as raised:
            self.engine.arm_autonomy()
        self.assertIn(str(self.state / 'autonomy.md'), str(raised.exception))
        text = (self.state / 'autonomy.md').read_text()
        for line in AUTONOMY_FIXED:
            self.assertIn(line, text)
        self.assertIsNone(self.auto())
        with self.assertRaisesRegex(EngineError, 'goal'):  # the template's own placeholders refuse
            self.engine.arm_autonomy()

    def test_placeholder_or_bad_field_refuses_and_names_the_field(self):
        cases = [(dict(goal='<one line goal>'), 'goal'), (dict(passes='<integer>'), 'max_passes'),
                 (dict(passes='0'), 'max_passes'), (dict(passes='21'), 'max_passes'), (dict(passes='two'), 'max_passes'),
                 (dict(stalls='3'), 'max_stalls'), (dict(stalls='0'), 'max_stalls'),
                 (dict(deadline='<ISO 8601 with UTC offset>'), 'deadline'), (dict(deadline='tomorrow'), 'deadline'),
                 (dict(deadline='2027-01-16T00:00:00'), 'deadline'),  # no UTC offset
                 (dict(deadline=iso(T0 - 1)), 'deadline'), (dict(deadline=iso(T0)), 'deadline'),
                 (dict(checks=[]), 'Completion checks'), (dict(checks=['<NAME: argv...>']), 'Completion checks'),
                 (dict(checks=['no colon here']), 'Completion checks'),
                 (dict(checks=['a: true', 'a: true']), 'Completion checks')]
        for kw, field in cases:
            with self.subTest(kw=kw):
                self.ledger(**kw)
                with self.assertRaisesRegex(EngineError, field):
                    self.engine.arm_autonomy()
                self.assertIsNone(self.auto())

    def test_missing_field_refuses(self):
        self.ledger()
        path = self.state / 'autonomy.md'
        path.write_text(path.read_text().replace('goal: ship the fixture\n', ''))
        with self.assertRaisesRegex(EngineError, 'goal'):
            self.engine.arm_autonomy()

    def test_each_fixed_boundary_line_is_required_and_added_lines_are_fine(self):
        for line in AUTONOMY_FIXED:
            with self.subTest(line=line):
                self.ledger(boundaries=[l for l in AUTONOMY_FIXED if l != line])
                with self.assertRaisesRegex(EngineError, 'Approval boundaries'):
                    self.engine.arm_autonomy()
        self.ledger(extra='- Never touch the billing module.')
        self.assertTrue(self.engine.arm_autonomy()['active'])

    def test_arm_snapshots_stores_fields_and_prints_preconditions(self):
        receipt = self.arm(passes='5', stalls='1')
        self.assertTrue(receipt['active'])
        auto = self.auto()
        self.assertEqual((auto['active'], auto['passes'], auto['stalls'], auto['max_passes'], auto['max_stalls']),
                         (True, 0, 0, 5, 1))
        self.assertEqual(auto['goal'], 'ship the fixture')
        self.assertEqual(auto['deadline'], iso(T0 + 3600))
        self.assertEqual(auto['checks'], [dict(name='fixture', argv=PASS_ARGV)])
        self.assertTrue(Path(auto['ledger']['path']).is_file())
        self.assertIn('permission_mode', receipt['preconditions'])
        self.assertIn('keep-awake', receipt['preconditions']['keep_awake'])

    def test_arm_again_resets_counters_and_clears_the_old_report(self):
        self.arm(deadline=iso(T0 + 60))
        self.task('left-queued')
        self.accept_card('c')
        self.engine.hook_stop()
        self.now[0] = T0 + 61
        self.assertIsNone(self.engine.hook_stop())  # the deadline ends the run; the queued card does not
        self.assertEqual(self.auto()['last_stop_reason'], 'deadline')
        self.assertIsNotNone(self.engine.autonomy_report())
        self.arm()
        self.assertIsNone(self.engine.autonomy_report())
        self.assertEqual((self.auto()['passes'], self.auto()['active']), (0, True))

    def test_status_has_the_documented_keys_and_never_the_lease(self):
        idle = self.engine.autonomy_status()
        self.assertRegex(idle.pop('signature'), r'^[0-9a-f]{64}$')
        self.assertEqual(idle, dict(active=False, passes=None, max_passes=None, stalls=None,
                         max_stalls=None, deadline=None, parked=[], last_stop_reason=None))
        self.arm(passes='4')
        self.task('p')
        self.engine.park('main', self.lease, 'p', 'needs a push')
        status = self.engine.autonomy_status()
        self.assertEqual(set(status), {'active', 'passes', 'max_passes', 'stalls', 'max_stalls', 'deadline', 'parked',
                                       'last_stop_reason', 'signature'})
        self.assertEqual((status['active'], status['max_passes'], status['parked']), (True, 4, [{'id': 'p', 'reason': 'needs a push'}]))
        self.assertNotIn(self.lease, json.dumps(status))

    def test_template_carries_the_fields_and_the_fixed_lines(self):
        template = (Path(__file__).resolve().parents[1] / 'plugins/orchestra/config/autonomy-template.md').read_text()
        for line in AUTONOMY_FIXED:
            self.assertIn(line, template)
        for field in ('goal:', 'deadline:', '## Completion checks', '## Approval boundaries'):
            self.assertIn(field, template)
        self.assertNotIn('max_passes', template)
        self.assertNotIn('max_stalls', template)
        self.assertIn('The Release line overrides Push and Engine-gated actions for that remote and target only.', template)
        self.assertEqual(len(AUTONOMY_FIXED), 6)


class AutonomyLoopTests(AutonomyFixture):
    def test_stop_continues_inside_the_bounds_and_counts_passes(self):
        self.arm(passes='3')
        self.task('x')
        reason = self.engine.hook_stop()
        self.assertIn('Autonomy pass 1', reason)
        self.assertNotIn('of 3', reason)
        self.assertIn('park any card that reaches an approval boundary', reason)
        self.assertEqual(self.auto()['passes'], 1)

    def test_unarmed_and_inactive_stop_is_silent_and_writes_nothing(self):
        self.task('x')
        before = self.engine.state_path.read_bytes()
        self.assertIsNone(self.engine.hook_stop())
        self.assertEqual(before, self.engine.state_path.read_bytes())

    def test_a_newly_accepted_card_resets_the_stall_count(self):
        self.arm(passes='9', stalls='2')
        self.task('x')
        self.engine.hook_stop()
        self.engine.hook_stop()  # stalls 1
        self.assertEqual(self.auto()['stalls'], 1)
        self.accept_card('z')
        self.assertIsNotNone(self.engine.hook_stop())
        self.assertEqual((self.auto()['stalls'], self.auto()['active']), (0, True))

    def test_deadline_stops(self):
        self.arm(deadline=iso(T0 + 60))
        self.task('x')
        self.assertIsNotNone(self.engine.hook_stop())
        self.now[0] = T0 + 60.5
        self.assertIsNone(self.engine.hook_stop())
        self.assertEqual(self.auto()['last_stop_reason'], 'deadline')

    def test_completion_stops_only_with_a_passed_intact_gate_on_the_current_artifact(self):
        def not_complete():  # nothing is live, so the run stops, but not as complete; arm again for the next step
            self.assertIsNone(self.engine.hook_stop())
            self.assertEqual(self.auto()['last_stop_reason'], 'no-ready-card')
            self.engine.arm_autonomy()

        self.arm(passes='9')
        self.accept_card('x')  # SPEC 5.8 item 3: every card accepted and a final review, so only the gate decides
        self.final_review()
        not_complete()  # no gate receipt yet
        other = self.engine.run_gate('main', self.lease, 'fixture', [sys.executable, '-c', 'print("different")'])
        self.assertTrue(other['passed'])
        not_complete()  # same name, different argv
        self.engine.run_gate('main', self.lease, 'unrelated', PASS_ARGV)
        not_complete()  # same argv, different name
        self.assertTrue(self.engine.run_gate('main', self.lease, 'fixture', PASS_ARGV)['passed'])
        (self.repo / 'a').write_text('edited after the gate')
        self.final_review()
        not_complete()  # stale: the artifact moved on
        self.assertTrue(self.engine.run_gate('main', self.lease, 'fixture', PASS_ARGV)['passed'])
        self.assertIsNone(self.engine.hook_stop())
        self.assertEqual(self.auto()['last_stop_reason'], 'complete')

    def test_a_tampered_gate_log_is_not_completion(self):
        self.arm(passes='9')
        self.task('x')
        receipt = self.engine.run_gate('main', self.lease, 'fixture', PASS_ARGV)
        Path(receipt['path']).write_text('forged')
        self.assertIsNotNone(self.engine.hook_stop())

    def test_a_failed_gate_is_not_completion(self):
        self.arm(passes='9', checks=['fixture: ' + shlex.join([sys.executable, '-c', 'raise SystemExit(3)'])])
        self.task('x')
        receipt = self.engine.run_gate('main', self.lease, 'fixture', [sys.executable, '-c', 'raise SystemExit(3)'])
        self.assertFalse(receipt['passed'])
        self.assertIsNotNone(self.engine.hook_stop())

    def test_parked_only_stops(self):
        self.arm(passes='9')
        self.accept_card('done')
        self.task('p')
        self.engine.park('main', self.lease, 'p', 'needs a push')
        self.assertIsNone(self.engine.hook_stop())
        self.assertEqual(self.auto()['last_stop_reason'], 'parked-only')

    def test_a_card_blocked_behind_a_parked_dependency_is_parked_only(self):
        self.arm(passes='9')
        self.task('p')
        self.task('dep', dependencies=['p'])
        self.engine.park('main', self.lease, 'p', 'boundary')
        self.assertIsNone(self.engine.hook_stop())
        self.assertEqual(self.auto()['last_stop_reason'], 'parked-only')

    def test_no_ready_card_stops(self):
        self.arm(passes='9')
        self.accept_card('done')
        self.assertIsNone(self.engine.hook_stop())
        self.assertEqual(self.auto()['last_stop_reason'], 'no-ready-card')

    def test_running_and_reported_cards_keep_the_loop_going(self):
        self.arm(passes='9')
        self.task('x')
        token = self.engine.dispatch('main', self.lease, 'x', 'w')
        self.assertIsNotNone(self.engine.hook_stop())
        self.engine.report('w', token, done('Inspected x.'))
        self.assertIsNotNone(self.engine.hook_stop())

    def test_tampered_ledger_stops(self):
        self.arm(passes='9')
        self.task('x')
        self.assertIsNotNone(self.engine.hook_stop())
        with (self.state / 'autonomy.md').open('a') as out:
            out.write('- Quietly allow pushes.\n')
        self.assertIsNone(self.engine.hook_stop())
        self.assertEqual((self.auto()['last_stop_reason'], self.auto()['active']), ('ledger-tampered', False))

    def test_a_deleted_snapshot_stops_as_tampered(self):
        self.arm(passes='9')
        self.task('x')
        Path(self.auto()['ledger']['path']).unlink()
        self.assertIsNone(self.engine.hook_stop())
        self.assertEqual(self.auto()['last_stop_reason'], 'ledger-tampered')


class AutonomyParkTests(AutonomyFixture):
    def test_park_drops_assignment_reservation_and_capacity(self):
        self.task('a1', files=['shared'])
        self.task('a2', files=['shared'])
        self.task('dep', dependencies=['a1'])
        token = self.engine.dispatch('main', self.lease, 'a1', 'w1')
        self.assertEqual(self.engine.ready('main', self.lease), [])  # a2 collides with the running a1
        self.engine.park('main', self.lease, 'a1', 'needs a push')
        card = self.engine.status()['tasks']['a1']
        self.assertEqual((card['state'], card['parked_reason']), ('parked', 'needs a push'))
        for key in ('assignment', 'worker', 'inline', 'report'):
            self.assertNotIn(key, card)
        self.assertEqual(self.engine.ready('main', self.lease), ['a2'])  # reservation released, dep still blocked
        with self.assertRaises(EngineError):
            self.engine.report('w1', token, done('late report'))
        self.engine.dispatch('main', self.lease, 'a2', 'w1')  # the worker name is free again

    def test_park_a_reported_card_and_unpark_returns_it_to_the_queue(self):
        self.task('a')
        token = self.engine.dispatch('main', self.lease, 'a', 'w')
        self.engine.report('w', token, done('Inspected a.'))
        self.engine.park('main', self.lease, 'a', 'boundary')
        self.assertNotIn('report', self.engine.status()['tasks']['a'])
        self.engine.unpark('main', self.lease, 'a')
        card = self.engine.status()['tasks']['a']
        self.assertEqual(card['state'], 'queued')
        self.assertNotIn('parked_reason', card)
        self.assertEqual(self.engine.ready('main', self.lease), ['a'])

    def test_park_and_unpark_validate(self):
        self.task('a')
        self.accept_card('done')
        for args in [('done', 'why'), ('nope', 'why'), ('a', ''), ('a', '   ')]:
            with self.subTest(args=args), self.assertRaises(EngineError):
                self.engine.park('main', self.lease, *args)
        with self.assertRaises(EngineError):
            self.engine.park('main', 'wrong-lease', 'a', 'why')
        with self.assertRaises(EngineError):
            self.engine.unpark('main', self.lease, 'a')  # not parked
        self.engine.park('main', self.lease, 'a', 'why')
        with self.assertRaises(EngineError):
            self.engine.park('main', self.lease, 'a', 'again')
        with self.assertRaises(EngineError):
            self.engine.unpark('main', 'wrong-lease', 'a')

    def test_a_card_under_repair_cannot_be_parked(self):
        self.task('a')
        token = self.engine.dispatch('main', self.lease, 'a', 'w')
        self.engine.report('w', token, done('Implemented a.'))
        self.allow_review()
        report = self.root / 'r.json'
        self.review(report, tasks=['a'], findings=['bug'])
        self.engine.record_review('main', self.lease, 'reviewer', report, ['correctness'], ['a'], findings=['bug'])
        self.task('fix', mode='repair', files=['fix'], repair_of='a')
        with self.assertRaises(EngineError):
            self.engine.park('main', self.lease, 'a', 'why')

    def repaired(self):
        """A reported card whose repair card `repair-of-a` has reported too: `a` is reported with `repaired_by`."""
        self.task('a')
        token = self.engine.dispatch('main', self.lease, 'a', 'w')
        self.engine.report('w', token, done('Implemented a.'))
        self.allow_review()
        report = self.root / 'r.json'
        self.review(report, tasks=['a'], findings=['bug'])
        self.engine.record_review('main', self.lease, 'reviewer', report, ['correctness'], ['a'], findings=['bug'])
        self.task('repair-of-a', mode='repair', files=['fix'], repair_of='a')
        token = self.engine.dispatch('main', self.lease, 'repair-of-a', 'w2')
        self.engine.report('w2', token, done('Repaired a.'))
        self.assertEqual(self.engine.status()['tasks']['a']['state'], 'reported')

    def test_o30_parking_a_reported_card_under_repair_names_its_open_repair(self):
        self.repaired()
        with self.assertRaisesRegex(EngineError, 'repair-of-a'):
            self.engine.park('main', self.lease, 'a', 'why')
        self.assertEqual(self.engine.status()['tasks']['a']['state'], 'reported')

    def test_o30_a_card_whose_open_repair_is_parked_stops_parked_only(self):
        self.arm(passes='9')
        self.repaired()
        self.engine.park('main', self.lease, 'repair-of-a', 'needs a push')
        self.assertIsNone(self.engine.hook_stop())
        self.assertEqual(self.auto()['last_stop_reason'], 'parked-only')

    def test_unparking_a_parked_reported_repair_card_resumes_the_chain(self):
        self.repaired()
        self.engine.park('main', self.lease, 'repair-of-a', 'needs a push')
        self.assertEqual(self.engine.status()['tasks']['a']['state'], 'repairing')
        self.engine.unpark('main', self.lease, 'repair-of-a')
        self.assertEqual(self.engine.ready('main', self.lease), ['repair-of-a'])
        token = self.engine.dispatch('main', self.lease, 'repair-of-a', 'w3')
        self.engine.report('w3', token, done('Repaired a again.'))
        report = self.root / 'clean.json'
        self.review(report, tasks=['a', 'repair-of-a'])
        self.engine.record_review('main', self.lease, 'reviewer', report, ['correctness'], ['a', 'repair-of-a'])
        self.engine.accept('main', self.lease, 'repair-of-a')
        self.engine.accept('main', self.lease, 'a')
        self.assertEqual(self.engine.status()['tasks']['a']['state'], 'accepted')

    def test_parked_cards_block_finish(self):
        self.task('a', role='investigator', mode='code')
        self.engine.park('main', self.lease, 'a', 'why')
        with self.assertRaisesRegex(EngineError, 'accepted'):
            self.engine.close_session('main', self.lease)
        self.assertTrue(self.engine.status()['session']['active'])


class AutonomyBoundaryTests(AutonomyFixture):
    def setUp(self):
        super().setUp()
        self.fresh(dict(release=dict(enabled=True, authorization='user request', remote='devops', target='main',
                                     argv=['git', 'push', 'devops', 'HEAD:main'])))

    def test_permit_and_release_refuse_while_autonomy_is_active(self):
        self.arm()
        self.assertTrue(self.engine.autonomy_active())
        with self.assertRaisesRegex(EngineError, 'autonomy'):
            self.engine.release_permit('main', self.lease, 'devops', 'main')
        with self.assertRaisesRegex(EngineError, 'autonomy'):
            self.engine.check_release('devops', 'main', argv=['git', 'push', 'devops', 'HEAD:main'])
        self.engine.disarm_autonomy()
        self.assertFalse(self.engine.autonomy_active())
        with self.assertRaises(EngineError) as raised:  # now the ordinary evidence refusal
            self.engine.release_permit('main', self.lease, 'devops', 'main')
        self.assertNotIn('autonomy', str(raised.exception))

    def test_autonomy_active_needs_an_active_session(self):
        self.arm()
        self.engine.interrupt('main', self.lease)
        self.assertFalse(self.engine.autonomy_active())

    def test_interrupt_finish_and_session_end_clear_autonomy(self):
        self.arm()
        self.engine.interrupt('main', self.lease)
        self.assertIsNone(self.auto())
        self.engine.open_session('main', harness_session='S')
        self.arm()
        self.engine.end_harness_session('S')
        self.assertIsNone(self.auto())
        self.engine.open_session('main')
        self.arm()
        self.engine.interrupt_active()
        self.assertIsNone(self.auto())


class AutonomyReportTests(AutonomyFixture):
    def test_stop_writes_the_morning_report_with_accepted_parked_and_failures(self):
        self.engine.run_gate('main', self.lease, 'old-failure', [sys.executable, '-c', 'raise SystemExit(4)'])
        self.arm(deadline=iso(T0 + 60))
        self.accept_card('done')
        self.task('p')
        self.engine.park('main', self.lease, 'p', 'needs a push')
        self.task('b')
        token = self.engine.dispatch('main', self.lease, 'b', 'wb')
        self.engine.report('wb', token, done('Implemented b.'))
        report = self.root / 'r.json'
        self.review(report, reviewer='rev-1', tasks=['b'], findings=['off by one'])
        self.allow_review('rev-1')
        self.engine.record_review('main', self.lease, 'rev-1', report, ['correctness'], ['b'], findings=['off by one'])
        self.assertFalse(self.engine.run_gate('main', self.lease, 'unit', [sys.executable, '-c', 'raise SystemExit(3)'])['passed'])
        self.assertIsNotNone(self.engine.hook_stop())
        self.now[0] = T0 + 61
        self.assertIsNone(self.engine.hook_stop())
        progress = (self.state / 'progress.md').read_text()
        self.assertIn('## Run brief 2027-01-15T08:01:01', progress)
        for fragment in ('deadline', 'passes: 1', 'done (investigator/code)', 'p: needs a push',
                         'unit', 'exit 3', 'BLOCKED', 'rev-1', 'off by one'):
            self.assertIn(fragment, progress)
        self.assertNotIn('old-failure', progress)  # failures recorded before arm are not this run's
        stored = self.engine.autonomy_report()
        self.assertEqual(stored['reason'], 'deadline')
        self.assertEqual(stored['text'], progress.strip())
        self.assertEqual(stored['path'], str(self.engine.state_dir / 'progress.md'))

    def test_report_appends_and_keeps_earlier_progress_lines(self):
        (self.state / 'progress.md').write_text('# Plan X\nearlier line\n')
        self.arm(deadline=iso(T0 + 60))
        self.task('left-queued')
        self.accept_card('done')
        self.engine.hook_stop()
        self.now[0] = T0 + 61
        self.engine.hook_stop()
        text = (self.state / 'progress.md').read_text()
        self.assertTrue(text.startswith('# Plan X\nearlier line\n'))
        self.assertEqual(text.count('## Run brief'), 1)

    def test_disarm_records_the_reason_writes_the_report_and_clears_the_shown_one(self):
        self.arm(deadline=iso(T0 + 60))
        self.task('left-queued')
        self.accept_card('done')
        self.engine.hook_stop()
        self.now[0] = T0 + 61
        self.engine.hook_stop()  # the deadline report is now shown
        self.assertIsNotNone(self.engine.autonomy_report())
        self.assertFalse(self.engine.disarm_autonomy()['was_active'])
        self.assertIsNone(self.engine.autonomy_report())
        self.assertEqual(self.engine.autonomy_status()['last_stop_reason'], 'deadline')
        self.assertEqual((self.state / 'progress.md').read_text().count('## Run brief'), 1)
        self.arm(deadline=iso(self.now[0] + 3600))
        result = self.engine.disarm_autonomy()
        self.assertTrue(result['was_active'])
        self.assertIn('disarmed', result['text'])
        self.assertEqual((self.engine.autonomy_status()['active'], self.engine.autonomy_status()['last_stop_reason']), (False, 'disarmed'))
        self.assertEqual((self.state / 'progress.md').read_text().count('## Run brief'), 2)
        stored = self.engine.autonomy_report()  # SPEC 12.6: the disarm report is stored like any stop's
        self.assertEqual((stored['reason'], stored['text']), ('disarmed', result['text']))
        self.assertFalse(self.engine.disarm_autonomy()['was_active'])  # a later disarm clears it
        self.assertIsNone(self.engine.autonomy_report())

    def test_disarm_is_safe_at_any_time(self):
        fresh = Engine(self.root / 'fresh-state', self.repo)
        self.assertFalse(fresh.disarm_autonomy()['was_active'])
        self.assertFalse((self.root / 'fresh-state' / 'state.json').exists())
        before = self.engine.state_path.read_bytes()
        self.assertFalse(self.engine.disarm_autonomy()['was_active'])
        self.assertEqual(before, self.engine.state_path.read_bytes())
        self.assertFalse((self.state / 'progress.md').exists())

    def test_report_survives_interrupt_until_the_next_arm(self):
        self.arm(deadline=iso(T0 + 60))
        self.task('left-queued')
        self.accept_card('done')
        self.engine.hook_stop()
        self.now[0] = T0 + 61
        self.engine.hook_stop()
        stop_brief = self.engine.status()['last_brief']
        self.engine.interrupt('main', self.lease)
        self.assertEqual(self.engine.autonomy_report()['reason'], 'deadline')
        self.assertEqual(self.engine.status()['last_brief'], stop_brief)  # SPEC 5.9 item 2: the kept stop brief stays
        self.assertEqual(stop_brief['reason'], 'deadline')
        self.assertEqual(self.engine.status()['last_brief']['reason'], 'deadline')
        self.assertFalse(self.engine.autonomy_active())
        self.assertFalse(self.engine.autonomy_status()['active'])

    def test_a_malformed_autonomy_state_is_rejected(self):
        state = json.loads(self.engine.state_path.read_text())
        state['autonomy'] = {'active': 'yes'}
        self.engine.state_path.write_text(json.dumps(state))
        with self.assertRaises(EngineError):
            self.engine.status()


class MaterialityTests(EngineFixture):
    """SPEC 5.6 items 2 to 4, 5.13 items 1 and 2, and 5.17."""

    def reported(self, name='a', **kw):
        self.task(name, **kw)
        self.engine.report('w' + name, self.engine.dispatch('main', self.lease, name, 'w' + name), done('checked'))

    def issues_review(self, name, tasks, issues, findings=None, verdict=None):
        path = self.root / (name + '.json')
        blocking = [i['text'] for i in issues or [] if i.get('severity') == 'blocking']
        findings = blocking if findings is None else findings
        body = dict(reviewer='reviewer', categories=['correctness'], tasks=tasks, findings=findings, final=False,
                    verdict=verdict or ('BLOCKED' if findings else 'CLEAN'),
                    artifact=self.engine.artifact(self.engine.scope_for(tasks)),
                    summary='Behavior checked against acceptance criteria.')
        if issues is not None:
            body['issues'] = issues
        path.write_text(json.dumps(body))
        return path, findings

    def record(self, name, tasks, issues, findings=None, verdict=None):
        self.allow_review()
        path, findings = self.issues_review(name, tasks, issues, findings, verdict)
        return self.engine.record_review('main', self.lease, 'reviewer', path, ['correctness'], tasks, findings=findings)

    def brief(self, name, text):
        path = self.root / name
        path.write_text(text)
        return str(path)

    def drop_rev(self, name):
        state = json.loads(self.engine.state_path.read_text())
        state['tasks'][name].pop('rev')
        self.engine.state_path.write_text(json.dumps(state))

    def test_notes_only_report_is_clean_and_accepts(self):
        self.reported('a')
        notes = [dict(text='Rename helper', severity='note'), dict(text='Trailing comment', severity='note')]
        receipt = self.record('r', ['a'], notes)
        self.assertEqual([], receipt['findings'])
        self.assertEqual(['Rename helper', 'Trailing comment'], receipt['notes'])
        self.assertEqual('CLEAN', json.loads(Path(receipt['path']).read_text())['verdict'])
        self.engine.accept('main', self.lease, 'a')
        self.assertEqual('accepted', self.engine.status()['tasks']['a']['state'])

    def test_blocking_issue_needs_impact(self):
        self.reported('a')
        for impact in ['', '  ', None]:
            issue = dict(text='Bug', severity='blocking')
            if impact is not None:
                issue['impact'] = impact
            with self.assertRaisesRegex(EngineError, 'impact'):
                self.record('r', ['a'], [issue])
        self.record('ok', ['a'], [dict(text='Bug', severity='blocking', impact='Named test fails')])

    def test_issues_must_match_findings_and_verdict(self):
        self.reported('a')
        blocking = dict(text='Bug', severity='blocking', impact='Named requirement unmet')
        with self.assertRaisesRegex(EngineError, 'blocking'):
            self.record('differs', ['a'], [blocking], findings=['Other text'])
        with self.assertRaises(EngineError):
            self.record('clean-with-blocking', ['a'], [blocking], findings=[], verdict='CLEAN')
        with self.assertRaises(EngineError):
            self.record('note-as-finding', ['a'], [dict(text='Nit', severity='note')], findings=['Nit'])
        with self.assertRaises(EngineError):
            self.record('bad-severity', ['a'], [dict(text='Nit', severity='major', impact='x')])
        self.assertEqual([], self.engine.status()['reviews'])

    def test_repair_refused_for_notes_only(self):
        self.reported('a')
        self.record('r', ['a'], [dict(text='Nit', severity='note')])
        with self.assertRaisesRegex(EngineError, 'Repair needs earlier checked coding findings'):
            self.task('fix', mode='repair', files=['a'], repair_of='a')

    def test_review_of_2_2_card_without_issues_refused(self):
        self.reported('a')
        self.assertEqual('2.2', self.engine.status()['tasks']['a']['rev'])
        with self.assertRaisesRegex(EngineError, 'Review of 2.2 cards needs issues with severity'):
            self.record('r', ['a'], None)
        with self.assertRaisesRegex(EngineError, 'Review of 2.2 cards needs issues with severity'):
            self.record('r2', ['a'], None, findings=['bug'])

    def test_review_of_migrated_card_keeps_string_findings(self):
        self.reported('a')
        self.drop_rev('a')
        receipt = self.record('r', ['a'], None, findings=['bug'])
        self.assertEqual(['bug'], receipt['findings'])
        self.assertEqual([], receipt['notes'])
        with self.assertRaisesRegex(EngineError, 'findings'):
            self.engine.accept('main', self.lease, 'a')

    def test_clean_report_with_empty_issues_accepts(self):
        self.reported('a')
        receipt = self.record('r', ['a'], [])
        self.assertEqual([], receipt['findings'])
        self.engine.accept('main', self.lease, 'a')
        self.assertEqual('accepted', self.engine.status()['tasks']['a']['state'])

    def test_builder_brief_without_keep_remove_refused_at_add(self):
        for name, text, missing in [('none.md', 'Mode: implementation\nObjective.\n', '## Keep'),
                                    ('keep-only.md', 'Mode: implementation\n## Keep\nnone\n', '## Remove'),
                                    ('remove-only.md', 'Mode: implementation\n## Remove\nnone\n', '## Keep')]:
            with self.assertRaisesRegex(EngineError, missing, msg=name):
                self.task(name, brief=self.brief(name, text))
        self.assertEqual({}, self.engine.status()['tasks'])

    def test_builder_brief_with_none_lists_accepted(self):
        self.task('a', brief=self.brief('ok.md', 'Mode: implementation\nObjective.\n## Keep\nnone\n## Remove\nnone\n'))
        self.assertIn('a', self.engine.status()['tasks'])

    def test_queued_2_1_builder_without_headings_still_dispatches(self):
        path = self.brief('old.md', 'Mode: implementation\nObjective.\n')
        self.task('old')  # stored without a brief, then given a 2.1 brief that has no headings
        state = json.loads(self.engine.state_path.read_text())
        state['tasks']['old'].update(brief=path)
        state['tasks']['old'].pop('rev')
        self.engine.state_path.write_text(json.dumps(state))
        self.engine.dispatch('main', self.lease, 'old', 'worker')
        self.assertEqual('running', self.engine.status()['tasks']['old']['state'])

    def test_reviewer_brief_needs_no_keep_remove(self):
        self.task('B1')
        self.task('V1', role='code-reviewer', mode='final', files=[], review_of=['B1'],
                  brief=self.brief('rev.md', 'Mode: final\nObjective.\n'))
        self.assertIn('V1', self.engine.status()['tasks'])

    def two_reviews(self, resources1=(), resources2=()):
        self.reported('B1')
        self.task('V1', role='critic', mode='spec', files=['a'], resources=list(resources1), review_of=['B1'])
        self.task('V2', role='critic', mode='spec', files=['a'], resources=list(resources2), review_of=['B1'])
        self.engine.dispatch('main', self.lease, 'V1', 'review-1')

    def test_two_read_only_reviews_on_same_file_do_not_collide(self):
        self.two_reviews()
        self.assertEqual(['V2'], self.engine.ready('main', self.lease))
        self.engine.dispatch('main', self.lease, 'V2', 'review-2')

    def test_read_only_reviews_sharing_a_resource_still_collide(self):
        self.two_reviews(['db'], ['db'])
        self.assertEqual([], self.engine.ready('main', self.lease))
        with self.assertRaises(EngineError):
            self.engine.dispatch('main', self.lease, 'V2', 'review-2')

    def test_review_still_collides_with_running_writer(self):
        self.task('B0', files=['x'])
        self.engine.report('w0', self.engine.dispatch('main', self.lease, 'B0', 'w0'), done('checked'))
        self.task('W', files=['a'])
        self.engine.dispatch('main', self.lease, 'W', 'writer')
        self.task('V', role='critic', mode='spec', files=['a'], review_of=['B0'])
        self.assertEqual([], self.engine.ready('main', self.lease))


class AutonomyPreconditionsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / 'home'
        self.repo = Path(self.tmp.name) / 'repo'
        for d in (self.home / '.claude', self.repo / '.claude'):
            d.mkdir(parents=True)

    def report(self):
        return autonomy_preconditions(self.repo, home=self.home)

    def write(self, where, mode):
        path = {'user': self.home / '.claude/settings.json', 'project': self.repo / '.claude/settings.json',
                'local': self.repo / '.claude/settings.local.json'}[where]
        path.write_text(json.dumps({'permissions': {'defaultMode': mode}}))

    def test_unknown_when_no_settings_name_a_mode(self):
        out = self.report()
        self.assertTrue(out['permission_mode'].startswith('unknown'))
        self.assertIn('warning', out['permission_mode'].lower())
        self.assertIn('keep-awake', out['keep_awake'])

    def test_local_beats_project_beats_user(self):
        self.write('user', 'default')
        self.assertIn('default', self.report()['permission_mode'])
        self.write('project', 'acceptEdits')
        self.assertIn('acceptEdits', self.report()['permission_mode'])
        self.write('local', 'bypassPermissions')
        out = self.report()['permission_mode']
        self.assertIn('bypassPermissions', out)
        self.assertNotIn('warning', out.lower())

    def test_a_prompting_mode_warns_and_a_skipping_mode_does_not(self):
        self.write('user', 'default')
        self.assertIn('warning', self.report()['permission_mode'].lower())
        self.write('user', 'bypassPermissions')
        self.assertNotIn('warning', self.report()['permission_mode'].lower())

    def test_unreadable_settings_are_skipped_and_nothing_is_written(self):
        (self.repo / '.claude/settings.local.json').write_text('{not json')
        self.write('user', 'bypassPermissions')
        before = sorted(p.name for p in self.repo.rglob('*'))
        self.assertIn('bypassPermissions', self.report()['permission_mode'])
        self.assertEqual(before, sorted(p.name for p in self.repo.rglob('*')))

    def test_report_names_only_the_claude_permission_mode_and_keep_awake(self):
        self.assertEqual(sorted(self.report()), ['keep_awake', 'permission_mode'])


if __name__ == '__main__':
    unittest.main()


class FindingsLedgerTests(EngineFixture):
    """SPEC 5.12, 5.7 items 2 to 4, 5.11 items 1 and 2, 5.4 item 3, 5.14 item 5."""

    GATE = [sys.executable, '-c', 'print("ok")']

    def reported(self, name='a'):
        self.task(name)
        token = self.engine.dispatch('main', self.lease, name, 'worker-' + name)
        self.engine.report('worker-' + name, token, done('done'))

    def record(self, name, tasks, final=False, findings=None, categories=None, **extra):
        from orchestra_core.engine import CATEGORIES
        categories = categories or (CATEGORIES if final else ['correctness'])
        if final:
            tasks = sorted(self.engine.status()['tasks'])
        else:
            self.allow_review(name)
        path = self.root / (name + '.json')
        self.review(path, reviewer=name, tasks=tasks, categories=categories, findings=findings, final=final)
        body = json.loads(path.read_text())
        body.update(extra)
        path.write_text(json.dumps(body))
        return self.engine.record_review('main', self.lease, name, path, categories, tasks,
                                         final=final, findings=findings)

    def final_with_items(self, items, name='final'):
        self.reported()
        return self.record(name, ['a'], final=True, out_of_scope=items)

    def test_finding_add_requires_lease_and_known_review(self):
        self.reported()
        receipt = self.record('r', ['a'], findings=['Empty input crashes'])
        with self.assertRaises(EngineError):
            self.engine.add_finding('main', 'wrong-lease', receipt['id'], 'finding', 0, 'rejected', 'not a bug')
        with self.assertRaises(EngineError):
            self.engine.add_finding('main', self.lease, 'missing', 'finding', 0, 'rejected', 'not a bug')
        entry = self.engine.add_finding('main', self.lease, receipt['id'], 'finding', 0, 'rejected', 'not a bug')
        self.assertEqual('Empty input crashes', entry['text'])
        self.assertEqual({'review': receipt['id'], 'kind': 'finding', 'index': 0}, entry['source'])
        self.assertEqual([entry], self.engine.list_findings())

    def test_finding_list_for_brief_renders_known_findings(self):
        self.reported()
        receipt = self.record('r', ['a'], findings=['Empty input crashes'])
        entry = self.engine.add_finding('main', self.lease, receipt['id'], 'finding', 0, 'deferred', 'wait for the schema')
        block = self.engine.list_findings(for_brief=True)
        for part in ('Known findings', entry['id'], 'Empty input crashes', 'deferred', 'wait for the schema'):
            self.assertIn(part, block)

    def test_rejected_finding_does_not_allow_accept(self):
        self.reported()
        receipt = self.record('r', ['a'], findings=['Empty input crashes'])
        self.engine.add_finding('main', self.lease, receipt['id'], 'finding', 0, 'rejected', 'not a bug')
        with self.assertRaisesRegex(EngineError, 'current review findings'):
            self.engine.accept('main', self.lease, 'a')

    def test_2_1_state_without_findings_loads(self):
        self.reported()
        state = json.loads(self.engine.state_path.read_text())
        self.assertNotIn('findings', state)
        self.assertEqual([], self.engine.list_findings())
        self.assertIn('Known findings', self.engine.list_findings(for_brief=True))
        state['findings'] = []
        self.engine.state_path.write_text(json.dumps(state))
        self.assertEqual([], self.engine.list_findings())

    def test_finding_add_rejects_bad_disposition_and_index(self):
        self.reported()
        receipt = self.record('r', ['a'], findings=['Empty input crashes'])
        for kind, index, disposition in [('finding', 0, 'inline-fixed'), ('finding', 0, 'brief-later'),
                                         ('finding', 1, 'rejected'), ('finding', -1, 'rejected'),
                                         ('finding', True, 'rejected'), ('finding', '0', 'rejected'),
                                         ('out_of_scope', 0, 'inline'), ('nonsense', 0, 'rejected')]:
            with self.assertRaises(EngineError, msg=(kind, index, disposition)):
                self.engine.add_finding('main', self.lease, receipt['id'], kind, index, disposition, 'why')
        with self.assertRaises(EngineError):
            self.engine.add_finding('main', self.lease, receipt['id'], 'finding', 0, 'rejected', '  ')
        self.reported('b')
        final = self.record('f', ['a', 'b'], final=True, out_of_scope=['Dead code in util'])
        for disposition in ('rejected', 'deferred'):
            with self.assertRaises(EngineError, msg=disposition):
                self.engine.add_finding('main', self.lease, final['id'], 'out_of_scope', 0, disposition, 'why')
        self.assertEqual([], self.engine.list_findings())
        self.engine.add_finding('main', self.lease, final['id'], 'out_of_scope', 0, 'card', 'later', card='X1')

    def test_checkpoint_review_with_out_of_scope_is_refused(self):
        self.reported()
        with self.assertRaisesRegex(EngineError, 'raised only at the final review'):
            self.record('r', ['a'], out_of_scope=['Dead code in util'])
        self.assertEqual([], self.engine.status()['reviews'])

    def test_final_out_of_scope_does_not_block_verdict(self):
        receipt = self.final_with_items(['Dead code in util', 'Stale doc'])
        self.assertEqual([], receipt['findings'])
        self.assertEqual(['Dead code in util', 'Stale doc'], receipt['out_of_scope'])
        with self.assertRaises(EngineError):
            self.record('bad', ['a'], final=True, out_of_scope=['ok', ''])

    def test_completion_requires_triage_of_out_of_scope(self):
        receipt = self.final_with_items(['Dead code in util', 'Stale doc'])
        self.engine.accept('main', self.lease, 'a')
        with self.assertRaisesRegex(EngineError, 'triage'):
            self.engine.check_completion('main', self.lease)
        self.engine.add_finding('main', self.lease, receipt['id'], 'out_of_scope', 0, 'inline', 'fixed in place')
        with self.assertRaisesRegex(EngineError, 'triage'):
            self.engine.check_completion('main', self.lease)
        self.engine.add_finding('main', self.lease, receipt['id'], 'out_of_scope', 1, 'brief', 'for the user')
        self.engine.check_completion('main', self.lease)

    def test_triage_carries_forward_by_fingerprint(self):
        first = self.final_with_items(['Dead code in util'])
        self.engine.add_finding('main', self.lease, first['id'], 'out_of_scope', 0, 'brief', 'for the user')
        self.engine.accept('main', self.lease, 'a')
        second = self.record('final2', ['a'], final=True, out_of_scope=['Dead   code in\nutil'])
        self.assertNotEqual(first['id'], second['id'])
        self.engine.check_completion('main', self.lease)
        third = self.record('final3', ['a'], final=True, out_of_scope=['Dead code in util', 'A new item'])
        with self.assertRaisesRegex(EngineError, 'triage'):
            self.engine.check_completion('main', self.lease)
        self.assertNotEqual(first['id'], third['id'])

    def test_fingerprint_collapses_whitespace(self):
        import hashlib
        from orchestra_core.engine import _fingerprint
        self.assertEqual(hashlib.sha256(b'a b c').hexdigest(), _fingerprint('  a \n b\tc '))

    def test_gate_repeat_on_same_artifact_refused_without_again(self):
        first = self.engine.run_gate('main', self.lease, 'unit', self.GATE)
        self.assertTrue(first['passed'])
        with self.assertRaisesRegex(EngineError, 'Gate unit already passed on this artifact \\(receipt %s\\); pass --again to rerun' % first['id']):
            self.engine.run_gate('main', self.lease, 'unit', self.GATE)
        again = self.engine.run_gate('main', self.lease, 'unit', self.GATE, again=True)
        self.assertNotEqual(first['id'], again['id'])
        self.engine.run_gate('main', self.lease, 'other', self.GATE)
        (self.repo / 'a').write_text('changed')
        self.engine.run_gate('main', self.lease, 'unit', self.GATE)

    def test_failed_gate_rerun_allowed(self):
        bad = [sys.executable, '-c', 'raise SystemExit(3)']
        one = self.engine.run_gate('main', self.lease, 'bad', bad)
        two = self.engine.run_gate('main', self.lease, 'bad', bad)
        self.assertFalse(one['passed'] or two['passed'])
        self.assertNotEqual(one['id'], two['id'])

    def test_review_cites_stale_gate_refused(self):
        self.reported()
        gate = self.engine.run_gate('main', self.lease, 'unit', self.GATE)
        (self.repo / 'a').write_text('changed')
        with self.assertRaisesRegex(EngineError, 'stale gate receipt'):
            self.record('r', ['a'], gate_receipts=[gate['id']])

    def test_review_cites_current_passed_gate_accepted(self):
        self.reported()
        gate = self.engine.run_gate('main', self.lease, 'unit', self.GATE)
        receipt = self.record('r', ['a'], gate_receipts=[gate['id']])
        self.assertEqual([gate['id']], receipt['gate_receipts'])
        for cited in (['missing'], 'not-a-list', [3]):
            with self.assertRaises(EngineError, msg=cited):
                self.record('bad', ['a'], gate_receipts=cited)
        pathlib.Path(gate['path']).write_text('altered')
        with self.assertRaisesRegex(EngineError, 'altered gate receipt'):
            self.record('bad2', ['a'], gate_receipts=[gate['id']])

    def test_clean_review_citing_failed_gate_refused(self):
        self.reported()
        gate = self.engine.run_gate('main', self.lease, 'unit', [sys.executable, '-c', 'raise SystemExit(1)'])
        with self.assertRaisesRegex(EngineError, 'A failed gate receipt needs a blocking finding'):
            self.record('r', ['a'], gate_receipts=[gate['id']])
        receipt = self.record('r2', ['a'], findings=['unit gate fails'], gate_receipts=[gate['id']])
        self.assertEqual(['unit gate fails'], receipt['findings'])

    def test_gate_refuses_merged_delete_and_boundary_argv(self):
        for argv in (['git', 'branch', '-d', 'x'], ['git', 'worktree', 'remove', 'x'], ['git', 'branch', '-D', 'x']):
            before = len(self.engine.status()['gates'])
            with self.assertRaises(EngineError, msg=argv):
                self.engine.run_gate('main', self.lease, 'unsafe', argv)
            self.assertEqual(before, len(self.engine.status()['gates']))
        with self.assertRaisesRegex(EngineError, 'boundary actions run only through the guarded hook'):
            self.engine.run_gate('main', self.lease, 'unsafe', ['git', 'branch', '-d', 'x'])


class FixReviewTests(EngineFixture):
    """Per-task findings, the non-final critic receipt and the fix re-review ladder (contract items 4 and 5)."""
    LENSES = ['requirements', 'correctness', 'tests', 'architecture']

    def setUp(self):
        super().setUp()
        self.allow_review()

    def built(self, name, **kw):
        self.task(name, **kw)
        token = self.engine.dispatch('main', self.lease, name, 'w-' + name)
        self.engine.report('w-' + name, token, done('Built ' + name))

    def reviewed(self, name, tasks, findings=None, task_findings=None, repair_check=None, categories=None,
                 final=False, reviewer='reviewer'):
        path = self.root / (name + '.json')
        self.review(path, reviewer=reviewer, tasks=tasks, findings=findings, task_findings=task_findings,
                    repair_check=repair_check, categories=categories, final=final)
        return self.engine.record_review('main', self.lease, reviewer, path, categories or ['correctness'],
                                         tasks, final=final, findings=findings)

    def final(self, name, findings=None, task_findings=None):
        return self.reviewed(name, sorted(self.engine.status()['tasks']), findings=findings,
                             task_findings=task_findings, categories=self.LENSES, final=True, reviewer='final-reviewer')

    def blocked_chain(self):
        """B1 and B2 built; the final review blocks B1; R1 repairs it. Returns once R1 has reported."""
        (self.repo / 'B1').write_text('first')
        self.built('B1')
        self.built('B2')
        self.final('final', findings=['f'], task_findings={'B1': ['f'], 'B2': []})
        self.task('R1', mode='repair', repair_of='B1', files=['B1'])
        (self.repo / 'B1').write_text('repaired')
        self.engine.report('r1', self.engine.dispatch('main', self.lease, 'R1', 'r1'), done('Repaired'))

    def test_task_findings_block_only_named_card(self):
        self.built('B1')
        self.built('B2')
        self.reviewed('critic', ['B1', 'B2'], findings=['f'], task_findings={'B1': ['f'], 'B2': []})
        self.engine.accept('main', self.lease, 'B2')
        with self.assertRaisesRegex(EngineError, 'current review findings'):
            self.engine.accept('main', self.lease, 'B1')

    def test_task_findings_must_match_findings_union(self):
        self.built('B1')
        self.built('B2')
        for findings, task_findings, message in [
                (['f'], {'B1': ['g']}, 'Task findings must match'),
                (['f', 'g'], {'B1': ['f']}, 'Task findings must match'),
                (['f'], {'B1': ['f'], 'B9': []}, 'Task findings name an uncovered task'),
                (['f'], {'B1': 'f'}, 'Invalid task findings'),
                (['f'], ['f'], 'Invalid task findings')]:
            with self.assertRaisesRegex(EngineError, message):
                self.reviewed('bad', ['B1', 'B2'], findings=findings, task_findings=task_findings)
        self.assertEqual([], self.engine.status()['reviews'])
        receipt = self.reviewed('good', ['B1', 'B2'], findings=['f', 'g'], task_findings={'B1': ['f'], 'B2': ['g']})
        self.assertEqual({'B1': ['f'], 'B2': ['g']}, receipt['task_findings'])

    def test_review_without_task_findings_blocks_all_covered(self):
        self.built('B1')
        self.built('B2')
        receipt = self.reviewed('critic', ['B1', 'B2'], findings=['f'])
        self.assertNotIn('task_findings', receipt)
        for name in ('B1', 'B2'):
            with self.assertRaisesRegex(EngineError, 'current review findings'):
                self.engine.accept('main', self.lease, name)

    def test_clean_fix_re_review_accepts_the_chain_and_keeps_the_final_review_current(self):
        self.blocked_chain()
        self.engine.accept('main', self.lease, 'B2')
        check = self.reviewed('check', ['R1', 'B1'], repair_check=True)
        self.assertIs(True, check['repair_check'])
        self.engine.accept('main', self.lease, 'R1')
        self.engine.accept('main', self.lease, 'B1')
        self.assertEqual(['accepted'] * 3, [self.engine.status()['tasks'][i]['state'] for i in ('B1', 'B2', 'R1')])
        self.engine.check_completion('main', self.lease)  # the repaired file is inside the clean re-review's scope

    def test_edit_outside_the_fix_re_review_scope_voids_the_final_review(self):
        self.blocked_chain()
        self.engine.accept('main', self.lease, 'B2')
        self.reviewed('check', ['R1', 'B1'], repair_check=True)
        self.engine.accept('main', self.lease, 'R1')
        self.engine.accept('main', self.lease, 'B1')
        (self.repo / 'B2').write_text('edited after the final review')
        with self.assertRaisesRegex(EngineError, 'Current final review coverage is incomplete'):
            self.engine.check_completion('main', self.lease)

    def test_blocked_fix_re_review_leads_to_hold(self):
        self.blocked_chain()
        self.engine.accept('main', self.lease, 'B2')
        self.reviewed('check', ['R1', 'B1'], findings=['g'], task_findings={'R1': ['g'], 'B1': []}, repair_check=True)
        with self.assertRaisesRegex(EngineError, 'current review findings'):
            self.engine.accept('main', self.lease, 'R1')
        self.engine.hold('main', self.lease, 'R1', 'g')
        self.assertEqual(['held', 'held'], [self.engine.status()['tasks'][i]['state'] for i in ('R1', 'B1')])

    def test_one_repair_per_chain(self):
        self.blocked_chain()
        self.reviewed('check', ['R1', 'B1'], findings=['g'], task_findings={'R1': ['g'], 'B1': []}, repair_check=True)
        with self.assertRaisesRegex(EngineError, 'Escalation ends at one repair; hold the chain'):
            self.task('R2', mode='repair', repair_of='R1', files=['B1'])

    def test_fix_re_review_finding_on_ancestor_refused(self):
        self.blocked_chain()
        with self.assertRaisesRegex(EngineError, 'Attribute repair-diff findings to the chain tip R1'):
            self.reviewed('check', ['R1', 'B1'], findings=['g'], task_findings={'B1': ['g']}, repair_check=True)
        with self.assertRaisesRegex(EngineError, 'Attribute repair-diff findings to the chain tip'):
            self.reviewed('check', ['R1', 'B1'], findings=['g'], repair_check=True)
        receipt = self.reviewed('check', ['R1', 'B1'], findings=['g'], task_findings={'R1': ['g'], 'B1': []},
                                repair_check=True)
        self.assertEqual({'R1': ['g'], 'B1': []}, receipt['task_findings'])

    def test_fix_re_review_covers_only_repairs_of_final_findings(self):
        self.built('B1')
        self.reviewed('critic', ['B1'], findings=['f'])
        self.task('R1', mode='repair', repair_of='B1', files=['B1'])
        self.engine.report('r1', self.engine.dispatch('main', self.lease, 'R1', 'r1'), done('Repaired'))
        with self.assertRaisesRegex(EngineError, 'A fix re-review covers repair cards of a final-review finding'):
            self.reviewed('check', ['R1', 'B1'], repair_check=True)

    def test_record_review_stores_repair_check_marker(self):
        self.blocked_chain()
        receipt = self.reviewed('marked', ['R1', 'B1'], repair_check=True)
        self.assertIs(True, receipt['repair_check'])
        self.assertIs(True, self.engine.status()['reviews'][-1]['repair_check'])
        for value in (False, 'true', 1, None):
            path = self.root / 'bad.json'
            self.review(path, tasks=['R1', 'B1'])
            body = json.loads(path.read_text())
            body['repair_check'] = value
            path.write_text(json.dumps(body))
            with self.assertRaisesRegex(EngineError, 'repair_check must be true on a non-final fix re-review'):
                self.engine.record_review('main', self.lease, 'reviewer', path, ['correctness'], ['R1', 'B1'])
        with self.assertRaisesRegex(EngineError, 'repair_check must be true on a non-final fix re-review'):
            self.reviewed('final2', sorted(self.engine.status()['tasks']), final=True, repair_check=True,
                          categories=self.LENSES, reviewer='final-reviewer')

    def test_absent_task_findings_key_is_clean_at_every_reader(self):
        self.built('B')
        self.built('C')
        self.reviewed('critic', ['B', 'C'], findings=['f'], task_findings={'B': ['f']})
        with self.assertRaisesRegex(EngineError, 'Repair needs earlier checked coding findings'):
            self.task('RC', mode='repair', repair_of='C', files=['C'])
        self.engine.accept('main', self.lease, 'C')
        self.task('R1', mode='repair', repair_of='B', files=['B'])
        self.engine.report('r1', self.engine.dispatch('main', self.lease, 'R1', 'r1'), done('Repaired'))
        self.reviewed('recheck', ['R1', 'B'])
        self.engine.accept('main', self.lease, 'R1')
        self.engine.accept('main', self.lease, 'B')
        # C's newest receipt for its task is the critic review, whose findings are for B only.
        self.final('final')
        self.engine.check_completion('main', self.lease)

    def test_stale_newest_receipt_with_findings_for_other_task_keeps_verdict(self):
        self.built('B')
        self.built('C')
        self.reviewed('c-security', ['C'], categories=['security'])
        self.reviewed('critic', ['B', 'C'], findings=['f'], task_findings={'B': ['f'], 'C': []})
        (self.repo / 'B').write_text('edited after review')
        self.engine.accept('main', self.lease, 'C')
        with self.assertRaises(EngineError):
            self.engine.accept('main', self.lease, 'B')

    def test_repair_dispatch_refused_only_by_overlapping_acceptable_cards(self):
        for name, files in (('I1', ['docs/x.md']), ('I2', [])):
            self.built(name, role='investigator', mode='code', files=files)
        self.built('B2', files=['b.py'])
        self.reviewed('first', ['B2'], findings=['f'])
        self.task('R2', mode='repair', repair_of='B2', files=['b.py'])
        with self.assertRaisesRegex(EngineError, r'Accept I2 first; a repair would make its evidence stale'):
            self.engine.dispatch('main', self.lease, 'R2', 'r2')
        self.engine.accept('main', self.lease, 'I2')
        self.engine.report('r2', self.engine.dispatch('main', self.lease, 'R2', 'r2'), done('Repaired'))  # I1 does not block
        (self.repo / 'b.py').write_text('repaired')
        self.assertEqual('reported', self.engine.status()['tasks']['I1']['state'])
        self.engine.accept('main', self.lease, 'I1')


class HoldFixture(EngineFixture):
    ALL = ['requirements', 'correctness', 'security', 'tests', 'architecture', 'standards', 'cleanup']
    BASE = ['requirements', 'correctness', 'tests', 'architecture']

    def built(self, name, **kw):
        self.task(name, **kw)
        token = self.engine.dispatch('main', self.lease, name, 'w-' + name)
        self.engine.report('w-' + name, token, done('Built ' + name))

    def reviewed(self, name, tasks, findings=None, task_findings=None, repair_check=None, categories=None,
                 final=False, mutate=None, cleared=None, cover=True):
        if not final:
            self.allow_review()
        if final:  # a final review explicitly covers every task
            categories = categories or self.BASE
            if cover:
                tasks = sorted(set(tasks) | set(self.engine.status()['tasks']))
        reviewer = 'final-reviewer' if final else 'reviewer'
        path = self.root / (name + '.json')
        self.review(path, reviewer=reviewer, tasks=tasks, findings=findings, task_findings=task_findings,
                    repair_check=repair_check, categories=categories, final=final, cleared=cleared)
        if mutate:
            body = json.loads(path.read_text())
            mutate(body)
            path.write_text(json.dumps(body))
        return self.engine.record_review('main', self.lease, reviewer, path, categories or ['correctness'],
                                         tasks, final=final, findings=findings)

    def blocked_chain(self, check=True):
        """B1 blocked by the final review, repaired by R1, and R1 blocked by the fix re-review (or left reported)."""
        (self.repo / 'B1').write_text('first')
        self.built('B1')
        self.reviewed('first-final', ['B1'], findings=['f'], task_findings={'B1': ['f']}, final=True)
        self.task('R1', mode='repair', repair_of='B1', files=['B1'])
        (self.repo / 'B1').write_text('repaired')
        self.engine.report('r1', self.engine.dispatch('main', self.lease, 'R1', 'r1'), done('Repaired'))
        if check:
            self.reviewed('check', ['R1', 'B1'], findings=['g'], task_findings={'R1': ['g'], 'B1': []}, repair_check=True)

    def states(self, *ids):
        return [self.engine.status()['tasks'][i]['state'] for i in ids]

    def progress(self):
        path = self.engine.state_dir / 'progress.md'
        return path.read_text() if path.exists() else ''

class HoldTests(HoldFixture):
    """Repair ladder ending in hold, and held work at completion."""

    def test_hold_moves_whole_chain_and_logs(self):
        self.blocked_chain()
        result = self.engine.hold('main', self.lease, 'R1', 'g stays after one repair')
        self.assertEqual(['R1', 'B1'], result['held'])
        self.assertEqual(['held', 'held'], self.states('R1', 'B1'))
        self.assertEqual('g stays after one repair', self.engine.status()['tasks']['R1']['held_finding'])
        self.assertNotIn('held_finding', self.engine.status()['tasks']['B1'])
        self.assertIn('- held R1 (chain R1, B1): g stays after one repair', self.progress())
        with self.assertRaisesRegex(EngineError, 'Invalid or interrupted coordinator lease'):
            self.engine.hold('main', 'wrong', 'R1', 'x')

    def test_hold_refused_without_current_blocking_findings(self):
        self.blocked_chain(check=False)
        self.reviewed('clean', ['R1', 'B1'], repair_check=True)
        with self.assertRaisesRegex(EngineError, 'Hold needs'):
            self.engine.hold('main', self.lease, 'R1', 'clean repair')
        self.engine.accept('main', self.lease, 'R1')
        with self.assertRaisesRegex(EngineError, 'Hold needs'):
            self.engine.hold('main', self.lease, 'B1', 'has repaired_by')
        self.built('B2')
        self.reviewed('crit2', ['B2'], findings=['critic only'])
        with self.assertRaisesRegex(EngineError, 'Hold needs'):
            self.engine.hold('main', self.lease, 'B2', 'blocked only by a non-fix review')
        with self.assertRaisesRegex(EngineError, 'Hold needs a finding'):
            self.engine.hold('main', self.lease, 'B2', '  ')
        self.assertEqual('', self.progress())

    def test_dependency_on_held_card_is_ready(self):
        self.blocked_chain()
        self.task('C1', dependencies=['R1'], files=['C1'])
        self.assertNotIn('C1', self.engine.ready('main', self.lease))
        self.engine.hold('main', self.lease, 'R1', 'g')
        self.assertIn('C1', self.engine.ready('main', self.lease))

    def test_held_card_reserves_no_files(self):
        self.blocked_chain()
        self.task('N1', files=['B1'])
        self.assertNotIn('N1', self.engine.ready('main', self.lease))
        self.engine.hold('main', self.lease, 'R1', 'g')
        self.assertEqual(['N1'], self.engine.ready('main', self.lease))

    def test_repair_of_repair_refused_during_build(self):
        self.blocked_chain()
        with self.assertRaisesRegex(EngineError, 'Escalation ends at one repair; hold the chain'):
            self.task('R2', mode='repair', repair_of='R1', files=['B1'])
        self.assertNotIn('R2', self.engine.status()['tasks'])
        self.assertEqual('reported', self.states('R1')[0])

    def test_repair_of_held_tip_allowed_and_chain_repairing(self):
        self.blocked_chain()
        self.engine.hold('main', self.lease, 'R1', 'g')
        self.task('R2', mode='repair', repair_of='R1', files=['B1'])
        self.assertEqual(['repairing', 'repairing'], self.states('R1', 'B1'))
        self.assertEqual('R2', self.engine.status()['tasks']['R1']['repaired_by'])

    def test_review_may_cover_held_cards(self):
        self.blocked_chain()
        self.engine.hold('main', self.lease, 'R1', 'g')
        receipt = self.reviewed('final', ['B1', 'R1'], final=True, categories=self.ALL, cleared={'R1': 'no defect'})
        self.assertTrue({'B1', 'R1'} <= set(receipt['tasks']))
        self.task('V1', role='code-reviewer', mode='final', files=[], review_of=['R1'])
        self.assertIn('V1', self.engine.ready('main', self.lease))

    def test_accept_held_card_with_clean_current_verdict(self):
        self.blocked_chain()
        self.engine.hold('main', self.lease, 'R1', 'g')
        with self.assertRaisesRegex(EngineError, 'current review findings'):
            self.engine.accept('main', self.lease, 'R1')
        self.reviewed('clean', ['R1', 'B1'])
        with self.assertRaisesRegex(EngineError, 'repair must be accepted first'):
            self.engine.accept('main', self.lease, 'B1')
        self.engine.accept('main', self.lease, 'R1')
        self.engine.accept('main', self.lease, 'B1')
        self.assertEqual(['accepted', 'accepted'], self.states('R1', 'B1'))

    def test_first_repair_of_builder_still_allowed(self):
        self.built('B1')
        self.reviewed('crit', ['B1'], findings=['f'])
        self.task('R1', mode='repair', repair_of='B1', files=['B1'])
        self.assertEqual('repairing', self.states('B1')[0])

    def test_hold_refused_for_notes_only(self):
        self.blocked_chain(check=False)
        note = lambda body: body.update(issues=[dict(text='nit', severity='note')])
        receipt = self.reviewed('notes', ['R1', 'B1'], repair_check=True, mutate=note)
        self.assertEqual(['nit'], receipt['notes'])
        with self.assertRaisesRegex(EngineError, 'Hold needs'):
            self.engine.hold('main', self.lease, 'R1', 'a note is not a finding')

    def test_completion_refuses_while_card_held(self):
        self.blocked_chain()
        self.engine.hold('main', self.lease, 'R1', 'g')
        self.reviewed('final', ['B1', 'R1'], final=True, categories=self.ALL, cleared={'R1': 'no defect'})
        with self.assertRaisesRegex(EngineError, 'accepted'):
            self.engine.check_completion('main', self.lease)

class FinalReceiptTests(HoldFixture):
    """Final receipts, held tips, final repair rounds and `cleared`."""


    def test_contract_hash_unchanged_by_lens_change(self):
        from orchestra_core.engine import _contracts
        self.assertEqual('7b1f34b2bf297e6e95cdd59306a697f5a2b7410f5a84bc71feb7ffe0213439ed', _contracts()[1])

    def test_final_findings_need_task_findings_on_chain_tips(self):
        self.built('B1')
        self.reviewed('crit', ['B1'], findings=['f'])
        self.task('R1', mode='repair', repair_of='B1', files=['B1'])
        self.engine.report('r1', self.engine.dispatch('main', self.lease, 'R1', 'r1'), done('Repaired'))
        with self.assertRaisesRegex(EngineError, 'Attribute final findings to the chain tip R1'):
            self.reviewed('bare', ['B1', 'R1'], findings=['h'], final=True)
        with self.assertRaisesRegex(EngineError, 'Attribute final findings to the chain tip R1'):
            self.reviewed('ancestor', ['B1', 'R1'], findings=['h'], final=True, task_findings={'B1': ['h'], 'R1': []})
        receipt = self.reviewed('tip', ['B1', 'R1'], findings=['h'], final=True, task_findings={'R1': ['h']})
        self.assertEqual({'R1': ['h']}, receipt['task_findings'])

    def accepted_b1_with_final_finding(self):
        self.built('B1')
        self.reviewed('clean', ['B1'])
        self.engine.accept('main', self.lease, 'B1')
        self.reviewed('final', ['B1'], findings=['f'], final=True, task_findings={'B1': ['f']})

    def test_repair_of_accepted_tip_with_final_finding_allowed(self):
        self.accepted_b1_with_final_finding()
        self.task('R1', mode='repair', repair_of='B1', files=['B1'])
        self.assertEqual(['repairing'], self.states('B1'))

    def test_final_repair_card_stores_round_and_findings(self):
        self.accepted_b1_with_final_finding()
        self.task('R1', mode='repair', repair_of='B1', files=['B1'])
        task = self.engine.status()['tasks']['R1']
        self.assertEqual((1, ['f']), (task['final_round'], task['final_findings']))

    def test_final_round_counts_up_only_after_a_card_of_the_round_reported(self):
        for name in ('B1', 'B2', 'B3'):
            self.built(name)
        self.reviewed('clean', ['B1', 'B2', 'B3'])
        for name in ('B1', 'B2', 'B3'):
            self.engine.accept('main', self.lease, name)
        self.reviewed('final', ['B1', 'B2', 'B3'], findings=['f1', 'f2', 'f3'], final=True,
                      task_findings={'B1': ['f1'], 'B2': ['f2'], 'B3': ['f3']})
        rounds = []
        for repair, target in (('R1', 'B1'), ('R2', 'B2')):
            self.task(repair, mode='repair', repair_of=target, files=[target])
            rounds.append(self.engine.status()['tasks'][repair]['final_round'])
        self.engine.report('r1', self.engine.dispatch('main', self.lease, 'R1', 'r1'), done('Repaired'))
        self.task('R3', mode='repair', repair_of='B3', files=['B3'])
        rounds.append(self.engine.status()['tasks']['R3']['final_round'])
        self.assertEqual([1, 1, 2], rounds)

    def test_build_phase_repair_has_no_final_fields(self):
        self.built('B1')
        self.reviewed('crit', ['B1'], findings=['f'])
        self.task('R1', mode='repair', repair_of='B1', files=['B1'])
        task = self.engine.status()['tasks']['R1']
        self.assertNotIn('final_round', task)
        self.assertNotIn('final_findings', task)

    def test_final_receipt_must_address_every_held_tip(self):
        self.blocked_chain()
        self.engine.hold('main', self.lease, 'R1', 'g')
        with self.assertRaisesRegex(EngineError, 'Final receipt must address held tip R1'):
            self.reviewed('omitted', ['B1', 'R1'], final=True)
        with self.assertRaisesRegex(EngineError, 'cleared'):
            self.reviewed('blank', ['B1', 'R1'], final=True, cleared={'R1': '  '})
        with self.assertRaisesRegex(EngineError, 'cleared'):
            self.reviewed('not held', ['B1', 'R1'], final=True, cleared={'R1': 'ok', 'B1': 'ancestor'})
        cleared = self.reviewed('cleared', ['B1', 'R1'], final=True, cleared={'R1': 'no security defect'})
        self.assertEqual({'R1': 'no security defect'}, cleared['cleared'])
        found = self.reviewed('found', ['B1', 'R1'], findings=['still g'], final=True, task_findings={'R1': ['still g']})
        self.assertEqual({}, found['cleared'])

    def test_final_receipt_with_falsy_cleared(self):
        # Code decides: a final receipt's `cleared` must be an object, so a falsy non-object is refused;
        # an empty object is the same as none. A non-final receipt treats any falsy value as empty.
        self.blocked_chain()
        self.engine.hold('main', self.lease, 'R1', 'g')
        for name, falsy in (('list', []), ('none', None), ('empty-string', ''), ('zero', 0)):
            with self.assertRaisesRegex(EngineError, 'Invalid cleared entries', msg=name):
                self.reviewed('falsy-' + name, ['B1', 'R1'], final=True, mutate=lambda body, v=falsy: body.update(cleared=v))
        with self.assertRaisesRegex(EngineError, 'Final receipt must address held tip R1'):
            self.reviewed('empty-object', ['B1', 'R1'], final=True, cleared={})
        receipt = self.reviewed('plain', ['B1', 'R1'], mutate=lambda body: body.update(cleared=[]))
        self.assertEqual({}, receipt['cleared'])

    def test_final_receipt_must_cover_every_task(self):
        self.built('B1')
        self.built('B2')
        self.reviewed('clean', ['B1', 'B2'])
        every = sorted(self.engine.status()['tasks'])
        with self.assertRaisesRegex(EngineError, 'Final review must explicitly cover every task'):
            self.reviewed('partial', ['B1'], final=True, cover=False)
        with self.assertRaisesRegex(EngineError, 'Final review must explicitly cover every task'):
            self.reviewed('repeated', every + ['B2'], final=True, cover=False)
        self.assertTrue(self.reviewed('whole', every, final=True, cover=False)['final'])

    def test_cleared_refused_on_non_final_receipt(self):
        self.blocked_chain()
        self.engine.hold('main', self.lease, 'R1', 'g')
        with self.assertRaisesRegex(EngineError, 'Cleared entries are allowed only on final receipts'):
            self.reviewed('plain', ['B1', 'R1'], cleared={'R1': 'fine'})

    def test_held_tip_cleared_by_the_final_review_accepts_without_repair(self):
        self.blocked_chain()
        self.engine.hold('main', self.lease, 'R1', 'g')
        self.reviewed('cleared', ['B1', 'R1'], final=True, cleared={'R1': 'the held finding no longer reproduces'})
        with self.assertRaisesRegex(EngineError, 'Repair needs earlier checked coding findings'):
            self.task('R2', mode='repair', repair_of='R1', files=['B1'])
        with self.assertRaisesRegex(EngineError, 'repair must be accepted first'):
            self.engine.accept('main', self.lease, 'B1')
        self.engine.accept('main', self.lease, 'R1')
        self.engine.accept('main', self.lease, 'B1')
        self.assertEqual(['accepted', 'accepted'], self.states('R1', 'B1'))


class SelfReviewTests(EngineFixture):
    """Contract items 1 and 2: the SELF_REVIEW line and builder acceptance on it."""

    def running(self, name='a'):
        self.task(name)
        return self.engine.dispatch('main', self.lease, name, 'w-' + name)

    def test_builder_report_needs_exactly_one_self_review_line(self):
        token = self.running()
        good = {'checks': [{'command': 'pytest', 'exit_code': 0}],
                'criteria': [{'criterion': 'c', 'met': True, 'evidence': 'e'}]}
        line = 'SELF_REVIEW: ' + json.dumps(good)
        bad = {'no line': 'Built a.',
               'two lines': 'Built a.\n' + line + '\n' + line,
               'not json': 'Built a.\nSELF_REVIEW: {nope',
               'not an object': 'Built a.\nSELF_REVIEW: []',
               'empty checks': 'Built a.\nSELF_REVIEW: ' + json.dumps(dict(good, checks=[])),
               'empty criteria': 'Built a.\nSELF_REVIEW: ' + json.dumps(dict(good, criteria=[])),
               'no criteria key': 'Built a.\nSELF_REVIEW: ' + json.dumps({'checks': good['checks']}),
               'exit code not an int': 'Built a.\nSELF_REVIEW: ' + json.dumps(
                   dict(good, checks=[{'command': 'pytest', 'exit_code': '0'}])),
               'met not a bool': 'Built a.\nSELF_REVIEW: ' + json.dumps(
                   dict(good, criteria=[{'criterion': 'c', 'met': 1, 'evidence': 'e'}]))}
        for label, text in bad.items():
            with self.subTest(label), self.assertRaisesRegex(EngineError, 'Builder report needs one SELF_REVIEW line'):
                self.engine.report('w-a', token, text)
        self.assertEqual('running', self.engine.status()['tasks']['a']['state'])
        self.engine.report('w-a', token, 'ARTIFACT: abc123\nBuilt a.\n' + line)
        self.assertEqual(good, self.engine.status()['tasks']['a']['self_review'])

    def test_builder_report_needs_a_nonempty_artifact_line(self):
        token = self.running()
        line = 'SELF_REVIEW: ' + json.dumps({'checks': [{'command': 'pytest', 'exit_code': 0}],
                                             'criteria': [{'criterion': 'c', 'met': True, 'evidence': 'e'}]})
        for label, head in {'no line': 'Built a.', 'empty': 'ARTIFACT:\nBuilt a.', 'blank': 'ARTIFACT:   \nBuilt a.'}.items():
            with self.subTest(label), self.assertRaisesRegex(EngineError, 'Builder report needs a nonempty ARTIFACT line'):
                self.engine.report('w-a', token, head + '\n' + line)
        self.assertEqual('running', self.engine.status()['tasks']['a']['state'])
        self.engine.report('w-a', token, 'ARTIFACT: abc123\n' + line)
        self.assertEqual('reported', self.engine.status()['tasks']['a']['state'])

    def test_reported_card_takes_a_replacement_report_until_accepted(self):
        token = self.running()
        self.engine.report('w-a', token, done('First.', checks=[{'command': 'grep -q x a', 'exit_code': 1}]))
        with self.assertRaisesRegex(EngineError, 'Invalid assignment'):
            self.engine.report('w-other', token, done('Not mine.'))
        self.engine.report('w-a', token, done('Second.'))
        task = self.engine.status()['tasks']['a']
        self.assertEqual('reported', task['state'])
        self.assertIn('Second.', task['report'])
        self.assertEqual(0, task['self_review']['checks'][0]['exit_code'])
        self.engine.accept('main', self.lease, 'a')
        with self.assertRaisesRegex(EngineError, 'Invalid assignment'):
            self.engine.report('w-a', token, done('Late.'))

    def test_replacement_report_refused_once_a_review_covers_the_card(self):
        token = self.running()
        self.engine.report('w-a', token, done('First.'))
        path = self.root / 'final-a.json'
        self.review(path, tasks=['a'], categories=ALL_CATEGORIES, final=True)
        self.engine.record_review('main', self.lease, 'reviewer', path, ALL_CATEGORIES, ['a'], final=True)
        with self.assertRaisesRegex(EngineError, 'A review covers this report'):
            self.engine.report('w-a', token, done('Second.'))
        self.assertIn('First.', self.engine.status()['tasks']['a']['report'])

    def test_non_builder_report_needs_no_self_review(self):
        self.task('look', role='investigator', mode='code', files=[])
        token = self.engine.dispatch('main', self.lease, 'look', 'w-look')
        self.engine.report('w-look', token, 'Inspected.')
        self.assertNotIn('self_review', self.engine.status()['tasks']['look'])

    def test_failing_check_or_unmet_criterion_refuses_accept(self):
        cases = {'failing check': dict(checks=[{'command': 'pytest', 'exit_code': 1}]),
                 'one of two checks failing': dict(checks=[{'command': 'a', 'exit_code': 0}, {'command': 'b', 'exit_code': 2}]),
                 'unmet criterion': dict(criteria=[{'criterion': 'c', 'met': False, 'evidence': 'not done'}])}
        for label, kw in cases.items():
            name = label.replace(' ', '-')
            token = self.running(name)
            self.engine.report('w-' + name, token, done('Built.', **kw))
            with self.subTest(label), self.assertRaisesRegex(EngineError, 'Self-review has a failing check or unmet criterion'):
                self.engine.accept('main', self.lease, name)
            self.assertEqual('reported', self.engine.status()['tasks'][name]['state'])

    def test_builder_accepts_on_its_self_review_without_an_independent_review(self):
        token = self.running()
        self.engine.report('w-a', token, done('Built a.'))
        self.engine.accept('main', self.lease, 'a')
        self.assertEqual('accepted', self.engine.status()['tasks']['a']['state'])
        self.assertEqual([], self.engine.status()['reviews'])

    def test_stale_reported_artifact_refuses_accept(self):
        token = self.running()
        self.engine.report('w-a', token, done('Built a.'))
        (self.repo / 'a').write_text('edited after the report')
        with self.assertRaisesRegex(EngineError, 'Reported artifact is stale'):
            self.engine.accept('main', self.lease, 'a')


class RouteTests(EngineFixture):
    """Contract item 3: `start --items` and `route` decide who does builder work."""

    def run_with(self, items, name='state-items'):
        engine = Engine(self.root / name, self.repo)
        return engine, engine.open_session('main', items=items)

    def add(self, engine, lease, name, **kw):
        task = dict(id=name, role='builder', mode='implementation', inputs=['spec'], acceptance=['check behavior'],
                    files=[name], resources=[], dependencies=[])
        task.update(kw)
        engine.add_task('main', lease, task)

    def plan_card(self, engine, lease):
        self.add(engine, lease, 'plan', role='designer-planner', mode='plan', files=[])
        engine.report('planner', engine.dispatch('main', lease, 'plan', 'planner'), 'Plan: group the work.')
        engine.accept('main', lease, 'plan')

    def test_items_choose_the_route(self):
        for items, route in ((1, 'inline'), (5, 'inline'), (6, 'workflow'), (40, 'workflow')):
            engine, _ = self.run_with(items, 'state-%d' % items)
            session = engine.status()['session']
            self.assertEqual((items, route, []), (session['items'], session['route'], session['route_log']))

    def test_items_must_be_a_positive_integer(self):
        for bad in (0, -1, True, '3', 2.5):
            with self.subTest(bad), self.assertRaisesRegex(EngineError, 'Items must be an integer of 1 or more'):
                self.run_with(bad)

    def test_a_new_run_can_be_required_to_state_its_size(self):
        engine = Engine(self.root / 'needs-size', self.repo)
        with self.assertRaisesRegex(EngineError, 'A new run needs --size tiny, medium or large'):
            engine.open_session('main', require_size=True)
        lease = engine.open_session('main', size='medium', require_size=True)
        engine.interrupt('main', lease)
        lease = engine.open_session('main', require_size=True)  # a resumed run keeps its size
        self.assertEqual('medium', engine.status()['session']['size'])
        engine.interrupt('main', lease)
        with self.assertRaisesRegex(EngineError, 'apply to a new run'):
            engine.open_session('main', size='tiny')
        with self.assertRaisesRegex(EngineError, 'applies only to a new run'):
            engine.open_session('main', items=9)  # the 2.4 rule for items stays

    def test_inline_route_refuses_a_helper_without_a_reason(self):
        engine, lease = self.run_with(3)
        self.add(engine, lease, 'b')
        with self.assertRaisesRegex(EngineError, 'Inline route: the main session does this work; pass --helper REASON to dispatch a helper'):
            engine.dispatch('main', lease, 'b', 'helper')
        with self.assertRaisesRegex(EngineError, 'Inline route'):
            engine.dispatch('main', lease, 'b', 'helper', helper='  ')
        engine.dispatch('main', lease, 'b', 'helper', helper='a disjoint file the main session need not hold')
        self.assertEqual('a disjoint file the main session need not hold', engine.status()['tasks']['b']['helper_reason'])

    def test_inline_route_lets_the_main_session_do_the_work(self):
        engine, lease = self.run_with(3)
        self.add(engine, lease, 'b')
        token = engine.start_inline('main', lease, 'b')
        engine.report('main', token, done('Built b.'))
        engine.accept('main', lease, 'b')
        self.assertTrue(engine.status()['tasks']['b']['inline'])

    def test_inline_route_has_no_plan_card(self):
        engine, lease = self.run_with(5)
        with self.assertRaisesRegex(EngineError, 'Inline route: no plan card; the main session groups the work'):
            self.add(engine, lease, 'plan', role='designer-planner', mode='plan', files=[])
        self.add(engine, lease, 'product', role='designer-planner', mode='product', files=[])  # other modes stay

    def test_workflow_route_needs_an_accepted_plan_card_first(self):
        engine, lease = self.run_with(8)
        self.add(engine, lease, 'b')
        for label, action in (('dispatch', lambda: engine.dispatch('main', lease, 'b', 'w')),
                              ('inline', lambda: engine.start_inline('main', lease, 'b'))):
            with self.subTest(label), self.assertRaisesRegex(EngineError, 'Workflow route: accept the designer-planner plan card first'):
                action()
        self.add(engine, lease, 'plan', role='designer-planner', mode='plan', files=[])
        with self.assertRaisesRegex(EngineError, 'Workflow route: accept'):
            engine.dispatch('main', lease, 'b', 'w')  # a plan card that is only queued does not count
        engine.report('planner', engine.dispatch('main', lease, 'plan', 'planner'), 'Plan: group the work.')
        engine.accept('main', lease, 'plan')
        engine.report('w', engine.dispatch('main', lease, 'b', 'w'), done('Built b.'))
        engine.accept('main', lease, 'b')
        self.assertEqual('accepted', engine.status()['tasks']['b']['state'])

    def test_route_changes_items_and_route_and_logs_why(self):
        engine, lease = self.run_with(3)
        self.add(engine, lease, 'b')
        self.assertEqual({'items': 9, 'route': 'workflow'}, engine.set_route('main', lease, 9, 'the brief grew'))
        with self.assertRaisesRegex(EngineError, 'Workflow route'):
            engine.start_inline('main', lease, 'b')
        engine.set_route('main', lease, 2, 'most of it was one change')
        session = engine.status()['session']
        self.assertEqual((2, 'inline'), (session['items'], session['route']))
        self.assertEqual([(9, 'the brief grew'), (2, 'most of it was one change')],
                         [(e['items'], e['reason']) for e in session['route_log']])
        self.assertTrue(all(e['at'] for e in session['route_log']))
        engine.start_inline('main', lease, 'b')  # inline again

    def test_route_needs_a_reason_a_valid_count_and_the_lease(self):
        engine, lease = self.run_with(3)
        with self.assertRaisesRegex(EngineError, 'Route needs a reason'):
            engine.set_route('main', lease, 7, ' ')
        with self.assertRaisesRegex(EngineError, 'Items must be an integer'):
            engine.set_route('main', lease, 0, 'why')
        with self.assertRaisesRegex(EngineError, 'Invalid or interrupted coordinator lease'):
            engine.set_route('main', 'wrong', 7, 'why')
        self.assertEqual((3, 'inline', []), tuple(engine.status()['session'][k] for k in ('items', 'route', 'route_log')))

    def test_a_2_3_state_without_items_keeps_the_old_routing(self):
        state, lease = load_2_3_state(self.root, self.repo)
        engine = Engine(state, self.repo)
        self.assertNotIn('route', engine.status()['session'])
        self.add(engine, lease, 'b')
        self.add(engine, lease, 'plan', role='designer-planner', mode='plan', files=[])  # a plan card is allowed
        token = engine.dispatch('main', lease, 'b', 'w')  # no --helper, no plan card
        engine.report('w', token, done('Built b.'))
        engine.accept('main', lease, 'b')
        self.add(engine, lease, 'c')
        engine.start_inline('main', lease, 'c')


class SizeRouteTests(EngineFixture):
    """Contract items 2 to 6: a run routes by the size of its diff."""

    def run_with(self, size='medium', asks=None, owner_request=False, name='state-size'):
        engine = Engine(self.root / name, self.repo)
        return engine, engine.open_session('main', size=size, asks=asks, owner_request=owner_request, require_size=True)

    def add(self, engine, lease, name, **kw):
        task = dict(id=name, role='builder', mode='implementation', inputs=['spec'], acceptance=['check behavior'],
                    files=[name], resources=[], dependencies=[])
        task.update(kw)
        engine.add_task('main', lease, task)

    def test_new_run_without_size_is_refused_naming_size(self):
        engine = Engine(self.root / 'nosize', self.repo)
        with self.assertRaisesRegex(EngineError, 'A new run needs --size tiny, medium or large'):
            engine.open_session('main', require_size=True)
        self.assertIsNone(engine.status()['session'])

    def test_size_large_on_new_run_needs_owner_request_and_names_escalation(self):
        engine = Engine(self.root / 'large', self.repo)
        with self.assertRaisesRegex(EngineError, r'escalate with route --size large --reason TEXT, or pass --owner-request '
                                                 r'when the owner asked for a map'):
            engine.open_session('main', size='large', require_size=True)
        self.assertIsNone(engine.status()['session'])

    def test_owner_request_allows_large_start(self):
        engine, _ = self.run_with('large', owner_request=True)
        session = engine.status()['session']
        self.assertEqual(('large', 1, True), (session['size'], session['asks'], session['owner_request']))

    def test_unknown_size_and_bad_asks_are_refused(self):
        for bad in ('huge', '', 'Tiny', 3, True):
            with self.subTest(size=bad), self.assertRaises(EngineError):
                self.run_with(bad, name='bad-size')
        for bad in (0, -1, True, '2', 2.5):
            with self.subTest(asks=bad), self.assertRaisesRegex(EngineError, '--asks must be an integer, 1 or more'):
                self.run_with('tiny', asks=bad, name='bad-asks')

    def test_start_flags_on_a_resumed_run_are_refused(self):
        engine, lease = self.run_with('medium', asks=2)
        engine.interrupt('main', lease)
        for kw in (dict(size='tiny'), dict(asks=3), dict(owner_request=True)):
            with self.subTest(kw), self.assertRaisesRegex(
                    EngineError, r'--size, --asks and --owner-request apply to a new run; use start --new-run, or route --size '
                                 r'to change the tier'):
                engine.open_session('main', **kw)
        engine.open_session('main', require_size=True)  # a resumed run needs none of the flags
        self.assertEqual(('medium', 2), tuple(engine.status()['session'][k] for k in ('size', 'asks')))

    def test_session_records_size_asks_and_owner_request(self):
        engine, _ = self.run_with('tiny', asks=3)
        session = engine.status()['session']
        self.assertEqual(('tiny', 3, False, []), tuple(session[k] for k in ('size', 'asks', 'owner_request', 'route_log')))
        self.assertEqual(self.git('rev-parse', 'HEAD'), session['base'])
        self.assertNotIn('route', session)
        self.assertNotIn('items', session)

    def test_relaunch_keeps_size_asks_and_owner_request(self):
        engine, lease = self.run_with('large', asks=2, owner_request=True)
        engine.set_route('main', lease, None, 'it shrank', size='medium')
        engine.interrupt('main', lease)
        engine.open_session('main')
        session = engine.status()['session']
        self.assertEqual(('medium', 2, True), (session['size'], session['asks'], session['owner_request']))
        self.assertEqual(['it shrank'], [e['reason'] for e in session['route_log']])

    def mutate(self, name, change):
        engine, lease = self.run_with('medium', name=name)
        engine.interrupt('main', lease)
        path = engine.state_path
        data = json.loads(path.read_text())
        change(data['session'])
        path.write_text(json.dumps(data))
        return engine

    def test_state_with_items_and_size_together_is_invalid(self):
        engine = self.mutate('both', lambda s: s.update(items=2, route='inline'))
        with self.assertRaisesRegex(EngineError, 'Invalid session size'):
            engine.status()

    def test_bad_size_or_asks_in_state_is_invalid(self):
        changes = {'size': lambda s: s.update(size='huge'), 'asks0': lambda s: s.update(asks=0),
                   'asksbool': lambda s: s.update(asks=True), 'owner': lambda s: s.update(owner_request='yes'),
                   'log': lambda s: s.update(route_log=[{'size': 'huge', 'asks': 1, 'reason': 'r', 'at': 'x'}]),
                   'asks-no-size': lambda s: (s.pop('size'), s.update(asks=1))}
        for name, change in changes.items():
            with self.subTest(name), self.assertRaisesRegex(EngineError, 'Invalid session size'):
                self.mutate('bad-' + name, change).status()

    def test_bad_card_size_in_state_is_invalid(self):
        engine, lease = self.run_with('medium', name='card-size')
        self.add(engine, lease, 'b', size='tiny')
        engine.interrupt('main', lease)
        path = engine.state_path
        for bad in ('large', 'huge', None):
            data = json.loads(path.read_text())
            data['tasks']['b']['size'] = bad
            path.write_text(json.dumps(data))
            with self.subTest(bad), self.assertRaisesRegex(EngineError, 'Invalid task size'):
                engine.status()

    def test_route_size_logs_size_asks_reason(self):
        engine, lease = self.run_with('tiny', asks=2)
        self.assertEqual({'size': 'medium', 'asks': 3}, engine.set_route('main', lease, None, 'grew', size='medium', asks=3))
        session = engine.status()['session']
        self.assertEqual(('medium', 3), (session['size'], session['asks']))
        entry = session['route_log'][0]
        self.assertEqual(('medium', 3, 'grew'), (entry['size'], entry['asks'], entry['reason']))
        self.assertTrue(entry['at'])
        with self.assertRaisesRegex(EngineError, 'Route needs a reason'):
            engine.set_route('main', lease, None, ' ', size='tiny')
        with self.assertRaises(EngineError):
            engine.set_route('main', lease, None, 'why', size='huge')
        with self.assertRaisesRegex(EngineError, '--asks must be an integer'):
            engine.set_route('main', lease, None, 'why', size='tiny', asks=0)
        with self.assertRaisesRegex(EngineError, 'Invalid or interrupted coordinator lease'):
            engine.set_route('main', 'wrong', None, 'why', size='tiny')
        with self.assertRaisesRegex(EngineError, 'exactly one'):
            engine.set_route('main', lease, 3, 'why', size='tiny')
        with self.assertRaisesRegex(EngineError, 'exactly one'):
            engine.set_route('main', lease, None, 'why')
        self.assertEqual(1, len(engine.status()['session']['route_log']))

    def test_route_size_without_asks_keeps_the_current_count(self):
        engine, lease = self.run_with('tiny', asks=4)
        engine.set_route('main', lease, None, 'grew', size='medium')
        self.assertEqual(4, engine.status()['session']['asks'])
        self.assertEqual(4, engine.status()['session']['route_log'][0]['asks'])

    def test_route_size_can_escalate_to_large_without_owner_request(self):
        engine, lease = self.run_with('medium')
        engine.set_route('main', lease, None, 'grilling passed the ceiling', size='large')
        session = engine.status()['session']
        self.assertEqual(('large', False), (session['size'], session['owner_request']))
        engine.set_route('main', lease, None, 'it shrank', size='tiny')  # either direction
        self.assertEqual('tiny', engine.status()['session']['size'])

    def test_route_size_refused_on_items_run(self):
        state, lease = load_2_4_state(self.root, self.repo)
        engine = Engine(state, self.repo)
        with self.assertRaisesRegex(EngineError, 'This run routes by items; use route --items'):
            engine.set_route('main', lease, None, 'why', size='medium')

    def test_route_items_refused_on_size_run(self):
        engine, lease = self.run_with('medium')
        with self.assertRaisesRegex(EngineError, 'This run routes by size; use route --size'):
            engine.set_route('main', lease, 3, 'why')
        self.assertEqual([], engine.status()['session']['route_log'])

    def test_route_size_refused_on_2_3_run(self):
        state, lease = load_2_3_state(self.root, self.repo)
        engine = Engine(state, self.repo)
        with self.assertRaisesRegex(EngineError, 'This run has no route; start a new run with --size'):
            engine.set_route('main', lease, None, 'why', size='medium')
        engine.set_route('main', lease, 3, 'why')  # route --items behaves as in 2.4
        self.assertEqual('inline', engine.status()['session']['route'])

    def test_tiny_card_dispatch_needs_helper_reason(self):
        engine, lease = self.run_with('tiny')
        self.add(engine, lease, 'b')
        for helper in (None, '  '):
            with self.subTest(helper), self.assertRaisesRegex(
                    EngineError, 'Tiny unit: the main session does this work; pass --helper REASON to dispatch a helper'):
                engine.dispatch('main', lease, 'b', 'w', helper=helper)
        engine.dispatch('main', lease, 'b', 'w', helper='needs a second pair of hands')
        self.assertEqual('needs a second pair of hands', engine.status()['tasks']['b']['helper_reason'])

    def test_medium_card_dispatch_needs_no_helper(self):
        engine, lease = self.run_with('medium')
        self.add(engine, lease, 'b')
        engine.dispatch('main', lease, 'b', 'w')
        self.add(engine, lease, 'c')
        engine.dispatch('main', lease, 'c', 'x', helper='ignored')  # accepted and ignored on a medium card
        self.assertEqual('running', engine.status()['tasks']['c']['state'])

    def test_card_size_overrides_run_size(self):
        engine, lease = self.run_with('tiny')
        self.add(engine, lease, 'b', size='medium')
        engine.dispatch('main', lease, 'b', 'w')
        engine, lease = self.run_with('medium', name='other')
        self.add(engine, lease, 'b', size='tiny')
        with self.assertRaisesRegex(EngineError, 'Tiny unit'):
            engine.dispatch('main', lease, 'b', 'w')

    def test_card_without_size_reads_the_run_tier_at_dispatch(self):
        engine, lease = self.run_with('tiny')
        self.add(engine, lease, 'b')
        self.assertNotIn('size', engine.status()['tasks']['b'])
        engine.set_route('main', lease, None, 'it grew', size='medium')
        engine.dispatch('main', lease, 'b', 'w')  # no helper: the card now reads medium

    def test_large_run_card_defaults_to_medium(self):
        engine, lease = self.run_with('large', owner_request=True)
        self.add(engine, lease, 'b')
        engine.dispatch('main', lease, 'b', 'w')

    def test_invalid_card_size_is_refused(self):
        engine, lease = self.run_with('medium')
        for bad in ('large', 'huge', '', None, 3):
            with self.subTest(bad), self.assertRaisesRegex(EngineError, 'Invalid task size'):
                self.add(engine, lease, 'b', size=bad)
        self.assertEqual({}, engine.status()['tasks'])

    def test_card_size_on_items_and_2_3_runs_is_validated_and_ignored(self):
        for load, name in ((load_2_4_state, 'items'), (load_2_3_state, 'legacy')):
            state, lease = load(self.root, self.repo, name)
            engine = Engine(state, self.repo)
            with self.assertRaisesRegex(EngineError, 'Invalid task size'):
                self.add(engine, lease, 'x', size='huge')
            self.add(engine, lease, 'b', size='medium')
            self.add(engine, lease, 'c', size='tiny')
            if name == 'items':
                with self.assertRaisesRegex(EngineError, 'Inline route'):
                    engine.dispatch('main', lease, 'b', 'w')  # the 2.4 route check, not the card size, decides
            else:
                engine.dispatch('main', lease, 'b', 'w')
            if name == 'legacy':
                engine.dispatch('main', lease, 'c', 'x')  # a tiny card on a 2.3 run needs no helper

    def test_inline_reservation_of_a_tiny_card_is_not_gated(self):
        engine, lease = self.run_with('tiny')
        self.add(engine, lease, 'b')
        token = engine.start_inline('main', lease, 'b')
        engine.report('main', token, done('Built b.'))
        engine.accept('main', lease, 'b')
        self.assertTrue(engine.status()['tasks']['b']['inline'])

    def test_plan_card_refused_on_tiny_and_medium_run(self):
        for size in ('tiny', 'medium'):
            engine, lease = self.run_with(size, name='plan-' + size)
            with self.subTest(size), self.assertRaisesRegex(
                    EngineError, 'Plan card needs a large run or an owner request; escalate with route --size large --reason TEXT'):
                self.add(engine, lease, 'plan', role='designer-planner', mode='plan', files=[])
            self.add(engine, lease, 'product', role='designer-planner', mode='product', files=[])  # other modes stay

    def test_plan_card_allowed_on_large_run(self):
        engine, lease = self.run_with('medium')
        engine.set_route('main', lease, None, 'grilling passed the ceiling', size='large')
        self.add(engine, lease, 'plan', role='designer-planner', mode='plan', files=[])
        self.add(engine, lease, 'b')  # a large run does not force a plan before builders
        engine.dispatch('main', lease, 'b', 'w')

    def test_plan_card_allowed_with_session_owner_request(self):
        engine, lease = self.run_with('large', owner_request=True)
        engine.set_route('main', lease, None, 'shrank', size='medium')
        self.add(engine, lease, 'plan', role='designer-planner', mode='plan', files=[])

    def test_plan_card_allowed_with_task_owner_request(self):
        engine, lease = self.run_with('medium')
        self.add(engine, lease, 'plan', role='designer-planner', mode='plan', files=[], owner_request=True)
        self.assertTrue(engine.status()['tasks']['plan']['owner_request'])


class PrePrTests(EngineFixture):
    """Contract item 7: the read-only size check and reviewer choice."""

    def run_with(self, size='medium', asks=None, name='state-prepr', **kw):
        engine = Engine(self.root / name, self.repo)
        self.run_lease = engine.open_session('main', size=size, asks=asks, require_size=True, **kw)
        return engine

    def write(self, lines, path='big.txt'):
        (self.repo / path).write_text('x\n' * lines)

    def test_budget_is_guide_times_asks(self):
        for size, asks, budget in (('tiny', 1, 50), ('tiny', 3, 150), ('medium', 1, 400), ('medium', 2, 800)):
            engine = self.run_with(size, asks, name='b-%s-%d' % (size, asks))
            with self.subTest(size, asks=asks):
                out = engine.prepr()
                self.assertEqual((size, asks, budget, False), (out['size'], out['asks'], out['budget'], out['over_budget']))
                self.assertEqual(self.git('rev-parse', 'HEAD'), out['base'])

    def test_over_budget_warns_with_both_sizes_and_succeeds(self):
        engine = self.run_with('tiny', 2)
        self.write(101)
        out = engine.prepr()
        self.assertTrue(out['over_budget'])
        self.assertEqual(101, out['changed_lines'])
        self.assertEqual('Size warning: declared tiny with 2 ask(s) budgets 100 changed lines; the diff has 101. '
                         'Run route --size TIER --reason TEXT if the work grew.', out['warning'])

    def test_within_budget_has_no_warning(self):
        engine = self.run_with('tiny', 2)
        self.write(100)
        out = engine.prepr()
        self.assertEqual((100, False, None), (out['changed_lines'], out['over_budget'], out['warning']))

    def test_route_to_a_fitting_tier_clears_the_warning(self):
        engine = self.run_with('tiny')
        lease = self.run_lease
        self.write(120)
        self.assertIsNotNone(engine.prepr()['warning'])
        engine.set_route('main', lease, None, 'grew', size='tiny', asks=2)  # budget 100: still over
        self.assertIsNotNone(engine.prepr()['warning'])
        engine.set_route('main', lease, None, 'grew', size='medium')
        out = engine.prepr()
        self.assertEqual((800, None), (out['budget'], out['warning']))  # medium keeps the 2 asks

    def test_large_run_has_no_budget(self):
        engine = self.run_with('large', owner_request=True)
        self.write(900)
        out = engine.prepr()
        self.assertEqual(('large', None, False, None), (out['size'], out['budget'], out['over_budget'], out['warning']))

    def test_items_run_gets_no_size_check(self):
        state, _ = load_2_4_state(self.root, self.repo)
        self.write(900)
        out = Engine(state, self.repo).prepr()
        self.assertEqual((None, None, None, False, None, 900),
                         (out['size'], out['asks'], out['budget'], out['over_budget'], out['warning'], out['changed_lines']))

    def test_prepr_without_a_base_reports_nulls_and_the_full_reviewer(self):
        state, _ = load_2_3_state(self.root, self.repo)
        engine = Engine(state, self.repo)
        with mock.patch.object(Engine, '_changed', side_effect=AssertionError('read the diff without a base')):
            out = engine.prepr()
        self.assertEqual((None, None, 'full', 'orchestra:code-reviewer', None),
                         (out['base'], out['changed_lines'], out['reviewer'], out['agent'], out['warning']))
        self.assertEqual(['requirements', 'correctness', 'security', 'tests', 'architecture', 'standards', 'cleanup'],
                         out['lenses'])
        self.assertEqual((None, False), (out['budget'], out['over_budget']))

    def test_prepr_on_a_state_with_no_session_reports_nulls(self):
        engine = Engine(self.root / 'empty', self.repo)
        out = engine.prepr()
        self.assertEqual((None, None, None, 'full'), (out['base'], out['changed_lines'], out['size'], out['reviewer']))
        self.assertIsNone(out['warning'])

    def test_reviewer_bands_at_50_51_400_401(self):
        engine = self.run_with('large', owner_request=True)
        expected = ((50, 'medium', 'orchestra:code-reviewer-medium'), (51, 'medium', 'orchestra:code-reviewer-medium'),
                    (400, 'medium', 'orchestra:code-reviewer-medium'), (401, 'full', 'orchestra:code-reviewer'))
        for lines, reviewer, agent in expected:
            self.write(lines)
            out = engine.prepr()
            with self.subTest(lines):
                self.assertEqual((lines, reviewer, agent), (out['changed_lines'], out['reviewer'], out['agent']))

    def test_reviewer_follows_summed_lines_not_largest_ask(self):
        engine = self.run_with('tiny', 3)  # three tiny asks of 30 lines each: the sum is 90
        for i in range(3):
            self.write(30, 'ask%d.txt' % i)
        out = engine.prepr()
        self.assertEqual((90, 'medium'), (out['changed_lines'], out['reviewer']))

    def test_untracked_files_count_toward_changed_lines(self):
        engine = self.run_with('medium')
        (self.repo / 'a').write_text('initial\nmore\n')  # tracked: the unterminated line is rewritten, one more is added: 3
        self.write(10)  # untracked: 10
        self.assertEqual(13, engine.prepr()['changed_lines'])

    def test_prepr_writes_no_state(self):
        engine = self.run_with('tiny')
        self.write(80)
        before = engine.state_path.read_bytes()
        engine.prepr()
        self.assertEqual(before, engine.state_path.read_bytes())

    def test_the_cli_prints_the_warning_to_stderr_and_exits_zero(self):
        engine = self.run_with('tiny')
        self.write(80)
        result = subprocess.run([sys.executable, str(SCRIPTS / 'orchestra.py'), '--repo', str(self.repo),
                                 '--state', str(self.root / 'state-prepr'), 'prepr'], capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        out = json.loads(result.stdout)
        self.assertEqual(out['warning'], result.stderr.strip())


class LegacyStateTests(EngineFixture):
    """Contract item 3: a run state written by the 2.3 engine loads under 2.4; a real policy change still refuses."""

    def test_a_2_3_state_loads_interrupts_resumes_and_finishes(self):
        state, lease = load_2_3_state(self.root, self.repo)
        engine = Engine(state, self.repo)
        session = engine.status()['session']
        self.assertTrue(session['active'])
        self.assertNotIn('items', session)
        engine.interrupt('main', lease)
        lease = engine.open_session('main')  # a resumed 2.3 run needs no --items
        engine.close_session('main', lease)
        self.assertEqual('completed', engine.status()['session']['outcome'])

    def test_the_cli_status_interrupt_and_finish_load_a_2_3_state(self):
        state, lease = load_2_3_state(self.root, self.repo)
        cli = [sys.executable, str(SCRIPTS / 'orchestra.py'), '--repo', str(self.repo), '--state', str(state)]
        for command in (['status'], ['--lease', lease, 'interrupt']):
            result = subprocess.run(cli + command, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
        lease = json.loads(subprocess.run(cli + ['start'], capture_output=True, text=True, check=True).stdout)['lease']
        result = subprocess.run(cli + ['--lease', lease, 'finish'], capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_a_policy_change_still_refuses_a_2_3_state(self):
        state, _ = load_2_3_state(self.root, self.repo)
        with self.assertRaisesRegex(EngineError, r'policy changed while a run is active.*Upgrade from 2\.3 to 2\.4'):
            Engine(state, self.repo, dict(max_workers=3)).status()

    def test_a_state_with_items_never_takes_the_2_3_binding(self):
        state, _ = load_2_3_state(self.root, self.repo)
        data = json.loads((state / 'state.json').read_text())
        data['session'].update(items=2, route='inline')
        (state / 'state.json').write_text(json.dumps(data))
        with self.assertRaisesRegex(EngineError, 'policy changed while a run is active'):
            Engine(state, self.repo).status()

    def test_a_state_with_size_never_takes_the_2_3_binding(self):
        state, _ = load_2_3_state(self.root, self.repo)
        data = json.loads((state / 'state.json').read_text())
        data['session'].update(size='tiny', asks=1, owner_request=False, route_log=[])
        (state / 'state.json').write_text(json.dumps(data))
        with self.assertRaisesRegex(EngineError, 'policy changed while a run is active'):
            Engine(state, self.repo).status()

    def test_2_4_state_loads_and_keeps_2_4_routing(self):
        state, lease = load_2_4_state(self.root, self.repo)
        engine = Engine(state, self.repo)
        session = engine.status()['session']
        self.assertEqual((3, 'inline'), (session['items'], session['route']))
        task = dict(id='b', role='builder', mode='implementation', inputs=['spec'], acceptance=['check behavior'],
                    files=['b'], resources=[], dependencies=[])
        engine.add_task('main', lease, task)
        with self.assertRaisesRegex(EngineError, 'Inline route: the main session does this work; pass --helper REASON'):
            engine.dispatch('main', lease, 'b', 'w')
        self.assertEqual({'items': 9, 'route': 'workflow'}, engine.set_route('main', lease, 9, 'grew'))
        engine.interrupt('main', lease)
        engine.open_session('main', require_size=True)  # a resumed 2.4 run needs no --size
        self.assertEqual(9, engine.status()['session']['items'])

    def test_2_4_fixture_holds_only_placeholders(self):
        data = json.loads(STATE_2_4.read_text())
        self.assertEqual(('@REPO@', '@BASE@'), (data['repo'], data['session']['base']))
        text = STATE_2_4.read_text()
        for needle in ('/Users', '/private', '/tmp'):
            self.assertNotIn(needle, text)

    def test_2_4_policy_and_contract_hash_are_pinned(self):
        engine = Engine(self.root / 'pinned', self.repo)
        self.assertEqual('4b1d85568cf17dffc8adb272d1df95decfaf2a03c18c9176ff17190e4d5fb74d', engine.policy_hash)
        self.assertEqual('7b1f34b2bf297e6e95cdd59306a697f5a2b7410f5a84bc71feb7ffe0213439ed', engine.contract_hash)

    def test_one_combined_receipt_covers_all_required_categories(self):
        (self.repo / 'src' / 'auth').mkdir(parents=True)
        (self.repo / 'src/auth/login.py').write_text('x\n')
        required = self.engine.status(lenses=True)['required_lenses']
        self.assertIn('security', required)
        self.task('B')
        self.engine.report('w', self.engine.dispatch('main', self.lease, 'B', 'w'), done('Built B.'))
        self.engine.accept('main', self.lease, 'B')
        every = sorted(self.engine.status()['tasks'])
        path = self.root / 'combined.json'
        self.review(path, reviewer='final-reviewer', tasks=every, categories=required, final=True)
        self.engine.record_review('main', self.lease, 'final-reviewer', path, required, every, final=True)
        self.engine.check_completion('main', self.lease)


class DerivedLensTests(EngineFixture):
    """Contract item 6: the review lenses a change needs."""
    BASE = ['requirements', 'correctness', 'tests', 'architecture']

    def lenses(self):
        return self.engine.status(lenses=True)['required_lenses']

    def write(self, path, lines=1):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('x\n' * lines)

    def test_the_hook_facing_status_never_reads_the_diff(self):
        self.write('src/auth/login.py', 300)
        with mock.patch.object(Engine, '_changed', side_effect=AssertionError('status read the diff')):
            self.assertNotIn('required_lenses', self.engine.status())

    def test_the_cli_status_shows_the_lenses(self):
        self.write('src/auth/login.py')
        result = subprocess.run([sys.executable, str(SCRIPTS / 'orchestra.py'), '--repo', str(self.repo),
                                 '--state', str(self.root / 'state'), 'status'], capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(['requirements', 'correctness', 'security', 'tests', 'architecture'],
                         json.loads(result.stdout)['required_lenses'])

    def test_an_unchanged_repository_needs_the_four_base_lenses(self):
        self.assertEqual(self.BASE, self.lenses())

    def test_a_sensitive_path_adds_security(self):
        self.write('src/app.py')
        self.assertEqual(self.BASE, self.lenses())
        self.write('src/auth/login.py')
        self.assertEqual(['requirements', 'correctness', 'security', 'tests', 'architecture'], self.lenses())

    def test_size_above_the_threshold_adds_standards_and_cleanup(self):
        self.write('big.txt', 200)
        self.assertEqual(self.BASE, self.lenses())  # the threshold itself is not above it
        self.write('big.txt', 201)
        self.assertEqual(self.BASE + ['standards', 'cleanup'], self.lenses())

    def test_the_threshold_comes_from_policy(self):
        engine = Engine(self.root / 'small', self.repo, dict(standards_min_lines=5))
        engine.open_session('main')
        self.write('mid.txt', 6)
        self.assertEqual(self.BASE + ['standards', 'cleanup'], engine.status(lenses=True)['required_lenses'])

    def test_both_additions_together(self):
        self.write('migrations/0001.sql', 250)
        self.assertEqual(['requirements', 'correctness', 'security', 'tests', 'architecture', 'standards', 'cleanup'],
                         self.lenses())

    def test_an_explicit_category_list_overrides_the_derived_set(self):
        engine = Engine(self.root / 'explicit', self.repo, dict(required_review_categories=['correctness', 'tests']))
        engine.open_session('main')
        self.write('src/auth/login.py', 300)
        self.assertEqual(['correctness', 'tests'], engine.status(lenses=True)['required_lenses'])

    def test_completion_waits_for_a_derived_lens(self):
        self.write('src/auth/login.py')
        self.task('B')
        self.engine.report('w', self.engine.dispatch('main', self.lease, 'B', 'w'), done('Built B.'))
        self.engine.accept('main', self.lease, 'B')
        every = sorted(self.engine.status()['tasks'])

        def final(name, categories):
            path = self.root / (name + '.json')
            self.review(path, reviewer='final-reviewer', tasks=every, categories=categories, final=True)
            self.engine.record_review('main', self.lease, 'final-reviewer', path, categories, every, final=True)

        final('base', self.BASE)
        with self.assertRaises(EngineError):
            self.engine.check_completion('main', self.lease)
        final('security', ['security'])
        self.engine.check_completion('main', self.lease)


class RemovedFeatureTests(EngineFixture):
    """Contract items 4, 7 and 8: the pieces 2.4 removed, the one review kept, and the gate-id query."""

    def test_a_wave_key_is_refused(self):
        with self.assertRaisesRegex(EngineError, 'Waves are removed; use dependencies'):
            self.task('b', wave='W1')
        self.assertEqual({}, self.engine.status()['tasks'])

    def test_waves_and_supersede_are_gone(self):
        self.task('b')
        self.assertNotIn('waves', self.engine.status())
        self.assertFalse(hasattr(Engine, 'supersede'))
        self.assertFalse(hasattr(Engine, '_check_wave'))

    def test_only_the_pre_pr_review_and_the_fix_re_review_are_recorded(self):
        self.task('b')
        self.engine.report('w', self.engine.dispatch('main', self.lease, 'b', 'w'), done('Built b.'))
        path = self.root / 'r.json'
        self.review(path, reviewer='rando', tasks=['b'])
        with self.assertRaisesRegex(EngineError, 'Only the pre-PR review and the fix re-review are recorded'):
            self.engine.record_review('main', self.lease, 'rando', path, ['correctness'], ['b'])
        self.assertEqual([], self.engine.status()['reviews'])
        self.allow_review('rando')  # a critic card's receipt is still allowed
        self.engine.record_review('main', self.lease, 'rando', path, ['correctness'], ['b'])
        self.assertEqual(1, len(self.engine.status()['reviews']))

    def test_the_final_review_is_always_recorded(self):
        self.task('b')
        self.engine.report('w', self.engine.dispatch('main', self.lease, 'b', 'w'), done('Built b.'))
        path = self.root / 'final.json'
        self.review(path, reviewer='final-reviewer', tasks=['b'], final=True)
        self.assertTrue(self.engine.record_review('main', self.lease, 'final-reviewer', path, ['correctness'], ['b'],
                                                  final=True)['final'])

    def test_current_gate_ids(self):
        self.assertEqual([], self.engine.current_gate_ids())  # no receipt
        failed = self.engine.run_gate('main', self.lease, 'bad', [sys.executable, '-c', 'raise SystemExit(1)'])
        self.assertEqual([], self.engine.current_gate_ids())  # a failed receipt is not a passed one
        first = self.engine.run_gate('main', self.lease, 'unit', [sys.executable, '-c', 'pass'])
        second = self.engine.run_gate('main', self.lease, 'lint', [sys.executable, '-c', 'pass'])
        self.assertEqual(sorted([first['id'], second['id']]), sorted(self.engine.current_gate_ids()))
        self.assertNotIn(failed['id'], self.engine.current_gate_ids())
        (self.repo / 'a').write_text('edited after the gates')
        self.assertEqual([], self.engine.current_gate_ids())  # stale receipts
        fresh = self.engine.run_gate('main', self.lease, 'unit', [sys.executable, '-c', 'pass'])
        self.assertEqual([fresh['id']], self.engine.current_gate_ids())


HEADINGS = ('Needs you', 'Still failing / next phase', 'Held log', 'Final rounds', 'Notes', 'Deferred findings',
            'Parked', 'Accepted', 'Failures')


class RunBriefTests(AutonomyFixture, HoldFixture):
    """SPEC 5.9 (the run brief on every end path) and 5.16 item 5 (`write_busy_brief`)."""

    def brief_text(self):
        return self.engine.status()['last_brief']['text']

    @staticmethod
    def section(text, title):
        start = text.index('### ' + title + '\n')
        rest = text[start + len(title) + 5:]
        end = rest.find('### ')
        return rest if end < 0 else rest[:end]

    def held_run(self):
        """B1/R1 held, B2 accepted and blamed by a final receipt that clears R1; R2 is B2's final repair."""
        self.blocked_chain()
        self.engine.hold('main', self.lease, 'R1', 'g stays after one repair')
        self.built('B2')
        self.reviewed('clean2', ['B2'])
        self.engine.accept('main', self.lease, 'B2')
        self.reviewed('final', ['B1', 'R1', 'B2'], findings=['f'], final=True, task_findings={'B2': ['f']},
                      cleared={'R1': 'no defect'})
        self.task('R2', mode='repair', repair_of='B2', files=['B2'])

    def test_run_brief_lists_held_log_and_final_rounds(self):
        self.held_run()
        self.engine.interrupt('main', self.lease)
        text = self.brief_text()
        held = self.section(text, 'Held log')
        self.assertIn('R1 (chain R1, B1): g stays after one repair', held)
        self.assertIn('cleared by a lens: no defect', held)
        rounds = self.section(text, 'Final rounds')
        self.assertIn('round 1', rounds)
        self.assertIn('R2 (chain B2, R2)', rounds)
        self.assertIn('f', rounds)
        self.assertNotIn('R1', self.section(text, 'Still failing / next phase'))

    def test_run_brief_lists_still_failing_held_tips(self):
        self.blocked_chain()
        self.engine.hold('main', self.lease, 'R1', 'g stays after one repair')
        self.engine.interrupt('main', self.lease)
        failing = self.section(self.brief_text(), 'Still failing / next phase')
        self.assertIn('R1 (chain R1, B1)', failing)
        self.assertIn('g stays after one repair', failing)
        self.assertNotIn('attributed', self.section(self.brief_text(), 'Held log'))

    def test_close_session_writes_run_brief(self):
        (self.state / 'progress.md').write_text('# Plan X\nearlier line\n')
        self.engine.close_session('main', self.lease)
        progress = (self.state / 'progress.md').read_text()
        self.assertTrue(progress.startswith('# Plan X\nearlier line\n'))
        self.assertEqual(progress.count('## Run brief 2027-01-15T08:00:00'), 1)
        self.assertIn('- stop reason: closed', progress)
        stored = self.engine.status()['last_brief']
        self.assertEqual((stored['reason'], stored['at']), ('closed', '2027-01-15T08:00:00+00:00'))
        self.assertEqual(stored['path'], str((self.state / 'progress.md').resolve()))
        self.assertTrue(stored['text'].startswith('## Run brief 2027-01-15T08:00:00'))
        self.assertIn(stored['text'], progress)

    def test_interrupt_and_harness_end_write_run_brief(self):
        self.engine.interrupt('main', self.lease)
        self.assertEqual(self.engine.status()['last_brief']['reason'], 'interrupted')
        self.assertIn('- stop reason: interrupted', (self.state / 'progress.md').read_text())
        self.lease = self.engine.open_session('main', harness_session='S')
        self.now[0] += 60
        self.assertTrue(self.engine.end_harness_session('S'))
        stored = self.engine.status()['last_brief']
        self.assertEqual(stored['reason'], 'ended')
        self.assertIn('- stop reason: ended', stored['text'])
        self.lease = self.engine.open_session('main')
        self.now[0] += 60
        self.assertTrue(self.engine.interrupt_active())
        self.assertEqual(self.engine.status()['last_brief']['reason'], 'interrupted')
        self.assertEqual((self.state / 'progress.md').read_text().count('## Run brief'), 3)

    def test_noop_end_paths_write_no_brief(self):
        self.engine.interrupt('main', self.lease)
        before = (self.state / 'progress.md').read_bytes()
        self.assertFalse(self.engine.interrupt_active())
        self.assertFalse(self.engine.end_harness_session('nobody'))
        self.assertEqual(before, (self.state / 'progress.md').read_bytes())

    def test_run_brief_lists_still_failing_on_deadline(self):
        self.arm()
        self.built('B2')
        self.reviewed('b2', ['B2'], findings=['b2 breaks the parser'])
        self.now[0] += 7200
        self.assertIsNone(self.engine.hook_stop())
        stored = self.engine.status()['last_brief']
        self.assertEqual(stored['reason'], 'deadline')
        failing = self.section(stored['text'], 'Still failing / next phase')
        self.assertIn('B2', failing)
        self.assertIn('b2 breaks the parser', failing)
        self.assertIn('- deadline: ', stored['text'])

    def test_brief_command_is_read_only(self):
        self.engine.interrupt('main', self.lease)
        state_before = self.engine.state_path.read_bytes()
        progress_before = (self.state / 'progress.md').read_bytes()
        self.assertEqual(self.engine.brief(), self.brief_text())
        self.assertEqual(state_before, self.engine.state_path.read_bytes())
        self.assertEqual(progress_before, (self.state / 'progress.md').read_bytes())

    def test_brief_is_empty_before_any_run_ends(self):
        self.assertIsNone(self.engine.brief())

    def test_run_brief_needs_you_precedes_accepted(self):
        self.accept_card('done')
        self.task('p')
        self.engine.park('main', self.lease, 'p', 'needs a push')
        self.engine.interrupt('main', self.lease)
        text = self.brief_text()
        positions = [text.index('### ' + title + '\n') for title in HEADINGS]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('p: needs a push', self.section(text, 'Needs you'))

    def test_run_brief_keeps_2_1_lines(self):
        self.engine.run_gate('main', self.lease, 'old-failure', [sys.executable, '-c', 'raise SystemExit(4)'])
        self.arm(passes='1', stalls='2', deadline=iso(T0 + 60))  # a 2.1 ledger: the caps are recorded, never enforced
        self.accept_card('done')
        self.task('p')
        self.engine.park('main', self.lease, 'p', 'needs a push')
        self.task('b')
        token = self.engine.dispatch('main', self.lease, 'b', 'wb')
        self.engine.report('wb', token, done('Implemented b.'))
        report = self.root / 'r.json'
        self.review(report, reviewer='rev-1', tasks=['b'], findings=['off by one'])
        self.allow_review('rev-1')
        self.engine.record_review('main', self.lease, 'rev-1', report, ['correctness'], ['b'], findings=['off by one'])
        self.engine.run_gate('main', self.lease, 'unit', [sys.executable, '-c', 'raise SystemExit(3)'])
        self.engine.hook_stop()
        self.engine.hook_stop()
        self.now[0] = T0 + 61
        self.engine.hook_stop()
        text = self.brief_text()
        self.assertTrue(text.startswith('## Run brief 2027-01-15T08:01:01'))
        self.assertNotIn('Autonomy report', text)
        for fragment in ('- stop reason: deadline', '- passes: 2', '- stalls: 1', 'max_passes 1', 'max_stalls 2',
                         'recorded, not enforced', 'done (investigator/code)',
                         'p: needs a push', 'gate unit: exit 3', 'review rev-1: BLOCKED (off by one)'):
            self.assertIn(fragment, text)
        self.assertNotIn('old-failure', text)
        self.assertEqual(self.engine.autonomy_report()['text'], text)

    def test_unarmed_completed_run_brief_says_ready_to_release(self):
        self.engine.close_session('main', self.lease)
        self.assertIn('ready to release', self.section(self.brief_text(), 'Needs you'))
        self.lease = self.engine.open_session('main')
        self.engine.interrupt('main', self.lease)
        self.assertNotIn('ready to release', self.brief_text())

    def test_run_brief_marks_repaired_chains(self):
        self.blocked_chain(check=False)
        self.reviewed('clean', ['R1', 'B1'], repair_check=True)
        self.engine.accept('main', self.lease, 'R1')
        self.engine.accept('main', self.lease, 'B1')
        self.engine.interrupt('main', self.lease)
        accepted = self.section(self.brief_text(), 'Accepted')
        self.assertIn('repaired (B1, R1)', accepted)
        self.assertIn('R1 (builder/repair)', accepted)

    def test_run_brief_lists_notes(self):
        self.built('B1')
        note = lambda body: body.update(out_of_scope=['docs drift'], issues=body['issues'] + [dict(text='nit: rename x', severity='note')])
        receipt = self.reviewed('clean', ['B1'], mutate=note, final=True)
        self.engine.add_finding('main', self.lease, receipt['id'], 'out_of_scope', 0, 'brief', 'owner decides')
        self.built('B2')
        wave = self.reviewed('w', ['B2'], findings=['slow path'])
        self.engine.add_finding('main', self.lease, wave['id'], 'finding', 0, 'deferred', 'next sprint')
        self.engine.interrupt('main', self.lease)
        text = self.brief_text()
        self.assertIn('nit: rename x', self.section(text, 'Notes'))
        self.assertIn('slow path -- next sprint', self.section(text, 'Deferred findings'))
        needs = self.section(text, 'Needs you')
        self.assertIn('docs drift -- owner decides', needs)
        self.assertIn('slow path -- next sprint', needs)

    def test_progress_writes_are_single_appends(self):
        real_open, real_write, real_close = os.open, os.write, os.close
        opened, fds, writes, inject = [], set(), [], []

        def spy_open(path, flags, *args, **kwargs):
            if str(path).endswith('progress.md') and inject:
                other = real_open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
                real_write(other, inject.pop().encode())
                real_close(other)
            fd = real_open(path, flags, *args, **kwargs)
            if str(path).endswith('progress.md'):
                opened.append(flags)
                fds.add(fd)
            return fd

        def spy_write(fd, data):
            if fd in fds:
                writes.append(data)
            return real_write(fd, data)

        def spy_close(fd):
            fds.discard(fd)
            return real_close(fd)

        def single(label, action):
            opened.clear()
            writes.clear()
            with mock.patch.object(os, 'open', spy_open), mock.patch.object(os, 'write', spy_write), \
                    mock.patch.object(os, 'close', spy_close):
                action()
            self.assertEqual(len(opened), 1, label)
            self.assertTrue(opened[0] & os.O_APPEND, label)
            self.assertEqual(len(writes), 1, label)

        self.blocked_chain()
        single('hold', lambda: self.engine.hold('main', self.lease, 'R1', 'g'))
        self.fresh({})
        inject.append('line from another writer\n')
        single('close_session', lambda: self.engine.close_session('main', self.lease))
        text = (self.state / 'progress.md').read_text()
        self.assertLess(text.index('line from another writer'), text.index('## Run brief'))
        from orchestra_core.engine import write_busy_brief
        single('write_busy_brief', lambda: write_busy_brief(self.state, '2027-01-15T08:00:00+00:00'))
        text = (self.state / 'progress.md').read_text()
        self.assertIn('stop reason: state busy', text)
        self.assertIn('line from another writer', text)

    def test_write_busy_brief_leaves_state_json_alone(self):
        from orchestra_core.engine import write_busy_brief
        before = self.engine.state_path.read_bytes()
        write_busy_brief(self.state, '2027-01-15T08:00:00+00:00')
        self.assertEqual(before, self.engine.state_path.read_bytes())
        self.assertNotIn('last_brief', json.loads(before))

    def test_end_paths_keep_stopped_autonomy_brief(self):
        self.arm()
        self.now[0] += 7200
        self.assertIsNone(self.engine.hook_stop())
        stopped = self.engine.status()['last_brief']
        self.assertEqual(stopped['reason'], 'deadline')
        self.engine.interrupt('main', self.lease)
        self.lease = self.engine.open_session('main', harness_session='S2')
        self.assertTrue(self.engine.end_harness_session('S2'))
        progress = (self.state / 'progress.md').read_text()
        self.assertEqual(progress.count('## Run brief'), 3)
        self.assertIn('- stop reason: interrupted', progress)
        self.assertIn('- stop reason: ended', progress)
        self.assertEqual(self.engine.status()['last_brief'], stopped)
        self.lease = self.engine.open_session('main')
        self.arm(deadline=iso(self.now[0] + 3600))
        self.engine.interrupt('main', self.lease)
        self.assertEqual(self.engine.status()['last_brief']['reason'], 'interrupted')
        self.assertEqual((self.state / 'progress.md').read_text().count('## Run brief'), 4)

    def test_last_brief_must_be_well_formed(self):
        state = json.loads(self.engine.state_path.read_text())
        state['last_brief'] = {'reason': 'closed'}
        self.engine.state_path.write_text(json.dumps(state))
        with self.assertRaisesRegex(EngineError, 'Invalid last_brief'):
            self.engine.status()

    def test_lock_wait_raises_state_busy_and_default_blocks(self):
        from orchestra_core import portable as fcntl
        from orchestra_core.engine import StateBusy
        busy = Engine(self.state, self.repo, lock_wait=0.3, clock=lambda: self.now[0])
        self.engine.status()  # creates state.lock
        with (self.state / 'state.lock').open('a+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with self.assertRaises(StateBusy):
                busy.status()
            self.assertTrue(issubclass(StateBusy, EngineError))
        self.assertIn('session', busy.status())  # free again: the same engine reads


class AutonomyNoCapTests(AutonomyFixture, HoldFixture):
    """SPEC 5.8 (no count stops the loop, held work is live, completion order) and section 8 (2.1 runs)."""

    @staticmethod
    def section(text, title):
        start = text.index('### ' + title + '\n')
        rest = text[start + len(title) + 5:]
        end = rest.find('### ')
        return rest if end < 0 else rest[:end]

    def passing_gate(self):
        self.assertTrue(self.engine.run_gate('main', self.lease, 'fixture', PASS_ARGV)['passed'])

    def finish_line(self):
        """B1 accepted, a final review over every category, and the ledger check passed on the current artifact."""
        self.built('B1')
        self.reviewed('clean', ['B1'])
        self.engine.accept('main', self.lease, 'B1')
        self.reviewed('final', ['B1'], final=True, categories=self.ALL)
        self.passing_gate()

    def last_stop(self):
        return self.auto().get('last_stop_reason')

    def test_hook_stop_completes_when_everything_holds(self):
        self.arm()
        self.finish_line()
        self.assertIsNone(self.engine.hook_stop())
        self.assertEqual(self.last_stop(), 'complete')

    def test_stop_check_continues_while_final_finding_open_without_cards(self):
        self.arm()
        self.built('B1')
        self.reviewed('clean', ['B1'])
        self.engine.accept('main', self.lease, 'B1')
        self.reviewed('final', ['B1'], findings=['f'], final=True, task_findings={'B1': ['f']})
        reason = self.engine.hook_stop()
        self.assertIsInstance(reason, str)
        self.assertIn('start the final repair round', reason)
        self.assertIsNone(self.last_stop())
        self.assertTrue(self.engine.autonomy_active())

    def test_hook_stop_never_stops_on_pass_count(self):
        self.arm()
        self.task('x')
        for n in range(1, 51):
            self.assertIn('Autonomy pass %d:' % n, self.engine.hook_stop())
        self.assertEqual((self.auto()['passes'], self.auto()['active'], self.last_stop()), (50, True, None))

    def test_hook_stop_never_stops_on_stalls(self):
        self.arm()
        self.task('x')
        for _ in range(11):  # the arming turn is not a pass, so ten passes stall
            self.assertIsInstance(self.engine.hook_stop(), str)
        self.assertEqual((self.auto()['stalls'], self.auto()['active'], self.last_stop()), (10, True, None))

    def test_hook_stop_continues_while_held_cards_remain(self):
        self.arm()
        self.blocked_chain()
        self.engine.hold('main', self.lease, 'R1', 'g')
        self.assertEqual(self.engine.ready('main', self.lease), [])
        reason = self.engine.hook_stop()
        self.assertIn('start or continue the final phase', reason)
        self.assertEqual((self.auto()['active'], self.last_stop()), (True, None))

    def test_hook_stop_parked_only_when_held_and_parked(self):
        self.arm()
        self.blocked_chain()
        self.engine.hold('main', self.lease, 'R1', 'g')
        self.task('P')
        self.engine.park('main', self.lease, 'P', 'needs a push')
        self.assertIsNone(self.engine.hook_stop())
        self.assertEqual((self.auto()['active'], self.last_stop()), (False, 'parked-only'))
        needs = self.section(self.engine.status()['last_brief']['text'], 'Needs you')
        self.assertIn('P: needs a push', needs)
        self.assertIn('R1 (chain R1, B1)', needs)

    def test_complete_skips_ledger_checks_until_all_accepted(self):
        real, calls = Engine.artifact, []

        def counting(engine, scope=None):
            calls.append(scope)
            return real(engine, scope)

        self.arm()
        self.passing_gate()
        self.task('x', role='investigator', mode='code')
        with mock.patch.object(Engine, 'artifact', counting):
            self.assertIsInstance(self.engine.hook_stop(), str)
        self.assertEqual(calls, [])
        self.engine.report('w', self.engine.dispatch('main', self.lease, 'x', 'w'), done('Inspected x.'))
        self.engine.accept('main', self.lease, 'x')
        with mock.patch.object(Engine, 'artifact', counting):
            self.assertIsNone(self.engine.hook_stop())  # nothing live and no final review: not complete
        self.assertGreater(len(calls), 0)
        self.assertEqual(self.last_stop(), 'no-ready-card')

    def test_hook_stop_not_complete_while_held(self):
        self.arm()
        self.blocked_chain()
        self.engine.hold('main', self.lease, 'R1', 'g')
        self.reviewed('final', ['B1', 'R1'], final=True, categories=self.ALL, cleared={'R1': 'no defect'})
        self.passing_gate()
        self.assertIsInstance(self.engine.hook_stop(), str)
        self.assertEqual((self.auto()['active'], self.last_stop()), (True, None))

    def test_hook_stop_not_complete_while_final_finding_open(self):
        self.arm()
        self.built('B2')
        self.reviewed('clean', ['B2'])
        self.engine.accept('main', self.lease, 'B2')
        self.reviewed('final', ['B2'], findings=['f'], final=True, categories=self.ALL, task_findings={'B2': ['f']})
        self.passing_gate()
        self.engine.hook_stop()
        self.assertNotEqual(self.last_stop(), 'complete')

    def test_hook_stop_not_complete_while_card_repairing(self):
        self.arm()
        self.built('B2')
        self.reviewed('final', ['B2'], findings=['f'], final=True, task_findings={'B2': ['f']})
        self.task('R2', mode='repair', repair_of='B2', files=['B2'])
        self.assertEqual(self.states('B2'), ['repairing'])
        self.passing_gate()
        self.assertIsInstance(self.engine.hook_stop(), str)
        self.assertEqual((self.auto()['active'], self.last_stop()), (True, None))

    def test_hook_stop_deadline_still_stops(self):
        self.arm(deadline=iso(T0 + 60))
        self.task('x')
        self.assertIsInstance(self.engine.hook_stop(), str)
        self.now[0] = T0 + 61
        self.assertIsNone(self.engine.hook_stop())
        self.assertEqual((self.auto()['active'], self.last_stop(), self.auto()['passes']), (False, 'deadline', 1))
        self.assertEqual(self.engine.status()['last_brief']['reason'], 'deadline')

    def test_ledger_without_caps_arms(self):
        self.assertTrue(self.arm()['active'])
        self.assertNotIn('max_passes', self.auto())
        self.assertNotIn('max_stalls', self.auto())
        status = self.engine.autonomy_status()
        self.assertEqual((status['active'], status['max_passes'], status['max_stalls']), (True, None, None))

    def test_2_1_ledger_with_caps_still_arms_and_caps_are_ignored(self):
        self.arm(passes='1', stalls='1')
        self.task('x')
        for _ in range(4):
            self.assertIsInstance(self.engine.hook_stop(), str)
        auto = self.auto()
        self.assertEqual((auto['max_passes'], auto['max_stalls']), (1, 1))  # recorded
        self.assertEqual((auto['passes'], auto['stalls'], auto['active']), (4, 3, True))  # never enforced

    def test_signature_changes_on_report_hold_or_gate(self):
        self.arm()
        sig = lambda: self.engine.autonomy_status()['signature']
        seen = [sig()]
        self.assertRegex(seen[0], r'^[0-9a-f]{64}$')
        self.assertEqual(sig(), seen[0])  # a no-op leaves it

        def step(label, action):
            action()
            seen.append(sig())
            self.assertNotEqual(seen[-1], seen[-2], label)
            self.assertEqual(sig(), seen[-1], label + ' (read twice)')

        step('report', lambda: self.built('B1'))
        step('review', lambda: self.reviewed('final', ['B1'], findings=['f'], task_findings={'B1': ['f']}, final=True))
        step('repair card', lambda: self.task('R1', mode='repair', repair_of='B1', files=['B1']))
        step('repair report', lambda: self.engine.report(
            'r1', self.engine.dispatch('main', self.lease, 'R1', 'r1'), done('Repaired')))
        step('check', lambda: self.reviewed('check', ['R1', 'B1'], findings=['g'],
                                            task_findings={'R1': ['g'], 'B1': []}, repair_check=True))
        step('hold', lambda: self.engine.hold('main', self.lease, 'R1', 'g'))
        step('gate', self.passing_gate)

    def state_2_1(self, queued=True):
        """A 2.1 run: an accepted card, a parked card, optionally a queued one, a review, a passed gate and an armed
        ledger with caps. The engine writes it, then every key 2.1 never wrote is removed from the stored state."""
        self.accept_card('a')
        self.task('p')
        self.engine.park('main', self.lease, 'p', 'needs a push')
        if queued:
            self.task('q')
        self.arm(passes='1', stalls='2')
        self.passing_gate()
        raw = json.loads(self.engine.state_path.read_text())
        for key in ('signature', 'rev', 'seq', 'last_brief', 'held', 'last_signature'):
            raw['autonomy'].pop(key, None)
        for key in set(raw) - {'version', 'repo', 'policy', 'session', 'tasks', 'permits', 'reviews', 'gates', 'autonomy'}:
            raw.pop(key)
        self.engine.state_path.write_text(json.dumps(raw))
        return self.lease

    def test_2_1_state_fixture_loads_under_2_2(self):
        self.state_2_1()
        status = self.engine.status()
        self.assertEqual(sorted(status['tasks']), ['a', 'p', 'q'])
        self.assertEqual((status['autonomy']['max_passes'], status['autonomy']['passes']), (1, 0))
        self.assertTrue(self.engine.autonomy_active())
        for expected in (1, 2, 3, 4):  # past the old cap, which is recorded only
            self.assertIn('Autonomy pass %d:' % expected, self.engine.hook_stop())
        self.assertEqual((self.auto()['active'], self.auto()['max_passes'], self.auto()['passes']), (True, 1, 4))
        self.assertRegex(self.engine.autonomy_status()['signature'], r'^[0-9a-f]{64}$')

    def test_2_1_parked_card_keeps_park_semantics(self):
        lease = self.state_2_1(queued=False)
        self.assertIsNone(self.engine.hook_stop())  # a parked card and nothing else live: the 2.1 stop
        self.assertEqual(self.last_stop(), 'parked-only')
        self.engine.unpark('main', lease, 'p')
        self.assertEqual(self.states('p'), ['queued'])
        self.engine.park('main', lease, 'p', 'needs a push again')
        with self.assertRaisesRegex(EngineError, 'accepted'):
            self.engine.close_session('main', lease)


UNIT_ARGV = [sys.executable, '-c', 'print("passed")']
RELEASE_POLICY = dict(required_checks=[dict(name='unit', argv=UNIT_ARGV)],
                      release=dict(enabled=True, authorization='user request', remote='devops', target='main',
                                   argv=['git', 'push', 'devops', 'HEAD:main']))
PREAUTH = '- Release: pre-authorized devops main'


class ReleasePreauthTests(AutonomyFixture, HoldFixture):
    """SPEC 5.8 item 8: the ledger's Release line, `autonomy.release`, and the exact-pair exemption."""

    def setUp(self):
        super().setUp()
        self.fresh(RELEASE_POLICY)

    def boundaries(self, release):
        return [release if line == AUTONOMY_FIXED[0] else line for line in AUTONOMY_FIXED]

    def release_evidence(self):
        """A clean final review and a passed required gate on the current artifact: what a release permit needs."""
        path = self.root / 'release-final.json'
        self.review(path, reviewer='reviewer', categories=self.ALL, final=True)
        self.engine.record_review('main', self.lease, 'reviewer', path, self.ALL, final=True)
        self.engine.run_gate('main', self.lease, 'unit', UNIT_ARGV)

    def arm_with(self, release, relaunch=False):
        self.ledger(boundaries=self.boundaries(release))
        return self.engine.arm_autonomy(relaunch=relaunch)

    def test_arm_preauthorized_release_permits_exact_pair(self):
        self.release_evidence()
        self.arm_with(PREAUTH)
        self.assertEqual(self.auto()['release'], dict(remote='devops', target='main'))
        self.assertTrue(self.engine.autonomy_active())
        permit = self.engine.release_permit('main', self.lease, 'devops', 'main')
        self.assertEqual(permit['action'], 'release')
        self.assertEqual(permit, self.engine.check_release('devops', 'main', argv=['git', 'push', 'devops', 'HEAD:main']))
        for pair in (('devops', 'other'), ('origin', 'main')):  # any other pair stays an approval boundary
            with self.subTest(pair=pair):
                with self.assertRaisesRegex(EngineError, 'autonomy'):
                    self.engine.release_permit('main', self.lease, *pair)
                with self.assertRaisesRegex(EngineError, 'autonomy'):
                    self.engine.check_release(*pair)

    def test_permit_refused_under_autonomy_without_preauthorization(self):
        self.release_evidence()
        self.arm_with(AUTONOMY_FIXED[0])
        self.assertNotIn('release', self.auto())
        with self.assertRaisesRegex(EngineError, 'autonomy'):
            self.engine.release_permit('main', self.lease, 'devops', 'main')
        with self.assertRaisesRegex(EngineError, 'autonomy'):
            self.engine.check_release('devops', 'main')

    def test_preauthorization_mismatch_refused(self):
        for line in ('- Release: pre-authorized devops other', '- Release: pre-authorized origin main'):
            with self.subTest(line=line):
                self.ledger(boundaries=self.boundaries(line))
                with self.assertRaisesRegex(EngineError, 'Release pre-authorization must match policy.release'):
                    self.engine.arm_autonomy()
                self.assertIsNone(self.auto())
        disabled = dict(RELEASE_POLICY, release=dict(RELEASE_POLICY['release'], enabled=False))
        self.fresh(disabled)
        self.ledger(boundaries=self.boundaries(PREAUTH))
        with self.assertRaisesRegex(EngineError, 'Release pre-authorization must match policy.release'):
            self.engine.arm_autonomy()
        self.fresh(None)  # no release policy at all
        self.ledger(boundaries=self.boundaries(PREAUTH))
        with self.assertRaisesRegex(EngineError, 'Release pre-authorization must match policy.release'):
            self.engine.arm_autonomy()

    def test_arm_refuses_malformed_release_line(self):
        bad = ['- Release: pre-authorized origin', '- Release: pre-authorized devops main extra', '- Release: allowed',
               '- Release:', '- Release: no release, permit or deploy', '- Release: pre-authorized  ']
        for line in bad:
            with self.subTest(line=line):
                self.ledger(boundaries=self.boundaries(line))
                with self.assertRaisesRegex(EngineError, 'Approval boundaries need exactly one Release line'):
                    self.engine.arm_autonomy()
        for pair in ([AUTONOMY_FIXED[0], PREAUTH], [PREAUTH, PREAUTH]):
            with self.subTest(pair=pair):
                self.ledger(boundaries=[*pair, *AUTONOMY_FIXED[1:]])
                with self.assertRaisesRegex(EngineError, 'Approval boundaries need exactly one Release line'):
                    self.engine.arm_autonomy()

    def test_ledger_with_both_release_lines_refused(self):
        self.ledger(boundaries=[*AUTONOMY_FIXED, PREAUTH])
        with self.assertRaisesRegex(EngineError, 'Approval boundaries need exactly one Release line'):
            self.engine.arm_autonomy()
        self.assertIsNone(self.auto())

    def test_arm_from_shipped_template_accepts_fixed_release_line(self):
        template = (Path(__file__).resolve().parents[1] / 'plugins/orchestra/config/autonomy-template.md').read_text()
        filled = (template.replace('<one line goal>', 'ship the fixture')
                  .replace('<ISO 8601 time with a UTC offset, in the future>', iso(T0 + 3600))
                  .replace('<NAME: argv...>', 'fixture: ' + shlex.join(PASS_ARGV)))
        self.assertIn(AUTONOMY_FIXED[0], filled)
        (self.state / 'autonomy.md').write_text(filled)
        self.assertTrue(self.engine.arm_autonomy()['active'])
        self.assertNotIn('release', self.auto())
        (self.state / 'autonomy.md').write_text(filled.replace(AUTONOMY_FIXED[0], PREAUTH))
        self.assertTrue(self.engine.arm_autonomy()['active'])
        self.assertEqual(self.auto()['release'], dict(remote='devops', target='main'))

    def test_preauthorization_keeps_the_other_fixed_lines_required(self):
        for line in AUTONOMY_FIXED[1:]:
            with self.subTest(line=line):
                self.ledger(boundaries=[l for l in self.boundaries(PREAUTH) if l != line])
                with self.assertRaisesRegex(EngineError, 'Approval boundaries must keep the fixed line'):
                    self.engine.arm_autonomy()


class RelaunchTests(AutonomyFixture, HoldFixture):
    """SPEC 5.10 items 1 to 4 and 5.4 to 6, 5.8 item 7, 5.9 item 2: autonomy that survives the end of a session."""

    def arm_relaunch(self, **kw):
        self.ledger(**kw)
        return self.engine.arm_autonomy(relaunch=True)

    def end_session(self):
        self.engine.interrupt('main', self.lease)

    def last_brief(self):
        return self.engine.status()['last_brief']

    def test_relaunch_autonomy_survives_session_end(self):
        self.engine.interrupt('main', self.lease)
        self.engine.open_session('main', harness_session='S')
        self.arm_relaunch()
        self.assertTrue(self.auto()['relaunch'])
        self.assertTrue(self.engine.end_harness_session('S'))
        self.assertFalse(self.engine.status()['session']['active'])
        self.assertEqual((self.auto()['active'], self.auto()['relaunch']), (True, True))
        self.assertTrue(self.engine.autonomy_active())  # no session, still armed (SPEC 5.10 item 3)
        self.assertTrue(self.engine.autonomy_status()['active'])

    def test_relaunch_autonomy_survives_interrupt(self):
        self.arm_relaunch()
        self.engine.interrupt('main', self.lease)
        self.assertEqual((self.auto()['active'], self.engine.status()['session']['active']), (True, False))
        self.engine.open_session('main')
        self.assertTrue(self.engine.interrupt_active())
        self.assertEqual((self.auto()['active'], self.engine.status()['session']['active']), (True, False))
        self.assertTrue(self.engine.autonomy_active())

    def test_close_session_under_relaunch_stops_complete_with_brief(self):
        self.arm_relaunch()
        self.engine.close_session('main', self.lease)
        self.assertEqual((self.auto()['active'], self.auto()['last_stop_reason']), (False, 'complete'))
        self.assertEqual(self.last_brief()['reason'], 'complete')
        self.assertIn('stop reason: complete', (self.state / 'progress.md').read_text())
        self.assertEqual(self.engine.autonomy_report()['reason'], 'complete')
        self.assertFalse(self.engine.autonomy_active())

    def test_close_session_brief_reason_by_mode(self):
        self.fresh(None)
        self.engine.close_session('main', self.lease)  # unarmed
        self.assertEqual(self.last_brief()['reason'], 'closed')
        self.fresh(None)
        self.ledger()
        self.engine.arm_autonomy()  # in-session autonomy, as in 2.1
        self.engine.close_session('main', self.lease)
        self.assertEqual(self.last_brief()['reason'], 'closed')
        self.assertIsNone(self.auto())
        self.fresh(None)
        self.arm_relaunch()
        self.engine.close_session('main', self.lease)
        self.assertEqual(self.last_brief()['reason'], 'complete')
        self.assertEqual((self.auto()['active'], self.auto()['last_stop_reason']), (False, 'complete'))

    def test_non_relaunch_autonomy_cleared_on_session_end(self):
        self.ledger()
        self.engine.arm_autonomy()
        self.assertNotIn('relaunch', self.auto())
        self.engine.interrupt('main', self.lease)
        self.assertIsNone(self.auto())
        self.engine.open_session('main', harness_session='S')
        self.ledger()
        self.engine.arm_autonomy()
        self.engine.end_harness_session('S')
        self.assertIsNone(self.auto())
        self.assertFalse(self.engine.autonomy_active())

    def test_settle_stops_on_deadline_between_passes(self):
        self.arm_relaunch(deadline=iso(T0 + 60))
        self.task('x')
        self.end_session()
        self.assertEqual(self.engine.settle(), dict(armed=True, stopped=False, reason=None, signature=self.engine.autonomy_status()['signature'],
                                                    passes=0, stalls=0))
        self.assertEqual(self.auto()['passes'], 0)  # settle never counts a pass
        self.now[0] = T0 + 61
        result = self.engine.settle()
        self.assertEqual((result['armed'], result['stopped'], result['reason']), (False, True, 'deadline'))
        self.assertEqual(self.last_brief()['reason'], 'deadline')
        self.assertIn('stop reason: deadline', (self.state / 'progress.md').read_text())
        self.assertEqual(self.engine.settle()['reason'], 'deadline')  # a stopped run reports its stop again
        self.assertEqual(self.engine.settle()['stopped'], True)

    def test_settle_without_autonomy_writes_nothing(self):
        before = self.engine.state_path.read_bytes()
        result = self.engine.settle()
        self.assertEqual((result['armed'], result['stopped'], result['reason'], result['passes']), (False, False, None, None))
        self.assertRegex(result['signature'], r'^[0-9a-f]{64}$')
        self.assertEqual(before, self.engine.state_path.read_bytes())

    def test_settle_unarmed_does_not_write_state(self):
        self.task('x')
        before = (self.engine.state_path.read_bytes(), self.engine.state_path.stat().st_mtime_ns,
                  self.engine.state_path.stat().st_ino)
        result = self.engine.settle()
        self.assertEqual((False, False, None), (result['armed'], result['stopped'], result['reason']))
        after = (self.engine.state_path.read_bytes(), self.engine.state_path.stat().st_mtime_ns,
                 self.engine.state_path.stat().st_ino)
        self.assertEqual(before, after)

    def test_settle_stops_idle_and_on_a_tampered_ledger(self):
        self.arm_relaunch()
        self.end_session()
        result = self.engine.settle()  # nothing ready, nothing live, nothing parked
        self.assertEqual((result['stopped'], result['reason']), (True, 'no-ready-card'))
        self.engine.open_session('main')
        self.arm_relaunch()
        (self.state / 'autonomy.md').write_text((self.state / 'autonomy.md').read_text() + '- extra\n')
        self.assertEqual(self.engine.settle()['reason'], 'ledger-tampered')

    def test_settle_parked_only_when_held_and_parked(self):
        self.arm_relaunch()
        self.blocked_chain()
        self.engine.hold('main', self.lease, 'R1', 'g')
        self.task('P')
        self.engine.park('main', self.lease, 'P', 'needs a push')
        self.end_session()
        result = self.engine.settle()
        self.assertEqual((result['armed'], result['stopped'], result['reason']), (False, True, 'parked-only'))
        text = self.last_brief()['text']
        self.assertEqual(self.last_brief()['reason'], 'parked-only')
        needs = text[text.index('### Needs you'):]
        self.assertIn('P: needs a push', needs)
        self.assertIn('R1 (chain R1, B1)', needs)

    def test_settle_held_alone_continues(self):
        self.arm_relaunch()
        self.blocked_chain()
        self.engine.hold('main', self.lease, 'R1', 'g')
        self.end_session()
        result = self.engine.settle()
        self.assertEqual((result['armed'], result['stopped'], result['passes']), (True, False, 0))

    def test_hook_stop_without_session_under_relaunch_is_noop(self):
        self.arm_relaunch()
        self.task('x')
        self.end_session()
        before = self.engine.state_path.read_bytes()
        self.assertIsNone(self.engine.hook_stop())
        self.assertEqual(before, self.engine.state_path.read_bytes())
        self.assertEqual((self.auto()['passes'], self.auto()['stalls'], self.auto()['active']), (0, 0, True))

    def test_hook_stop_inside_a_relaunch_pass_counts_but_continues_nothing(self):
        self.arm_relaunch(deadline=iso(T0 + 60))
        self.task('x')
        self.assertIsNone(self.engine.hook_stop())  # the harness is the loop
        self.assertIsNone(self.engine.hook_stop())
        self.assertEqual((self.auto()['passes'], self.auto()['active']), (2, True))
        self.now[0] = T0 + 61
        self.assertIsNone(self.engine.hook_stop())
        self.assertEqual((self.auto()['active'], self.auto()['last_stop_reason']), (False, 'deadline'))

    def test_end_pass_session_checks_nonce_and_writes_ended_brief(self):
        self.engine.interrupt('main', self.lease)
        self.engine.open_session('main', relaunch_pass='n-1')
        self.assertEqual(self.engine.status()['session']['relaunch_pass'], 'n-1')
        self.arm_relaunch()
        for wrong in ('n-2', '', None):
            with self.subTest(nonce=wrong):
                with self.assertRaisesRegex(EngineError, 'nonce'):
                    self.engine.end_pass_session(wrong)
                self.assertTrue(self.engine.status()['session']['active'])
        result = self.engine.end_pass_session('n-1')
        self.assertEqual(result['reason'], 'ended')
        session = self.engine.status()['session']
        self.assertEqual((session['active'], session['outcome']), (False, 'pass-exited'))
        self.assertTrue(self.auto()['active'])
        self.assertEqual(self.last_brief()['reason'], 'ended')
        with self.assertRaises(EngineError):  # nothing left to end
            self.engine.end_pass_session('n-1')

    def test_end_pass_session_leaves_a_session_without_the_nonce(self):
        self.arm_relaunch()  # the fixture session carries no relaunch_pass
        with self.assertRaisesRegex(EngineError, 'nonce'):
            self.engine.end_pass_session('n-1')
        self.assertTrue(self.engine.status()['session']['active'])

    def test_end_pass_session_keeps_a_stopped_autonomy_brief(self):
        self.engine.interrupt('main', self.lease)
        self.engine.open_session('main', relaunch_pass='n-1')
        self.arm_relaunch(deadline=iso(T0 + 60))
        self.now[0] = T0 + 61
        self.assertIsNone(self.engine.hook_stop())
        self.assertEqual(self.last_brief()['reason'], 'deadline')
        self.engine.end_pass_session('n-1')
        self.assertEqual(self.last_brief()['reason'], 'deadline')  # kept stop brief (SPEC 5.9 item 2)
        self.assertEqual(self.engine.autonomy_report()['reason'], 'deadline')
        self.assertIn('stop reason: ended', (self.state / 'progress.md').read_text())

    def test_open_session_takes_pass_nonce_from_marker_without_env(self):
        marks = self.state / 'relaunch'
        marks.mkdir()
        self.arm_relaunch()
        self.end_session()
        (marks / 'pass-abc123.marker').write_text('')
        self.engine.open_session('main')
        self.assertEqual(self.engine.status()['session']['relaunch_pass'], 'abc123')
        self.engine.interrupt_active()
        self.engine.open_session('main', relaunch_pass='from-env')  # the env nonce wins
        self.assertEqual(self.engine.status()['session']['relaunch_pass'], 'from-env')
        self.engine.interrupt_active()
        (marks / 'pass-def456.marker').write_text('')  # two markers: none is stored
        self.engine.open_session('main')
        self.assertNotIn('relaunch_pass', self.engine.status()['session'])
        self.engine.interrupt_active()
        (marks / 'pass-def456.marker').unlink()
        (marks / 'pass-abc123.marker').unlink()  # no marker: none is stored
        self.engine.open_session('main')
        self.assertNotIn('relaunch_pass', self.engine.status()['session'])

    def test_open_session_ignores_malformed_env_pass_nonce(self):
        """SPEC 5.10 item 5.3: the env nonce takes the marker-name check; a malformed one stores no nonce."""
        marks = self.state / 'relaunch'
        marks.mkdir()
        self.arm_relaunch()
        self.end_session()
        (marks / 'pass-abc123.marker').write_text('')
        for bad in ('../x', 'a b', 'n;rm', 'x\n'):
            self.engine.open_session('main', relaunch_pass=bad)
            self.assertNotIn('relaunch_pass', self.engine.status()['session'], bad)
            self.engine.interrupt_active()
        self.engine.open_session('main', relaunch_pass='ok_Nonce-1')
        self.assertEqual(self.engine.status()['session']['relaunch_pass'], 'ok_Nonce-1')

    def test_open_session_ignores_a_marker_when_relaunch_is_not_armed(self):
        marks = self.state / 'relaunch'
        marks.mkdir()
        (marks / 'pass-abc123.marker').write_text('')
        self.ledger()
        self.engine.arm_autonomy()  # in-session autonomy, not relaunch
        self.engine.interrupt('main', self.lease)
        self.engine.open_session('main')
        self.assertNotIn('relaunch_pass', self.engine.status()['session'])

    def test_open_session_still_refuses_while_a_session_is_active(self):
        self.arm_relaunch()
        with self.assertRaisesRegex(EngineError, 'already active'):
            self.engine.open_session('main', relaunch_pass='n')
