"""Durable workflow consistency checks, not a hostile-worker security boundary."""
from __future__ import annotations

import contextlib
import copy
from . import portable
import hashlib
import json
import os
import math
import re
import shlex
import shutil
import signal
from pathlib import Path
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone

from .guards import classify_command


ACTIVE_MISMATCH = ('Repository or policy changed while a run is active, so a new run is refused. '
                   'End it with the version that started it, or move state.json out of the state '
                   'directory (README, Upgrade from 2.3 to 2.4)')


class EngineError(ValueError):
    pass



class StateBusy(EngineError):
    """The state lock stayed held past `lock_wait` (SPEC 5.16 item 3)."""

REVIEW_ROLES = ('code-reviewer', 'critic')
CATEGORIES = ['requirements', 'correctness', 'security', 'tests', 'architecture', 'standards', 'cleanup']
REBIND_WINDOW_SECONDS = 60
KEEP_REMOVE = ('## Keep', '## Remove')  # builder briefs carry both headings; checked at add only (SPEC 5.13)
PACKAGE_ROOT = Path(__file__).resolve().parents[2]
ALWAYS_LENSES = ('requirements', 'correctness', 'tests', 'architecture')
INLINE_MAX_ITEMS = 5  # contract item 3: 1 to 5 items run inline, 6 or more go through a plan
SIZES = ('tiny', 'medium', 'large')
TIER_GUIDE = {'tiny': 50, 'medium': 400}  # contract item 1: changed lines per ask
CARD_SIZES = ('tiny', 'medium')  # a card's own size; a large run sizes its cards as one of these
REVIEWER_BAND = (400, 'medium', 'orchestra:code-reviewer-medium')
REVIEWER_FULL = ('full', 'orchestra:code-reviewer')
ASKS_ERROR = '--asks must be an integer, 1 or more'
SELF_REVIEW_ERROR = 'Builder report needs one SELF_REVIEW line'
DEFAULT = dict(max_workers=20, required_checks=[], gate_timeout_seconds=300,
               secret_scan=dict(required=False, argv=[]),
               release=dict(enabled=False, remote=None, target=None, argv=[]),
               sensitive_paths=['**/auth/**', '**/security/**', '**/*secret*', '**/hooks/**', '**/guard*',
                                '**/migrations/**', '.github/**'],
               standards_min_lines=200)
# Contract item 3: a run started by 2.3 binds the hash 2.3 computed: its DEFAULT and its role-to-modes digest.
DEFAULT_2_3 = dict(max_workers=20, required_checks=[], required_review_categories=CATEGORIES,
                   gate_timeout_seconds=300, secret_scan=dict(required=False, argv=[]),
                   release=dict(enabled=False, remote=None, target=None, argv=[]))
CONTRACT_HASH_2_3 = '7e12cdf268d85df0aac178c92f1577a3ce2ffbf686fbc536204b4677dfe3a942'


def _contracts():
    """The role-to-modes map binds a run. Method files must exist but their text does not bind it."""
    try:
        path = PACKAGE_ROOT / 'config/roles.json'
        raw = path.read_bytes()
        roles = json.loads(raw)['roles']
        result = {}
        root = (PACKAGE_ROOT / 'skills').resolve()
        for role in roles:
            name, modes, methods = role['id'], role['modes'], role['methods']
            if (not isinstance(name, str) or name in result or not modes or not methods
                    or not all(isinstance(v, str) and v.strip() for v in modes + methods)):
                raise ValueError('Invalid role contract')
            result[name] = modes
            for method in methods:
                target = (root / method).resolve()
                if root not in target.parents or not target.is_file():
                    raise ValueError('Missing required method: ' + method)
        digest = _digest(result)  # every role, the orchestrator included, binds the run
        result.pop('orchestrator', None)  # but a task never takes the orchestrator role
        return result, digest
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise EngineError('Invalid canonical role/method contract: ' + str(exc)) from exc


AUTONOMY_TEMPLATE = PACKAGE_ROOT / 'config' / 'autonomy-template.md'
AUTONOMY_FIXED = (
    '- Release: no release, permit or deploy.',
    '- Merge: no pull request merge, and no local merge on the default branch.',
    '- Push: no push to any branch.',
    '- Deletion: no deletion of files, branches or tags.',
    '- Credential entry: never enter credentials.',
    '- Engine-gated actions: nothing that needs a permit.',
)
AUTONOMY_KEEP_AWAKE = 'User step: enable keep-awake in Claude Desktop (or keep the machine awake) for an overnight run.'
CLAUDE_PROMPT_FREE_MODES = ('bypassPermissions', 'dontAsk', 'auto')
PARKABLE = ('queued', 'running', 'reported')
DISPOSITIONS = dict(finding=('rejected', 'deferred', 'inline', 'card', 'brief'),
                    out_of_scope=('inline', 'card', 'brief'))  # SPEC 5.12 item 1
TASK_STATES = ('queued', 'running', 'reported', 'repairing', 'accepted', 'parked', 'held')


def _append_progress(state_dir, text):
    """Append one entry to progress.md: one O_APPEND open and one write of the whole entry (SPEC 5.9 item 5)."""
    path = Path(state_dir) / 'progress.md'
    try:
        old = path.read_bytes()
    except OSError:
        old = b''
    gap = '' if not old.strip() else ('' if old.endswith(b'\n') else '\n')
    entry = (gap + text + ('' if text.endswith('\n') else '\n')).encode()
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        os.write(fd, entry)
    finally:
        os.close(fd)


def write_busy_brief(state_dir, at):
    """SPEC 5.16 item 5: a `state busy` brief appended to progress.md without touching state.json."""
    if not isinstance(at, str):
        at = datetime.fromtimestamp(at, timezone.utc).isoformat(timespec='seconds')
    _append_progress(state_dir, '\n'.join([
        '## Run brief ' + at, '', '- stop reason: state busy',
        '- Orchestra state stayed locked past the Stop hook budget; the run was left as it was. Retry or run `brief`.']))


def _fingerprint(text):
    """SHA-256 of the text with whitespace collapsed (N5), so a reworded layout keeps its triage."""
    return hashlib.sha256(' '.join(text.split()).encode()).hexdigest()


def _section(text, title):
    start = re.search(r'^##[ \t]+' + re.escape(title) + r'[ \t]*$', text, re.M)
    if not start:
        return None
    rest = text[start.end():]
    end = re.search(r'^##[ \t]', rest, re.M)
    return rest[:end.start()] if end else rest


def parse_ledger(text, now):
    """Parse the autonomy ledger (SPEC 12.2); every refusal names the field."""
    text = text.replace('\r\n', '\n')  # A ledger saved with CRLF line endings (Windows editors) parses the same.
    fields = {}
    for name in ('goal', 'max_passes', 'max_stalls', 'deadline'):
        match = re.search(r'^' + name + r':[ \t]*(.*?)[ \t]*$', text, re.M)
        if not match and name in ('max_passes', 'max_stalls'):
            continue  # SPEC 5.8 item 5: a 2.1 cap is optional, recorded and never enforced
        if not match or not match.group(1):
            raise EngineError('Ledger field %s is missing or empty' % name)
        if re.fullmatch(r'<.*>', match.group(1)):
            raise EngineError('Ledger field %s still holds its template placeholder' % name)
        fields[name] = match.group(1)
    for name, top in (('max_passes', 20), ('max_stalls', 2)):
        if name not in fields:
            continue
        if not re.fullmatch(r'[0-9]{1,6}', fields[name]) or not 1 <= int(fields[name]) <= top:
            raise EngineError('Ledger field %s must be an integer from 1 to %d' % (name, top))
        fields[name] = int(fields[name])
    try:
        when = datetime.fromisoformat(fields['deadline'])
    except ValueError:
        raise EngineError('Ledger field deadline must be ISO 8601 with a UTC offset') from None
    if when.utcoffset() is None:
        raise EngineError('Ledger field deadline needs a UTC offset')
    if when.timestamp() <= now:
        raise EngineError('Ledger field deadline must be in the future')
    checks, names = [], set()
    for raw in (_section(text, 'Completion checks') or '').splitlines():
        line = raw.strip()
        if line.startswith('- '):
            line = line[2:].strip()
        if not line or line.startswith('>'):
            continue
        if re.fullmatch(r'<.*>', line):
            raise EngineError('Completion checks still hold a template placeholder')
        name, colon, rest = line.partition(':')
        name = name.strip()
        try:
            argv = shlex.split(rest)
        except ValueError:
            argv = []
        if not colon or not re.fullmatch(r'[A-Za-z0-9._-]+', name) or not argv:
            raise EngineError('Completion checks line is not NAME: argv...: ' + line)
        if name in names:
            raise EngineError('Completion checks repeat the name ' + name)
        names.add(name)
        checks.append(dict(name=name, argv=argv))
    if not checks:
        raise EngineError('Completion checks need at least one NAME: argv... line')
    lines = [line.strip() for line in (_section(text, 'Approval boundaries') or '').splitlines()]
    boundaries = set(lines)
    releases = [line for line in lines if line.startswith('- Release:')]  # SPEC 5.8 item 8: exactly one, fixed or pre-authorized
    pair = re.fullmatch(r'- Release: pre-authorized ([^\s]+) ([^\s]+)', releases[0]) if len(releases) == 1 else None
    if len(releases) != 1 or (releases[0] != AUTONOMY_FIXED[0] and not pair):
        raise EngineError('Approval boundaries need exactly one Release line')
    for line in AUTONOMY_FIXED[1:]:
        if line not in boundaries:
            raise EngineError('Approval boundaries must keep the fixed line: ' + line)
    caps = {k: fields[k] for k in ('max_passes', 'max_stalls') if k in fields}
    release = dict(release=dict(remote=pair.group(1), target=pair.group(2))) if pair else {}
    return dict(goal=fields['goal'], deadline=fields['deadline'], checks=checks, **caps, **release)


def autonomy_preconditions(repo, home=None):
    """Read and report only (SPEC 12.5): never changes a setting, never refuses."""
    home = Path(home) if home else Path.home()
    found = None
    for label, path in (('local project', Path(repo) / '.claude' / 'settings.local.json'),
                        ('project', Path(repo) / '.claude' / 'settings.json'),
                        ('user', home / '.claude' / 'settings.json')):
        try:
            value = json.loads(path.read_text())['permissions']['defaultMode']
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if isinstance(value, str) and value:
            found = (value, label)
            break
    if not found:
        mode = 'unknown (no Claude settings file names permissions.defaultMode); WARNING: prompts may stall an unattended run'
    elif found[0] in CLAUDE_PROMPT_FREE_MODES:
        mode = '%s (%s settings)' % found
    else:
        mode = '%s (%s settings); WARNING: this mode can stall on prompts' % found
    return dict(permission_mode=mode, keep_awake=AUTONOMY_KEEP_AWAKE)


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _digest(value):
    return _hash(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


class Engine:
    def __init__(self, state_dir, repo, policy=None, clock=time.time, lock_wait=None):
        self._clock = clock
        self.lock_wait = lock_wait
        self.repo = Path(repo).resolve()
        self.state_dir = Path(state_dir).resolve()
        for protected in (self.repo, PACKAGE_ROOT.resolve()):
            if self.state_dir == protected or protected in self.state_dir.parents:
                raise EngineError('Run state must live outside the repository and immutable plugin root')
        self.policy = copy.deepcopy(DEFAULT)
        legacy = copy.deepcopy(DEFAULT_2_3)
        if policy:
            self.policy.update(copy.deepcopy(policy))
            legacy.update(copy.deepcopy(policy))
        if isinstance(self.policy['max_workers'], bool) or not isinstance(self.policy['max_workers'], int) or self.policy['max_workers'] < 1:
            raise EngineError('Invalid worker capacity')
        timeout = self.policy['gate_timeout_seconds']
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise EngineError('Gate timeout must be positive and finite')
        for key in ('release', 'secret_scan'):
            if not isinstance(self.policy[key], dict):
                raise EngineError('Invalid policy ' + key)
        if not isinstance(self.policy['required_checks'], list):
            raise EngineError('Invalid required checks')
        categories = self.policy.get('required_review_categories')  # an explicit override of the derived lenses
        if categories is not None and (not isinstance(categories, list) or not categories
                                       or any(not isinstance(c, str) or c not in CATEGORIES for c in categories)):
            raise EngineError('required_review_categories must be a non-empty list of known categories')
        globs = self.policy['sensitive_paths']
        if not isinstance(globs, list) or any(not isinstance(g, str) or not g for g in globs):
            raise EngineError('sensitive_paths must be a list of glob strings')
        minimum = self.policy['standards_min_lines']
        if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 0:
            raise EngineError('standards_min_lines must be a non-negative integer')
        self.modes, self.contract_hash = _contracts()
        self.policy_hash = _digest(dict(policy=self.policy, contracts=self.contract_hash))
        self._policy_hash_2_3 = _digest(dict(policy=legacy, contracts=CONTRACT_HASH_2_3))
        self._git('rev-parse', '--show-toplevel')
        if Path(self._git('rev-parse', '--show-toplevel').decode().strip()).resolve() != self.repo:
            raise EngineError('repo must name repository root')
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_path = self.state_dir / 'state.json'

    def _git(self, *args):
        try:
            return subprocess.check_output(['git', '-C', str(self.repo), *args], stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as exc:
            raise EngineError(exc.stderr.decode(errors='replace')) from exc

    @staticmethod
    def _in_scope(path, scope):
        return any(path == s or path.startswith(s + '/') for s in scope)

    def _file_entries(self, scope=None):
        """[name, value] for every tracked and untracked nonignored entry, limited to `scope` when given."""
        names = self._git('ls-files', '-z', '--cached', '--others', '--exclude-standard').split(b'\0')
        entries = []
        for raw in sorted(set(names) - {b''}):
            if scope is not None and not self._in_scope(os.fsdecode(raw), scope):
                continue
            path = self.repo / os.fsdecode(raw)
            if path.is_symlink():
                value = ['symlink', os.readlink(path)]
            elif path.is_file():
                value = ['file', path.stat().st_mode & 0o777, _hash(path.read_bytes())]
            elif path.is_dir():
                # Gitlinks need their nested HEAD, dirty state and contents bound too.
                value = ['directory', self._directory_hash(path)]
            else:
                value = ['missing']
            entries.append([os.fsdecode(raw), value])
        return entries

    def _entry_digests(self):
        """{path: short digest} of every entry: what a final receipt keeps to tell later which files changed."""
        return {name: _digest(value)[:16] for name, value in self._file_entries()}

    def artifact(self, scope=None):
        """Whole-repo evidence, or with `scope` (repository-relative paths) evidence for those paths plus HEAD."""
        scope = sorted({Path(s).as_posix() for s in scope}) if scope else None
        # Hash every tracked and untracked nonignored entry. Index and status are also bound.
        entries = self._file_entries(scope)
        common = Path(self._git('rev-parse', '--git-common-dir').decode().strip())
        if not common.is_absolute():
            common = self.repo / common
        index = self._git('ls-files', '--stage', '-z')
        status = self._git('status', '--porcelain=v1', '-z', '--untracked-files=all')
        result = dict(repo=str(self.repo), identity=str(common.resolve()),
                      head=self._git('rev-parse', 'HEAD').decode().strip(),
                      tree=self._git('rev-parse', 'HEAD^{tree}').decode().strip(),
                      fingerprint=_digest(entries), index=_hash(index), status=_hash(status),
                      policy=self.policy_hash)
        if scope is not None:
            lines = [l for l in index.split(b'\0') if l and self._in_scope(os.fsdecode(l.split(b'\t', 1)[-1]), scope)]
            changes, parts = [], status.split(b'\0')
            while parts:
                part = parts.pop(0)
                if not part:
                    continue
                paths = [os.fsdecode(part[3:])]
                if part[:1] in b'RC' or part[1:2] in b'RC':
                    paths.append(os.fsdecode(parts.pop(0)) if parts else '')
                if any(self._in_scope(x, scope) for x in paths):
                    changes.append(part)
            result.update(scope=scope, index=_hash(b'\0'.join(lines)), status=_hash(b'\0'.join(changes)))
        return result

    def scope_for(self, task_ids):
        """Union of the tasks' reservation files, or None (whole repo) when any task reserves no files."""
        with self._state(False) as state:
            return self._scope_of(state, task_ids)

    def _scope_of(self, state, task_ids):
        files, whole = set(), False
        for task_id in task_ids:
            if task_id not in state['tasks']:
                raise EngineError('Unknown task: ' + str(task_id))
            reserved = self._reservation(state['tasks'][task_id], state)['files']
            whole = whole or not reserved
            files.update(Path(f).as_posix() for f in reserved)
        return None if whole or not files else sorted(files)

    def _artifact_cached(self, cache, scope):
        key = tuple(scope) if scope else None
        if key not in cache:
            cache[key] = self.artifact(scope)
        return cache[key]

    @staticmethod
    def _directory_hash(path):
        entries = []
        for child in sorted(path.rglob('*')):
            if '.git' in child.relative_to(path).parts:
                continue
            if child.is_symlink():
                entries.append([str(child.relative_to(path)), 'link', os.readlink(child)])
            elif child.is_file():
                entries.append([str(child.relative_to(path)), _hash(child.read_bytes())])
        return _digest(entries)

    @contextlib.contextmanager
    def _state(self, write=True, block=False):
        """`block` makes a read wait for the lock even when `lock_wait` is set (records that must not be dropped)."""
        if _contracts()[1] != self.contract_hash:
            raise EngineError('Role or method instructions changed; start a new run')
        with (self.state_dir / 'state.lock').open('a+') as lock:
            if write or block or self.lock_wait is None:
                portable.flock(lock, portable.LOCK_EX if write else portable.LOCK_SH)
            else:
                end = time.monotonic() + self.lock_wait
                while True:
                    try:
                        portable.flock(lock, portable.LOCK_SH | portable.LOCK_NB)
                        break
                    except OSError:
                        if time.monotonic() >= end:
                            raise StateBusy('Orchestra state is busy; retry') from None
                        time.sleep(0.05)
            if self.state_path.exists():
                try:
                    state = json.loads(self.state_path.read_text())
                    self._validate_state(state)
                except (ValueError, TypeError, KeyError, OSError) as exc:
                    raise EngineError('Malformed run state: ' + str(exc)) from exc
                if state['repo'] != str(self.repo) or not self.binds(state):
                    session = state.get('session')
                    if session is None or (isinstance(session, dict) and session.get('active') is False):
                        raise EngineError('Repository or policy changed; run `start --new-run`')
                    raise EngineError(ACTIVE_MISMATCH)
                state['policy'] = self.policy_hash  # a 2.3 binding is rebound on the next write
            else:
                state = dict(version=1, repo=str(self.repo), policy=self.policy_hash,
                             session=None, tasks={}, reviews=[], gates=[], permits=[], autonomy=None)
            try:
                yield state
            except (KeyError, TypeError, AttributeError, IndexError) as exc:
                raise EngineError('Malformed run state or request: ' + str(exc)) from exc
            if write:
                fd, name = tempfile.mkstemp(dir=self.state_dir, prefix='.state-')
                try:
                    with os.fdopen(fd, 'w') as out:
                        json.dump(state, out, sort_keys=True, indent=2)
                        out.flush()
                        os.fsync(out.fileno())
                    os.replace(name, self.state_path)
                    portable.fsync_dir(self.state_dir)
                finally:
                    if os.path.exists(name):
                        os.unlink(name)

    def binds(self, state):
        """The state's policy hash is this engine's, or the one 2.3 computed for the same policy on a state with no
        `items` or `size` (contract item 3). Any other policy or roles change refuses."""
        session = state.get('session')
        return state.get('policy') == self.policy_hash or (
            state.get('policy') == self._policy_hash_2_3
            and not (isinstance(session, dict) and ('items' in session or 'size' in session)))

    @staticmethod
    def _route_for(items):
        return 'inline' if items <= INLINE_MAX_ITEMS else 'workflow'

    @classmethod
    def _validate_state(cls, state):
        if not isinstance(state, dict) or state.get('version') != 1:
            raise EngineError('Unsupported run state schema')
        for key, kind in [('repo', str), ('policy', str), ('tasks', dict),
                          ('reviews', list), ('gates', list), ('permits', list)]:
            if not isinstance(state.get(key), kind):
                raise EngineError('Invalid run state ' + key)
        brief = state.get('last_brief')
        if brief is not None and (not isinstance(brief, dict)
                                  or any(not isinstance(brief.get(k), str) for k in ('reason', 'at', 'text', 'path'))):
            raise EngineError('Invalid last_brief')
        for key in ('session', 'autonomy'):
            if key not in state or (state[key] is not None and not isinstance(state[key], dict)):
                raise EngineError('Invalid run state ' + key)
        auto = state['autonomy']
        if auto is not None:
            release = auto.get('release')
            if (('relaunch' in auto and not isinstance(auto['relaunch'], bool))
                    or ('release' in auto and (not isinstance(release, dict) or any(
                        not isinstance(release.get(k), str) or not release[k] for k in ('remote', 'target'))))):
                raise EngineError('Invalid autonomy state')
            ints = ('passes', 'stalls', 'armed_gates', 'armed_reviews')
            if (not isinstance(auto.get('active'), bool)
                    or any(k in auto and (isinstance(auto[k], bool) or not isinstance(auto[k], int))
                           for k in ('max_passes', 'max_stalls')) or ('report' in auto and not isinstance(auto['report'], dict))
                    or (auto['active'] and (any(isinstance(auto.get(k), bool) or not isinstance(auto.get(k), int) for k in ints)
                                            or any(not isinstance(auto.get(k), str) for k in ('goal', 'deadline'))
                                            or any(not isinstance(auto.get(k), list) for k in ('checks', 'accepted'))
                                            or not isinstance(auto.get('ledger'), dict)))):
                raise EngineError('Invalid autonomy state')
        session = state['session']
        if session is not None and (not isinstance(session.get('active'), bool)
                or any(not isinstance(session.get(k), str) or not session[k] for k in ('actor', 'lease'))):
            raise EngineError('Invalid session state')
        if session is not None:
            bound = session.get('harness_session')
            if 'harness_session' in session and (not isinstance(bound, str) or not bound):
                raise EngineError('Invalid harness session')
            if 'relaunch_pass' in session and (not isinstance(session['relaunch_pass'], str) or not session['relaunch_pass']):
                raise EngineError('Invalid relaunch pass')
            if 'size' in session or 'asks' in session or 'owner_request' in session:
                log = session.get('route_log', [])
                if ('items' in session or session.get('size') not in SIZES or not cls._asks_ok(session.get('asks'))
                        or not isinstance(session.get('owner_request'), bool) or not isinstance(log, list)
                        or any(not isinstance(e, dict) or e.get('size') not in SIZES or not cls._asks_ok(e.get('asks'))
                               or not isinstance(e.get('reason'), str) or not isinstance(e.get('at'), str) for e in log)):
                    raise EngineError('Invalid session size')
            if 'items' in session:
                if (type(session['items']) is not int or session['items'] < 1
                        or session.get('route') != cls._route_for(session['items'])
                        or not isinstance(session.get('route_log', []), list)
                        or any(not isinstance(e, dict) or type(e.get('items')) is not int
                               or not isinstance(e.get('reason'), str) or not isinstance(e.get('at'), str)
                               for e in session.get('route_log', []))):
                    raise EngineError('Invalid session route')
            if 'base' in session and (not isinstance(session['base'], str) or not session['base']):
                raise EngineError('Invalid session base')
            pending = session.get('pending_rebind')
            if 'pending_rebind' in session and (not isinstance(pending, dict) or not isinstance(pending.get('from'), str)
                    or isinstance(pending.get('at'), bool) or not isinstance(pending.get('at'), (int, float))):
                raise EngineError('Invalid pending rebind')
        for name, task in state['tasks'].items():
            if not isinstance(task, dict) or task.get('id') != name or task.get('state') not in TASK_STATES:
                raise EngineError('Invalid task state')
            for key in ('role', 'mode'):
                if not isinstance(task.get(key), str):
                    raise EngineError('Invalid task ' + key)
            for key in ('inputs', 'acceptance', 'files', 'resources', 'dependencies'):
                if not isinstance(task.get(key), list) or any(not isinstance(v, str) or not v.strip() for v in task[key]):
                    raise EngineError('Invalid task ' + key)
            if any(dep not in state['tasks'] for dep in task['dependencies']):
                raise EngineError('Invalid stored dependency')
            if 'final_round' in task and (type(task['final_round']) is not int or task['final_round'] < 1):
                raise EngineError('Invalid task final_round')
            if 'final_findings' in task and (not isinstance(task['final_findings'], list)
                                             or any(not isinstance(f, str) or not f.strip() for f in task['final_findings'])):
                raise EngineError('Invalid task final_findings')
            if 'held_finding' in task and (not isinstance(task['held_finding'], str) or not task['held_finding'].strip()):
                raise EngineError('Invalid task held_finding')
            if 'helper_reason' in task and (not isinstance(task['helper_reason'], str) or not task['helper_reason'].strip()):
                raise EngineError('Invalid task helper_reason')
            if 'size' in task and task['size'] not in CARD_SIZES:
                raise EngineError('Invalid task size')
            if 'self_review' in task and not cls._self_review_ok(task['self_review']):
                raise EngineError('Invalid task self_review')
        findings = state.get('findings', [])
        if not isinstance(findings, list) or any(
                not isinstance(f, dict) or any(not isinstance(f.get(k), str) for k in ('id', 'fingerprint', 'text', 'reason', 'at'))
                or f.get('disposition') not in DISPOSITIONS['finding'] or not isinstance(f.get('source'), dict)
                for f in findings):
            raise EngineError('Invalid findings state')
        for review in state['reviews']:
            for key in ('out_of_scope', 'gate_receipts'):
                if key in review and (not isinstance(review[key], list) or any(not isinstance(v, str) for v in review[key])):
                    raise EngineError('Invalid reviews state')
            if 'entries' in review and (not isinstance(review['entries'], dict)
                                        or any(not isinstance(k, str) or not isinstance(v, str) for k, v in review['entries'].items())):
                raise EngineError('Invalid reviews state')
        fields = {
            'reviews': {'id': str, 'reviewer': str, 'categories': list, 'tasks': list, 'final': bool,
                        'findings': list, 'artifact': dict, 'action': str, 'path': str, 'source': str, 'sha256': str},
            'gates': {'id': str, 'name': str, 'argv': list, 'exit_code': int, 'artifact': dict,
                      'after': dict, 'action': str, 'path': str, 'sha256': str, 'passed': bool},
            'permits': {'id': str, 'action': str, 'remote': str, 'target': str, 'argv': list,
                        'artifact': dict, 'lease': str},
        }
        for key, schema in fields.items():
            for item in state[key]:
                if not isinstance(item, dict) or any(not isinstance(item.get(k), kind) for k, kind in schema.items()):
                    raise EngineError('Invalid ' + key + ' state')

    def _check_contract(self, task):
        modes, digest = _contracts()
        if digest != self.contract_hash:
            raise EngineError('Role or method instructions changed; start a new run')
        if task['mode'] not in modes.get(task['role'], []):
            raise EngineError('Unavailable role or mode')
        if 'objective' in task and (not isinstance(task['objective'], str) or not task['objective'].strip()):
            raise EngineError('Task objective must be meaningful')
        if 'brief' in task:
            if not isinstance(task['brief'], str) or not task['brief'].strip():
                raise EngineError('Task brief must name a file')
            brief = Path(task['brief'])
            if not brief.is_absolute():
                brief = self.repo / brief
            if not brief.is_file() or not brief.read_bytes().strip():
                raise EngineError('Task brief must be an existing nonempty file')
            if not re.search(r'^Mode:[ \t]+' + re.escape(task['mode']) + r'[ \t]*$', brief.read_text(errors='replace'), re.M):
                raise EngineError('Task brief must carry the line Mode: ' + task['mode'])

    def _check_keep_remove(self, task):
        brief = Path(task['brief'])
        if not brief.is_absolute():
            brief = self.repo / brief
        text = brief.read_text(errors='replace')
        for heading in KEEP_REMOVE:
            if not re.search(r'^' + re.escape(heading) + r'[ \t]*$', text, re.M):
                raise EngineError('Builder brief needs the heading ' + heading)

    @staticmethod
    def _redact_leases(value):
        if isinstance(value, dict):
            return {k: Engine._redact_leases(v) for k, v in value.items() if k != 'lease'}
        if isinstance(value, list):
            return [Engine._redact_leases(v) for v in value]
        return value

    def status(self, lenses=False):
        """The run state without any lease: the board and `where` never see one (SPEC 11.2). `lenses` adds
        `required_lenses`, which reads the diff; the hooks never ask for it."""
        with self._state(False) as state:
            result = self._redact_leases(copy.deepcopy(state))
            if lenses:
                result['required_lenses'] = self._required_lenses(state)
            return result

    def current_gate_ids(self):
        """Ids of the passed gate receipts for the current whole-repository artifact; [] when there are none."""
        with self._state(False) as state:
            gates = [g for g in state['gates'] if g['passed']]
        if not gates:
            return []
        artifact = self.artifact()
        return [g['id'] for g in gates if g['artifact'] == artifact and self._intact(g)]

    @staticmethod
    def _glob_regex(glob):
        out, i = [], 0
        while i < len(glob):
            if glob.startswith('**/', i):
                out.append('(?:.*/)?')
                i += 3
            elif glob.startswith('/**', i) and i + 3 == len(glob):
                out.append('/.*')
                i += 3
            elif glob.startswith('**', i):
                out.append('.*')
                i += 2
            elif glob[i] == '*':
                out.append('[^/]*')
                i += 1
            elif glob[i] == '?':
                out.append('[^/]')
                i += 1
            else:
                out.append(re.escape(glob[i]))
                i += 1
        return re.compile(''.join(out))

    def _changed(self, base):
        """(paths, changed line count) from the run's base commit to the working tree, untracked files included."""
        paths, lines = set(), 0
        for row in self._git('diff', '--numstat', '-z', '--no-renames', base, '--').split(b'\0'):
            if row:
                added, deleted, name = row.decode(errors='replace').split('\t', 2)
                paths.add(name)
                lines += (int(added) + int(deleted)) if added.isdigit() and deleted.isdigit() else 0
        for raw in self._git('ls-files', '-z', '--others', '--exclude-standard').split(b'\0'):
            if raw:
                name = os.fsdecode(raw)
                paths.add(name)
                path = self.repo / name
                if path.is_file() and not path.is_symlink():
                    data = path.read_bytes()
                    lines += len(data.splitlines())
        return sorted(paths), lines

    def prepr(self):
        """Contract item 7: the pre-PR size check and reviewer choice. Read-only, no lease."""
        with self._state(False) as state:
            session = state['session'] or {}
            base = session.get('base')
            lenses = self._required_lenses(state)
            lines = self._changed(base)[1] if base is not None else None
        size, asks = session.get('size'), session.get('asks')
        budget = TIER_GUIDE[size] * asks if size in TIER_GUIDE else None
        over = budget is not None and lines is not None and lines > budget
        bound, *band = REVIEWER_BAND
        reviewer, agent = band if lines is not None and lines <= bound else REVIEWER_FULL
        warning = ('Size warning: declared %s with %d ask(s) budgets %d changed lines; the diff has %d. Run route --size TIER '
                   '--reason TEXT if the work grew.' % (size, asks, budget, lines)) if over else None
        return dict(base=base, changed_lines=lines, size=size, asks=asks, budget=budget, over_budget=over,
                    reviewer=reviewer, agent=agent, lenses=lenses, warning=warning)

    def _required_lenses(self, state):
        """Contract item 6: the review categories completion needs. An explicit policy list overrides the derived set;
        a run with no stored base (made by 2.3) needs every category."""
        explicit = self.policy.get('required_review_categories')
        if explicit is not None:
            return list(explicit)
        base = (state['session'] or {}).get('base')
        if base is None:
            return list(CATEGORIES)
        paths, lines = self._changed(base)
        wanted = set(ALWAYS_LENSES)
        if any(self._glob_regex(g).fullmatch(p) for g in self.policy['sensitive_paths'] for p in paths):
            wanted.add('security')
        if lines > self.policy['standards_min_lines']:
            wanted.update(('standards', 'cleanup'))
        return [c for c in CATEGORIES if c in wanted]

    @staticmethod
    def _lease(state, actor, lease):
        session = state['session']
        if not session or not session['active'] or session['actor'] != actor or session['lease'] != lease:
            raise EngineError('Invalid or interrupted coordinator lease')

    def validate_lease(self, actor, lease):
        """Check coordinator consistency; caller identifiers are not authentication."""
        with self._state(False) as state:
            self._lease(state, actor, lease)

    def _marker_nonce(self):
        """SPEC 5.10 item 5.3: the nonce of the single `<state>/relaunch/pass-<nonce>.marker`; none, or several, is None."""
        names = [p.name for p in (self.state_dir / 'relaunch').glob('pass-*.marker')]
        nonce = names[0][len('pass-'):-len('.marker')] if len(names) == 1 else None
        return nonce if nonce and re.fullmatch(r'[A-Za-z0-9_-]+', nonce) else None

    @staticmethod
    def _asks_ok(asks):
        return type(asks) is int and asks >= 1

    @classmethod
    def _check_start(cls, size, asks, owner_request):
        """Contract item 2: what a new run must state. The CLI runs it before archiving an ended run."""
        if size is None:
            raise EngineError('A new run needs --size tiny, medium or large')
        if size not in SIZES:
            raise EngineError('Size must be tiny, medium or large')
        if asks is not None and not cls._asks_ok(asks):
            raise EngineError(ASKS_ERROR)
        if size == 'large' and not owner_request:
            raise EngineError('A new run starts at tiny or medium; escalate with route --size large --reason TEXT, '
                              'or pass --owner-request when the owner asked for a map')

    @staticmethod
    def _check_items(items):
        if isinstance(items, bool) or not isinstance(items, int) or items < 1:
            raise EngineError('Items must be an integer of 1 or more')

    def open_session(self, actor, harness_session=None, relaunch_pass=None, items=None, size=None, asks=None,
                     owner_request=False, require_size=False):
        """Open the coordinator session. A new run (no earlier session record) stores `size`, `asks`, `owner_request` and
        `base` (a 2.4 test run stores `items` and `route`); a resumed run keeps them. `require_size` is the CLI's rule that
        a new run states its size (contract items 2 and 3)."""
        if not isinstance(actor, str) or not actor.strip():
            raise EngineError('Missing coordinator')
        if items is not None:
            self._check_items(items)
            if size is not None:
                raise EngineError('Invalid session size')
        if harness_session is not None and (not isinstance(harness_session, str) or not harness_session.strip()):
            raise EngineError('Invalid harness session id')
        if relaunch_pass is not None and (not isinstance(relaunch_pass, str) or not relaunch_pass.strip()):
            raise EngineError('Invalid relaunch pass nonce')
        with self._state() as state:
            if state['session'] and state['session']['active']:
                raise EngineError('A coordinator session is already active')
            lease = uuid.uuid4().hex
            prior = state['session']
            if prior is not None and items is not None:
                raise EngineError('--items applies only to a new run; use route to change it')
            if prior is not None and (size is not None or asks is not None or owner_request):
                raise EngineError('--size, --asks and --owner-request apply to a new run; use start --new-run, or route --size '
                                  'to change the tier')
            if prior is None and items is None and (require_size or size is not None or asks is not None or owner_request):
                self._check_start(size, asks, owner_request)
            state['session'] = dict(actor=actor, lease=lease, active=True)
            if prior is None:
                state['session']['base'] = self._git('rev-parse', 'HEAD').decode().strip()
                if items is not None:
                    state['session'].update(items=items, route=self._route_for(items), route_log=[])
                elif size is not None:
                    state['session'].update(size=size, asks=1 if asks is None else asks, owner_request=bool(owner_request),
                                            route_log=[])
            else:
                for key in ('base', 'items', 'route', 'route_log', 'size', 'asks', 'owner_request'):
                    if key in prior:
                        state['session'][key] = prior[key]
            if harness_session is not None:
                state['session']['harness_session'] = harness_session
            auto = state['autonomy']
            if relaunch_pass is None and auto and auto['active'] and auto.get('relaunch'):
                relaunch_pass = self._marker_nonce()  # the environment may not reach the pass's tool calls (K11)
            if relaunch_pass is not None and re.fullmatch(r'[A-Za-z0-9_-]+', relaunch_pass):
                state['session']['relaunch_pass'] = relaunch_pass
            for task in state['tasks'].values():
                if task['state'] == 'running':
                    task['state'] = 'queued'
                    task.pop('assignment', None)
                    task.pop('report', None)
            state['permits'] = []
            return lease

    def set_route(self, actor, lease, items, reason, size=None, asks=None):
        """Change the tier (`size`, `asks`) of a size run, or the item count and the route it implies of a 2.4 run, and log
        why (contract items 3 and 4). Exactly one of `items` and `size`."""
        if (items is None) == (size is None):
            raise EngineError('Route needs exactly one of --size or --items')
        if size is None:
            self._check_items(items)
        elif size not in SIZES:
            raise EngineError('Size must be tiny, medium or large')
        if asks is not None and (size is None or not self._asks_ok(asks)):
            raise EngineError(ASKS_ERROR)
        if not isinstance(reason, str) or not reason.strip():
            raise EngineError('Route needs a reason')
        with self._state() as state:
            self._lease(state, actor, lease)
            session = state['session']
            at = datetime.fromtimestamp(self._clock(), timezone.utc).isoformat(timespec='seconds')
            if size is not None:
                if 'items' in session:
                    raise EngineError('This run routes by items; use route --items')
                if 'size' not in session:
                    raise EngineError('This run has no route; start a new run with --size')
                session.update(size=size, asks=session['asks'] if asks is None else asks)
                session.setdefault('route_log', []).append(dict(size=size, asks=session['asks'], reason=reason.strip(), at=at))
                return dict(size=size, asks=session['asks'])
            if 'size' in session:
                raise EngineError('This run routes by size; use route --size')
            session.update(items=items, route=self._route_for(items))
            session.setdefault('route_log', []).append(dict(items=items, reason=reason.strip(), at=at))
            return dict(items=items, route=session['route'])

    def interrupt(self, actor, lease):
        with self._state() as state:
            self._lease(state, actor, lease)
            state['session']['active'] = False
            state['permits'] = []
            self._write_brief(state, 'interrupted')
            state['autonomy'] = self._kept_autonomy(state)

    def interrupt_active(self):
        """Interrupt the active session without a caller-supplied lease. Python only, for the Interrupt hook."""
        with self._state(False, block=True) as state:
            if not (state['session'] and state['session']['active']):
                return False  # Read-only unless there is a session to interrupt
        with self._state() as state:
            if not (state['session'] and state['session']['active']):
                return False
            state['session']['active'] = False
            state['permits'] = []
            self._write_brief(state, 'interrupted')
            state['autonomy'] = self._kept_autonomy(state)
            return True

    @staticmethod
    def _stopped_report_kept(state):
        auto = state['autonomy']
        return bool(auto and not auto['active'] and 'report' in auto)

    @staticmethod
    def _kept_autonomy(state):
        """Clear autonomy as today, except a stopped run's morning report stays until the next arm or disarm, and
        armed `relaunch` autonomy survives the end of a session (SPEC 5.10 item 2)."""
        auto = state['autonomy']
        if auto and auto['active'] and auto.get('relaunch'):
            return auto
        return auto if Engine._stopped_report_kept(state) else None

    @staticmethod
    def _bound_to(state, session_id):
        session = state['session']
        return bool(session and session['active'] and session.get('harness_session') == session_id)

    def end_harness_session(self, session_id):
        """The bound harness session ended: what interrupt does, with outcome 'ended'. Idempotent."""
        with self._state(False, block=True) as state:
            if not self._bound_to(state, session_id):
                return False  # A no-op never rewrites state.json
        with self._state() as state:
            if not self._bound_to(state, session_id):
                return False
            state['session'].update(active=False, outcome='ended')
            state['session'].pop('pending_rebind', None)  # harness_session stays as a record
            state['permits'] = []
            self._write_brief(state, 'ended')
            state['autonomy'] = self._kept_autonomy(state)
            return True

    def end_pass_session(self, nonce):
        """SPEC 5.10 item 5.4: the relaunch harness ends the pass's session. No lease, no harness id; refused unless the
        session carries this nonce, which is a cooperative marker and not authentication. Relaunch autonomy stays armed."""
        with self._state() as state:
            session = state['session']
            if not session or not session['active']:
                raise EngineError('No active session to end')
            if not isinstance(nonce, str) or not nonce or session.get('relaunch_pass') != nonce:
                raise EngineError('The active session was not started by this pass: nonce mismatch')
            session.update(active=False, outcome='pass-exited')
            session.pop('pending_rebind', None)
            state['permits'] = []
            self._write_brief(state, 'ended')  # `pass-exited` maps to `ended`; a stopped autonomy brief stays last_brief
            state['autonomy'] = self._kept_autonomy(state)
            return dict(ended=True, reason='ended', relaunch=bool(state['autonomy'] and state['autonomy'].get('relaunch')))

    def mark_harness_rebind(self, session_id):
        """/clear or /resume: the process continues under a new id; record the pending hand-over."""
        with self._state(False) as state:
            if not self._bound_to(state, session_id):
                return False  # A no-op never rewrites state.json
        with self._state() as state:
            if not self._bound_to(state, session_id):
                return False
            state['session']['pending_rebind'] = {'from': session_id, 'at': self._clock()}
            return True

    def apply_harness_rebind(self, session_id):
        """Bind the new id when a fresh pending rebind exists (age 0..60 s); one-shot, stale entries are removed."""
        with self._state(False) as state:
            if not state['session'] or 'pending_rebind' not in state['session']:
                return False  # Read-only unless a rebind is pending (SPEC 12.6)
        with self._state() as state:
            session = state['session']
            pending = session.pop('pending_rebind', None) if session else None
            if pending is None:
                return False
            if not 0 <= self._clock() - pending['at'] <= REBIND_WINDOW_SECONDS:
                return False
            session['harness_session'] = session_id
            return True

    def add_task(self, actor, lease, task):
        task = copy.deepcopy(task)
        with self._state() as state:
            self._lease(state, actor, lease)
            for key in ('id', 'role', 'mode'):
                if not isinstance(task.get(key), str) or not task[key].strip():
                    raise EngineError('Missing task ' + key)
            if task['id'] in state['tasks']:
                raise EngineError('Duplicate task')
            if 'wave' in task:
                raise EngineError('Waves are removed; use dependencies')
            self._check_contract(task)
            if task['role'] == 'designer-planner' and task['mode'] == 'plan' and state['session'].get('route') == 'inline':
                raise EngineError('Inline route: no plan card; the main session groups the work')
            session = state['session']
            if (task['role'] == 'designer-planner' and task['mode'] == 'plan' and 'size' in session
                    and session['size'] != 'large' and not session['owner_request'] and task.get('owner_request') is not True):
                raise EngineError('Plan card needs a large run or an owner request; escalate with route --size large --reason TEXT')
            if 'size' in task and task['size'] not in CARD_SIZES:
                raise EngineError('Invalid task size')
            if task['role'] == 'builder' and 'brief' in task:
                self._check_keep_remove(task)
            if self._is_release(task) and any(self._is_release(t) for t in state['tasks'].values()):
                raise EngineError('A run supports one terminal release task')
            for key in ('inputs', 'acceptance', 'files', 'resources', 'dependencies'):
                values = task.get(key)
                if not isinstance(values, list) or any(not isinstance(v, str) or not v.strip() for v in values):
                    raise EngineError('Invalid task ' + key)
                if key in ('inputs', 'acceptance') and not values:
                    raise EngineError('Empty task ' + key)
                if len(values) != len(set(values)):
                    raise EngineError('Duplicate ' + key)
            for name in task['files']:
                p = Path(name)
                if any(char in name for char in '*?[]'):
                    raise EngineError('File ownership needs explicit paths, not globs')
                if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0] == '.git':
                    raise EngineError('File ownership must stay inside repository')
                resolved = (self.repo / p).resolve()
                if self.repo not in resolved.parents:
                    raise EngineError('File ownership escapes repository')
            if any(dep not in state['tasks'] for dep in task['dependencies']):
                raise EngineError('Unknown dependency or cycle')
            review_of = task.get('review_of', [])
            if (not isinstance(review_of, list)
                    or any(not isinstance(i, str) or i not in state['tasks'] for i in review_of)
                    or len(review_of) != len(set(review_of))):
                raise EngineError('Review targets must name existing tasks')
            if task['role'] == 'code-reviewer' and not review_of:
                raise EngineError('A code-reviewer card needs review_of naming the tasks it reviews')
            if review_of and task['role'] not in REVIEW_ROLES:
                raise EngineError('Only independent review roles can use review_of')
            if set(review_of) & set(task['dependencies']):
                raise EngineError('Use review_of instead of an accepted dependency for reviewed work')
            if task['role'] == 'builder' and task['mode'] == 'repair':
                repair_of = task.get('repair_of')
                if repair_of not in state['tasks'] or state['tasks'][repair_of]['role'] != 'builder':
                    raise EngineError('Repair needs a specific earlier builder task')
                original = state['tasks'][repair_of]
                if original['state'] not in ('reported', 'accepted', 'held') or original.get('repaired_by'):
                    raise EngineError('Repair needs a reported builder without an existing repair')
                if repair_of in task['dependencies']:
                    raise EngineError('repair_of replaces an accepted dependency on the original')
                verdicts = self._review_verdicts(state, {}, task_id=repair_of)
                if not any(self._task_findings(r, repair_of) for r in verdicts.values()):
                    raise EngineError('Repair needs earlier checked coding findings')
                self._check_repair_ladder(state, original)
                final_findings = self._final_findings(state, repair_of)
                if final_findings:
                    task['final_round'] = self._next_final_round(state)
                    task['final_findings'] = final_findings
                # Suspend the whole chain atomically. Reports and workers remain as history,
                # but none of those old assignments reserve capacity or writable files.
                original['repaired_by'] = task['id']
                ancestor = original
                while True:
                    ancestor['state'] = 'repairing'
                    ancestor['review_since'] = len(state['reviews'])
                    if not ancestor.get('repair_of'):
                        break
                    ancestor = state['tasks'][ancestor['repair_of']]
            # Dependencies refer only to existing immutable cards, making cycles impossible.
            task['state'] = 'queued'
            task['rev'] = '2.2'
            task['seq'] = len(state['tasks'])  # state.json is saved with sorted keys, so add order is stored
            state['tasks'][task['id']] = task

    def _check_repair_ladder(self, state, original):
        """The ladder ends in hold (SPEC 5.2 item 4): a repair of a repair, or of a card the repair-diff check
        blocked, needs the chain held or a current final receipt that blames it. 2.1 chains stay valid history."""
        if original['state'] == 'held' or self._final_blocks(state, original['id']):
            return
        if original['mode'] == 'repair':
            raise EngineError('Escalation ends at one repair; hold the chain')
        if self._blocked_by_repair_check(state, original['id']):
            raise EngineError('Repair-diff check blocked %s; hold the chain' % original['id'])

    def _final_receipts(self, state, task_id):
        """The current final receipts for the card. Coverage of cards added since is not required, so a round's
        repairs, added together, each still see the receipts that blame their chains (SPEC 5.5 item 4)."""
        verdicts = self._review_verdicts(state, {}, task_id=task_id)
        return [r for r in {r['id']: r for r in verdicts.values()}.values() if r['final']]

    def _final_blocks(self, state, task_id):
        """A current final receipt with blocking findings attributed to the card."""
        return any(self._task_findings(r, task_id) for r in self._final_receipts(state, task_id))

    def _final_findings(self, state, task_id):
        """The blocking findings current final receipts attribute to the card, in order and without repeats."""
        return list(dict.fromkeys(f for r in self._final_receipts(state, task_id) for f in self._task_findings(r, task_id)))

    @staticmethod
    def _next_final_round(state):
        """SPEC 5.5 item 4: 1 plus the highest `final_round` once a card of that round has reported, else that round; first is 1."""
        rounds = [t['final_round'] for t in state['tasks'].values() if 'final_round' in t]
        if not rounds:
            return 1
        top = max(rounds)
        return top + 1 if any('report' in t for t in state['tasks'].values() if t.get('final_round') == top) else top

    def _blocked_by_repair_check(self, state, task_id):
        """The card's current blocking verdict comes from a repair-diff check (`repair_check: true`, SPEC 5.2 item 2b)."""
        verdicts = self._review_verdicts(state, {}, task_id=task_id)
        return any(r.get('repair_check') and self._task_findings(r, task_id) for r in verdicts.values())

    def hold(self, actor, lease, task_id, finding):
        """End the repair ladder: move the whole chain to `held` and log it (SPEC 5.2 item 2)."""
        if not isinstance(finding, str) or not finding.strip():
            raise EngineError('Hold needs a finding')
        finding = finding.strip()
        with self._state() as state:
            self._lease(state, actor, lease)
            task = state['tasks'].get(task_id)
            if not task or task['role'] != 'builder' or task['state'] != 'reported' or task.get('repaired_by'):
                raise EngineError('Hold needs a reported builder card without an existing repair')
            blocked = any(self._task_findings(r, task_id) for r in self._review_verdicts(state, {}, task_id=task_id).values())
            if not ((task['mode'] == 'repair' and blocked)
                    or (task['mode'] != 'repair' and self._blocked_by_repair_check(state, task_id))):
                raise EngineError('Hold needs a repair card with current blocking findings, '
                                  'or a card blocked by a repair-diff check')
            chain = [task_id]
            while state['tasks'][chain[-1]].get('repair_of'):
                chain.append(state['tasks'][chain[-1]]['repair_of'])
            for ident in chain:
                state['tasks'][ident]['state'] = 'held'
            task['held_finding'] = finding
            at = datetime.fromtimestamp(self._clock(), timezone.utc).isoformat(timespec='seconds')
            _append_progress(self.state_dir, '- held %s (chain %s): %s (at %s)' % (task_id, ', '.join(chain), finding, at))
            return dict(held=chain, finding=finding)

    @staticmethod
    def _is_release(task):
        return task['role'] == 'operator' and task['mode'] == 'release'

    @staticmethod
    def _paths_overlap(xs, ys):
        """The path rule of `_collides`: a path equal to, or a parent of, a path on the other side."""
        return any(x == y or x in y.parents or y in x.parents for x in map(Path, xs) for y in map(Path, ys))

    @staticmethod
    def _collides(a, b):
        if set(a['resources']) & set(b['resources']):
            return True
        return Engine._paths_overlap(a['files'], b['files'])

    @staticmethod
    def _task_findings(receipt, task_id):
        """One receipt's blocking findings for one task (SPEC 5.1 item 4). An absent key is clean."""
        per_task = receipt.get('task_findings')
        return receipt['findings'] if per_task is None else per_task.get(task_id, [])

    @staticmethod
    def _read_review(task):
        return bool(task.get('review_of')) and task['role'] in REVIEW_ROLES

    def park(self, actor, lease, task_id, reason):
        """An approval boundary: set the card aside and release its assignment, reservation and capacity (SPEC 12.4)."""
        if not isinstance(reason, str) or not reason.strip():
            raise EngineError('Parking needs a reason')
        with self._state() as state:
            self._lease(state, actor, lease)
            task = state['tasks'].get(task_id)
            if task and task.get('repaired_by'):  # O30: park the open repair card instead
                raise EngineError('A card under repair cannot be parked; park its open repair card '
                                  + self._open_repair(state, task)['id'])
            if not task or task['state'] not in PARKABLE:
                raise EngineError('Only a queued, running or reported card can be parked')
            task.update(state='parked', parked_reason=reason.strip())
            for key in ('assignment', 'worker', 'lease', 'inline', 'report', 'report_artifact'):
                task.pop(key, None)
            ancestor = task
            while ancestor.get('repair_of'):  # the repair's report is dropped: its chain is under repair again
                ancestor = state['tasks'][ancestor['repair_of']]
                ancestor['state'] = 'repairing'
                ancestor['review_since'] = len(state['reviews'])

    @staticmethod
    def _open_repair(state, task):
        """The last card of a repair chain: the one without `repaired_by`."""
        while task.get('repaired_by'):
            task = state['tasks'][task['repaired_by']]
        return task

    def unpark(self, actor, lease, task_id):
        with self._state() as state:
            self._lease(state, actor, lease)
            task = state['tasks'].get(task_id)
            if not task or task['state'] != 'parked':
                raise EngineError('Task is not parked')
            task['state'] = 'queued'
            task.pop('parked_reason', None)

    @staticmethod
    def _reservation(task, state):
        files, resources = set(task['files']), set(task['resources'])
        while task.get('repair_of'):
            task = state['tasks'][task['repair_of']]
            files.update(task['files'])
            resources.update(task['resources'])
        return dict(files=list(files), resources=list(resources))

    def _ready(self, state):
        occupied = [t for t in state['tasks'].values() if t['state'] == 'running'
                    or (t['state'] == 'reported' and not self._read_review(t))
                    or (t['state'] == 'queued' and t.get('repair_of'))]
        if sum(t['state'] == 'running' for t in occupied) >= self.policy['max_workers']:
            return []
        return [t['id'] for t in state['tasks'].values() if t['state'] == 'queued'
                and all(state['tasks'][d]['state'] in ('accepted', 'held') for d in t['dependencies'])
                and all(state['tasks'][d]['state'] in ('reported', 'accepted', 'held') for d in t.get('review_of', []))
                and not any(other['id'] != t['id']
                            and self._collides(self._reservation(t, state), self._reservation(other, state))
                            and not (other['id'] in t.get('review_of', []) and other['state'] == 'reported'
                                     and not set(t['resources']) & set(other['resources']))
                            and not (self._read_review(t) and self._read_review(other)
                                     and not set(t['resources']) & set(other['resources']))
                            for other in occupied)]

    def ready(self, actor, lease):
        with self._state(False) as state:
            self._lease(state, actor, lease)
            return self._ready(state)

    def dispatch(self, actor, lease, task_id, worker, helper=None):
        return self._start_assignment(actor, lease, task_id, worker, inline=False, helper=helper)

    def start_inline(self, actor, lease, task_id):
        return self._start_assignment(actor, lease, task_id, actor, inline=True)

    @staticmethod
    def _check_route(state, task, inline, helper):
        """Contract item 3. A state with no `route` (made by 2.3) is not checked."""
        session = state['session']
        if task['role'] == 'builder' and 'size' in session:
            size = task.get('size') or ('medium' if session['size'] == 'large' else session['size'])
            if size == 'tiny' and not inline and not (isinstance(helper, str) and helper.strip()):
                raise EngineError('Tiny unit: the main session does this work; pass --helper REASON to dispatch a helper')
            return
        route = session.get('route')
        if route is None or task['role'] != 'builder':
            return
        if route == 'workflow':
            if not any(t['role'] == 'designer-planner' and t['mode'] == 'plan' and t['state'] == 'accepted'
                       for t in state['tasks'].values()):
                raise EngineError('Workflow route: accept the designer-planner plan card first')
        elif not inline and not (isinstance(helper, str) and helper.strip()):
            raise EngineError('Inline route: the main session does this work; pass --helper REASON to dispatch a helper')

    def _start_assignment(self, actor, lease, task_id, worker, inline, helper=None):
        with self._state() as state:
            self._lease(state, actor, lease)
            if not isinstance(worker, str) or not worker.strip() or (worker == actor and not inline):
                raise EngineError('Worker must differ from coordinator')
            task = state['tasks'].get(task_id)
            if inline and task and task['role'] in REVIEW_ROLES:
                raise EngineError('Independent review roles need a separate worker')
            if any(t.get('worker') == worker and t['state'] in ('running', 'reported') for t in state['tasks'].values()):
                raise EngineError('Worker is already reserved')
            if task:
                self._check_route(state, task, inline, helper)
            if task and task['role'] == 'builder' and task['mode'] == 'repair':
                self._check_accept_before_repair(state, task)
            if task_id not in self._ready(state):
                raise EngineError('Task is not ready or capacity is exhausted')
            self._check_contract(state['tasks'][task_id])
            token = uuid.uuid4().hex
            state['tasks'][task_id].update(state='running', worker=worker, assignment=token, lease=lease, inline=inline)
            if isinstance(helper, str) and helper.strip():
                state['tasks'][task_id]['helper_reason'] = helper.strip()
            return token

    def _evidence_scopes(self, state, task_id):
        """The scopes a card's acceptance depends on; None means the whole repository (SPEC 5.1 item 10)."""
        task = state['tasks'][task_id]
        if not task.get('review_required', False):
            return [self._scope_of(state, [task_id])]  # accepted on its own report artifact
        receipts = {r['id']: r for r in self._review_verdicts(state, {}, task_id=task_id).values()}
        return [r.get('scope') for r in receipts.values()]

    def _check_accept_before_repair(self, state, repair):
        """A repair lands in the shared tree: refuse while an acceptable reported card's evidence overlaps it."""
        reserved = self._reservation(repair, state)['files']
        for other in state['tasks'].values():
            if other['state'] != 'reported' or self._accept_refusal(state, {}, other['id']) is not None:
                continue
            if not reserved or any(scope is None or self._paths_overlap(scope, reserved)
                                   for scope in self._evidence_scopes(state, other['id'])):
                raise EngineError('Accept %s first; a repair would make its evidence stale' % other['id'])

    @staticmethod
    def _self_review_ok(review):
        """The SELF_REVIEW shape of contract item 1: non-empty `checks` and `criteria`, each entry well typed."""
        if not isinstance(review, dict):
            return False
        checks, criteria = review.get('checks'), review.get('criteria')
        return (isinstance(checks, list) and bool(checks) and isinstance(criteria, list) and bool(criteria)
                and all(isinstance(c, dict) and isinstance(c.get('command'), str) and c['command'].strip()
                        and type(c.get('exit_code')) is int for c in checks)
                and all(isinstance(c, dict) and isinstance(c.get('criterion'), str) and c['criterion'].strip()
                        and type(c.get('met')) is bool and isinstance(c.get('evidence'), str) for c in criteria))

    @classmethod
    def _parse_self_review(cls, report):
        lines = [line for line in report.splitlines() if line.startswith('SELF_REVIEW: ')]
        if len(lines) != 1:
            raise EngineError(SELF_REVIEW_ERROR)
        try:
            review = json.loads(lines[0][len('SELF_REVIEW: '):])
        except ValueError:
            raise EngineError(SELF_REVIEW_ERROR) from None
        if not cls._self_review_ok(review):
            raise EngineError(SELF_REVIEW_ERROR)
        return review

    def report(self, worker, token, report):
        if not isinstance(report, str) or not report.strip():
            raise EngineError('Empty worker report')
        with self._state() as state:
            task = next((t for t in state['tasks'].values() if t.get('assignment') == token), None)
            replacing = bool(task) and task['state'] == 'reported'  # a repair needs a covering review, refused below
            if not task or task['worker'] != worker or not (task['state'] == 'running' or replacing):
                raise EngineError('Invalid assignment')
            if replacing and any(task['id'] in r.get('tasks', []) for r in state['reviews']):
                raise EngineError('A review covers this report; route a change through a repair card')
            self._lease(state, state['session']['actor'], task['lease'])
            review = self._parse_self_review(report) if task['role'] == 'builder' else None
            if task['role'] == 'builder' and not any(
                    line.startswith('ARTIFACT:') and line[len('ARTIFACT:'):].strip() for line in report.splitlines()):
                raise EngineError('Builder report needs a nonempty ARTIFACT line')
            task.update(state='reported', report=report,
                        report_artifact=self.artifact(self._scope_of(state, [task['id']])))
            if review is not None:
                task['self_review'] = review
            ancestor = task
            while ancestor.get('repair_of'):
                ancestor = state['tasks'][ancestor['repair_of']]
                ancestor['state'] = 'reported'
                ancestor['report_artifact'] = self.artifact(self._scope_of(state, [ancestor['id']]))  # the repair changed its files

    def _snapshot(self, path, kind):
        path = Path(path).resolve()
        if not path.is_file() or not path.read_bytes().strip():
            raise EngineError('Evidence report must be a nonempty file')
        data = path.read_bytes()
        target = self.state_dir / (kind + '-' + uuid.uuid4().hex)
        with target.open('xb') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        return dict(source=str(path), path=str(target), sha256=_hash(data))

    @staticmethod
    def _intact(receipt):
        for key in ('path', 'source'):
            if key in receipt:
                p = Path(receipt[key])
                if not p.is_file() or _hash(p.read_bytes()) != receipt['sha256']:
                    return False
        return True

    def record_review(self, actor, lease, reviewer, report_path, categories, task_ids=None, final=False, findings=None):
        with self._state() as state:
            self._lease(state, actor, lease)
            ids = list(task_ids or [])
            findings = findings or []
            if not isinstance(findings, list) or any(not isinstance(f, str) or not f.strip() for f in findings):
                raise EngineError('Invalid review findings')
            if not isinstance(reviewer, str) or not reviewer.strip() or reviewer == actor:
                raise EngineError('Review must be independent of coordinator')
            if not isinstance(categories, list) or not categories or not set(categories) <= set(CATEGORIES):
                raise EngineError('Invalid review categories')
            if not final and not ids:
                raise EngineError('Review needs task coverage')
            if any(i not in state['tasks'] for i in ids):
                raise EngineError('Unknown reviewed task')
            if final and (len(ids) != len(set(ids)) or set(ids) not in (set(state['tasks']), self._pre_release_ids(state))):
                raise EngineError('Final review must explicitly cover every task')
            covered = [state['tasks'][i] for i in ids]
            if any(t.get('worker') == reviewer and not self._read_review(t) for t in covered):
                raise EngineError('Worker cannot review own artifact')
            if any(t['state'] not in ('reported', 'accepted', 'held') for t in covered):
                raise EngineError('Review covers incomplete work')
            scope = None if final else self._scope_of(state, ids)
            artifact = self.artifact(scope)
            try:
                body = json.loads(Path(report_path).read_text())
            except (ValueError, OSError) as exc:
                raise EngineError('Review report must be structured JSON') from exc
            expected = dict(reviewer=reviewer, categories=categories, tasks=ids, findings=findings,
                            verdict='BLOCKED' if findings else 'CLEAN', artifact=artifact, final=bool(final))
            if not isinstance(body, dict) or any(body.get(k) != v for k, v in expected.items()):
                raise EngineError('Review report metadata, verdict or artifact does not match')
            if not isinstance(body.get('summary'), str) or not body['summary'].strip():
                raise EngineError('Review needs a nonempty semantic summary')
            task_findings = self._check_task_findings(state, body, ids, findings)
            repair_check = self._check_repair_marker(body, final)
            if not final and repair_check:
                self._check_fix_review(state, covered)
            elif not final and not any(t['role'] == 'critic' and t.get('worker') == reviewer for t in state['tasks'].values()):
                raise EngineError('Only the pre-PR review and the fix re-review are recorded')
            if not final and findings and (repair_check or any(t.get('repaired_by') for t in covered)):
                self._check_chain_tips(state, covered, task_findings)
            if final and findings and covered:
                self._check_chain_tips(state, covered, task_findings, 'final')
            cleared = self._check_cleared(state, body, final, task_findings)
            notes = self._check_issues(body, findings, covered)
            out_of_scope = self._check_out_of_scope(body, final)
            gate_receipts = self._check_gate_receipts(state, body, findings)
            evidence = self._snapshot(report_path, 'review')
            receipt = dict(id=uuid.uuid4().hex, reviewer=reviewer, categories=categories,
                           tasks=ids, final=bool(final), findings=findings, notes=notes, artifact=artifact,
                           out_of_scope=out_of_scope, gate_receipts=gate_receipts, cleared=cleared,
                           scope=scope, action='review', **evidence)
            if task_findings is not None:
                receipt['task_findings'] = task_findings
            if repair_check:
                receipt['repair_check'] = True
            if final:
                receipt['entries'] = self._entry_digests()  # lets a clean fix re-review tell which files changed since
            state['reviews'].append(receipt)
            return copy.deepcopy(receipt)

    def _check_task_findings(self, state, body, ids, findings):
        """Per-task findings (SPEC 5.1 item 4): covered keys only, and the ordered union equals `findings`."""
        if 'task_findings' not in body:
            return None
        per_task = body['task_findings']
        if not isinstance(per_task, dict) or any(
                not isinstance(v, list) or any(not isinstance(f, str) or not f.strip() for f in v)
                for v in per_task.values()):
            raise EngineError('Invalid task findings')
        if any(key not in ids for key in per_task):
            raise EngineError('Task findings name an uncovered task')
        if list(dict.fromkeys(f for v in per_task.values() for f in v)) != findings:
            raise EngineError('Task findings must match the review findings')
        return per_task

    @staticmethod
    def _check_repair_marker(body, final):
        """`repair_check` marks the fix re-review; only the value true, and never on the final receipt (contract item 4)."""
        if 'repair_check' not in body:
            return False
        if body['repair_check'] is not True or final:
            raise EngineError('repair_check must be true on a non-final fix re-review')
        return True

    @staticmethod
    def _check_fix_review(state, covered):
        """The fix re-review covers repair cards whose chain starts at a final-review finding, plus their ancestors."""
        repairs = [t for t in covered if t['role'] == 'builder' and t['mode'] == 'repair']
        allowed, fixes = set(), 0
        for repair in repairs:
            chain = [repair]
            while chain[-1].get('repair_of'):
                chain.append(state['tasks'][chain[-1]['repair_of']])
            if any(t.get('final_findings') for t in chain):
                fixes += 1
                allowed.update(t['id'] for t in chain)
        if not fixes or fixes != len(repairs) or any(t['id'] not in allowed for t in covered):
            raise EngineError('A fix re-review covers repair cards of a final-review finding and their ancestors')

    def _check_chain_tips(self, state, covered, task_findings, kind='repair-diff'):
        """Tip rule (SPEC 5.1 item 6, 5.5 item 3): a blocked repair-diff check or final receipt names chain tips, never an ancestor."""
        if task_findings is None:
            raise EngineError('Attribute %s findings to the chain tip %s' % (kind, self._open_repair(state, covered[0])['id']))
        for key, found in task_findings.items():
            if found and state['tasks'][key].get('repaired_by'):
                raise EngineError('Attribute %s findings to the chain tip %s' % (kind, self._open_repair(state, state['tasks'][key])['id']))

    def _check_cleared(self, state, body, final, task_findings):
        """SPEC 5.5 item 3: `cleared` maps a held tip to a reason, on final receipts only; a final receipt addresses every held tip."""
        cleared = body.get('cleared', {})
        if not final:
            if cleared:
                raise EngineError('Cleared entries are allowed only on final receipts')
            return {}
        held = [t['id'] for t in state['tasks'].values() if t['state'] == 'held' and not t.get('repaired_by')]
        if (not isinstance(cleared, dict)
                or any(key not in held or not isinstance(reason, str) or not reason.strip() for key, reason in cleared.items())):
            raise EngineError('Invalid cleared entries: each names a held tip with a non-empty reason')
        for tip in held:
            if tip not in cleared and not (task_findings or {}).get(tip):
                raise EngineError('Final receipt must address held tip ' + tip)
        return cleared

    @staticmethod
    def _check_out_of_scope(body, final):
        """Out-of-scope items never change the verdict and exist only on final receipts (SPEC 5.7 item 2)."""
        items = body.get('out_of_scope', [])
        if not final and items:
            raise EngineError('Out-of-scope findings are raised only at the final review')
        if not isinstance(items, list) or any(not isinstance(i, str) or not i.strip() for i in items):
            raise EngineError('Invalid out-of-scope findings')
        return items

    def _check_gate_receipts(self, state, body, findings):
        """A cited gate receipt must exist, be intact and match the current whole-repository artifact (SPEC 5.11 item 1)."""
        cited = body.get('gate_receipts', [])
        if not isinstance(cited, list) or any(not isinstance(c, str) or not c for c in cited):
            raise EngineError('Invalid gate receipts')
        current = self.artifact() if cited else None
        failed = False
        for ident in cited:
            gate = next((g for g in state['gates'] if g['id'] == ident), None)
            if gate is None:
                raise EngineError('Review cites an unknown gate receipt: ' + ident)
            if not self._intact(gate):
                raise EngineError('Review cites an altered gate receipt: ' + ident)
            if gate['artifact'] != current:
                raise EngineError('Review cites a stale gate receipt: ' + ident)
            failed = failed or not gate['passed']
        if failed and not findings:
            raise EngineError('A failed gate receipt needs a blocking finding')
        return cited

    @staticmethod
    def _check_issues(body, findings, covered):
        """Materiality (SPEC 5.6): blocking issues are the findings; note texts are returned."""
        if 'issues' not in body:
            if any('rev' in t for t in covered):
                raise EngineError('Review of 2.2 cards needs issues with severity')
            return []
        issues = body['issues']
        if not isinstance(issues, list) or any(
                not isinstance(i, dict) or not isinstance(i.get('text'), str) or not i['text'].strip()
                or i.get('severity') not in ('blocking', 'note') for i in issues):
            raise EngineError('Review issues need text and a severity of blocking or note')
        if any(i['severity'] == 'blocking' and (not isinstance(i.get('impact'), str) or not i['impact'].strip())
               for i in issues):
            raise EngineError('A blocking issue needs an impact')
        if findings != [i['text'] for i in issues if i['severity'] == 'blocking']:
            raise EngineError('Review findings must equal the blocking issues in order')
        return [i['text'] for i in issues if i['severity'] == 'note']

    def _kept_current(self, state, review, cache):
        """Ids a CLEAN fix re-review resolves when a stale final review stays current for completion, else None.
        Every file changed since the final review must belong to a repair card that a later, current, CLEAN fix
        re-review covered (contract item 5)."""
        if not review['final'] or 'entries' not in review:
            return None
        ids = [r['id'] for r in state['reviews']]
        later = [r for r in state['reviews'][ids.index(review['id']) + 1:]
                 if r.get('repair_check') and not r['findings'] and self._intact(r)
                 and r['artifact'] == self._artifact_cached(cache, r.get('scope'))]
        repairs = {i for r in later for i in r['tasks']
                   if state['tasks'][i]['role'] == 'builder' and state['tasks'][i]['mode'] == 'repair'}
        scope = self._scope_of(state, sorted(repairs)) if repairs else None
        if scope is None:
            return None
        if 'entries' not in cache:
            cache['entries'] = self._entry_digests()
        old, now = review['entries'], cache['entries']
        if any(old.get(name) != now.get(name) and not self._in_scope(name, scope) for name in old.keys() | now.keys()):
            return None
        if any(review['artifact'][k] != self._artifact_cached(cache, None)[k] for k in ('repo', 'identity', 'policy')):
            return None
        return {i for r in later for i in r['tasks']}

    def _review_verdicts(self, state, cache, task_id=None, final=False, keep=False):
        """Newest relevant verdict wins; altered evidence cannot restore an older verdict. With `keep`, a stale final
        review that a CLEAN fix re-review keeps current counts as current (`cache['resolved']` records the ids)."""
        verdicts = {}
        since = state['tasks'][task_id].get('review_since', 0) if task_id is not None else 0
        for review in state['reviews'][since:]:
            if task_id is not None and task_id not in review['tasks']:
                continue
            if final and not review['final']:
                continue
            # Each receipt is compared against the artifact recomputed with its own stored scope.
            # A stale newest receipt leaves its categories without a current verdict (O19).
            current = review['artifact'] == self._artifact_cached(cache, review.get('scope'))
            resolved = None
            if not current and keep and review['final']:
                resolved = self._kept_current(state, review, cache)
                if resolved is not None:
                    current = True
            if final and not self._pre_release_ids(state) <= set(review['tasks']) | (resolved or set()):
                continue  # a repair card the fix re-review covered counts as covered by the final review it fixed
            if resolved is not None:
                cache.setdefault('resolved', {})[review['id']] = resolved
            for category in review['categories']:
                verdicts[category] = (review, current)
        # A stale non-CLEAN newest receipt in any category voids every verdict until re-review (O22).
        # Per task, the receipt voids only when its findings for that task are non-empty (SPEC 5.1 item 4).
        if any(not current and (self._task_findings(review, task_id) if task_id is not None else review['findings'])
               for review, current in verdicts.values()):
            return {}
        verdicts = {category: review for category, (review, current) in verdicts.items() if current}
        if any(not self._intact(review) for review in verdicts.values()):
            kind = 'final' if final else 'task'
            raise EngineError('Current ' + kind + ' review evidence is missing or altered')
        return verdicts

    def _accept_refusal(self, state, cache, task_id):
        """Why `accept` would refuse this card now, or None when every accept check passes."""
        task = state['tasks'].get(task_id)
        if not task or task['state'] not in ('reported', 'held'):
            return 'Task has no reported result'
        verdicts = self._review_verdicts(state, cache, task_id=task_id)
        if any(self._task_findings(r, task_id) for r in verdicts.values()):
            return 'Task has current review findings'
        if task.get('repaired_by') and state['tasks'][task['repaired_by']]['state'] != 'accepted':
            return 'Task repair must be accepted first'
        if task['role'] == 'builder':
            review = task.get('self_review')
            if review is None:
                return SELF_REVIEW_ERROR
            if any(c['exit_code'] != 0 for c in review['checks']) or not all(c['met'] for c in review['criteria']):
                return 'Self-review has a failing check or unmet criterion'
        elif task.get('review_required', False):
            return None if verdicts else 'Task needs current independent review'
        if task['report_artifact'] != self._artifact_cached(cache, self._scope_of(state, [task_id])):
            return 'Reported artifact is stale'
        return None

    def accept(self, actor, lease, task_id):
        with self._state() as state:
            self._lease(state, actor, lease)
            refusal = self._accept_refusal(state, {}, task_id)
            if refusal:
                raise EngineError(refusal)
            state['tasks'][task_id]['state'] = 'accepted'

    def add_finding(self, actor, lease, review_id, kind, index, disposition, reason, card=None):
        """Record the coordinator's disposition of one receipt item (SPEC 5.12). A rejection accepts no card."""
        with self._state() as state:
            self._lease(state, actor, lease)
            review = next((r for r in state['reviews'] if r['id'] == review_id), None)
            if review is None:
                raise EngineError('Unknown review: ' + str(review_id))
            if kind not in DISPOSITIONS:
                raise EngineError('Finding kind must be finding or out_of_scope')
            if disposition not in DISPOSITIONS[kind]:
                raise EngineError('Disposition for %s must be one of %s' % (kind, ', '.join(DISPOSITIONS[kind])))
            items = review['findings'] if kind == 'finding' else review.get('out_of_scope', [])
            if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(items):
                raise EngineError('Finding index does not name an item of that receipt')
            if not isinstance(reason, str) or not reason.strip():
                raise EngineError('Finding needs a reason')
            if card is not None and (not isinstance(card, str) or not card.strip()):
                raise EngineError('Finding card must be a nonempty id')
            entry = dict(id=uuid.uuid4().hex, fingerprint=_fingerprint(items[index]), text=items[index],
                         source=dict(review=review_id, kind=kind, index=index), disposition=disposition,
                         reason=reason, at=datetime.fromtimestamp(self._clock(), timezone.utc).isoformat(timespec='seconds'))
            if card is not None:
                entry['card'] = card
            state.setdefault('findings', []).append(entry)
            return copy.deepcopy(entry)

    def list_findings(self, for_brief=False):
        """Lease-free read of the ledger; for_brief renders the block reviewer briefs carry."""
        with self._state(False) as state:
            entries = copy.deepcopy(state.get('findings', []))
        if not for_brief:
            return entries
        lines = ['Known findings']
        lines += ['- %s [%s] %s -- %s' % (e['id'], e['disposition'], e['text'], e['reason']) for e in entries]
        return '\n'.join(lines if entries else lines + ['- none'])

    def run_secret_scan(self, actor, lease):
        return self.run_gate(actor, lease, 'secret-scan', self.policy['secret_scan'].get('argv', []))

    def run_gate(self, actor, lease, name, argv, again=False, timeout=None):
        if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                                    or not math.isfinite(timeout) or timeout <= 0):
            raise EngineError('Gate timeout must be positive and finite')
        unavailable = name == 'secret-scan' and argv == [] and not self.policy['secret_scan'].get('argv')
        if unavailable and self.policy['secret_scan'].get('required'):
            raise EngineError('Required secret scanner is unavailable')
        if not isinstance(name, str) or not name.strip():
            raise EngineError('Gate needs a name')
        if not unavailable and (not isinstance(argv, list) or not argv or any(not isinstance(a, str) or not a or '\0' in a for a in argv)):
            raise EngineError('Gate needs an argv list')
        decision = classify_command(shlex.join(argv)) if not unavailable else None
        if decision is not None and decision.action != 'allow':
            raise EngineError('Gate command forbidden: ' + decision.reason)
        if decision is not None and (decision.boundary or decision.category in ('boundary', 'merged-delete')):
            raise EngineError('Gate command forbidden: boundary actions run only through the guarded hook')  # SPEC 5.14 item 5
        with self._state(False) as state:
            self._lease(state, actor, lease)
            gates = list(state['gates'])
        before = self.artifact()
        if not again:  # SPEC 5.11 item 2: a failed gate always reruns
            for gate in gates:
                if (gate['name'] == name and gate['argv'] == argv and gate['passed']
                        and gate['artifact'] == before and self._intact(gate)):
                    raise EngineError('Gate %s already passed on this artifact (receipt %s); pass --again to rerun'
                                      % (name, gate['id']))
        log = self.state_dir / ('gate-' + uuid.uuid4().hex + '.log')
        with log.open('xb') as out:
            try:
                if unavailable:
                    out.write(b'Optional secret scanner unavailable: no command configured\n')
                    code = 126
                else:
                    process = subprocess.Popen(argv, cwd=self.repo, stdout=out, stderr=subprocess.STDOUT,
                                               start_new_session=True)
                    try:
                        code = process.wait(timeout=timeout or self.policy['gate_timeout_seconds'])
                    except subprocess.TimeoutExpired:
                        portable.kill_tree(process)
                        process.wait()
                        raise
            except subprocess.TimeoutExpired:
                out.write(b'Gate timed out\n')
                code = 124
            except OSError as exc:
                out.write(str(exc).encode())
                code = 127
            out.flush()
            os.fsync(out.fileno())
        after = self.artifact()
        receipt = dict(id=uuid.uuid4().hex, name=name, argv=argv, exit_code=code,
                       artifact=before, after=after, action='gate', path=str(log),
                       sha256=_hash(log.read_bytes()), passed=code == 0 and before == after)
        with self._state() as state:
            self._lease(state, actor, lease)
            state['gates'].append(receipt)
        return receipt

    def _release_evidence(self, state, remote, target, action, argv=None):
        release = self.policy['release']
        if (action != 'release' or not release.get('enabled') or not release.get('authorization')
                or not release.get('argv') or release.get('remote') != remote or release.get('target') != target):
            raise EngineError('Release is disabled or target is unauthorized')
        decision = classify_command(shlex.join(release['argv']))
        if decision.action == 'deny':
            raise EngineError('Forbidden release command: ' + decision.reason)
        if decision.category == 'gitpush':
            command = release['argv'][0]
            if '/' in command and not Path(command).is_absolute():
                command = str(self.repo / command)
            executable, engine_git = shutil.which(command), shutil.which('git')
            if (not executable or not engine_git or Path(executable).resolve() != Path(engine_git).resolve()
                    or len(release['argv']) != 4 or release['argv'][1:2] != ['push']):
                raise EngineError('Known Git release needs exactly engine Git, push, remote and refspec')
        if decision.category == 'gitpush' and (decision.action != 'release'
                or decision.remote != remote or decision.target != target):
            raise EngineError('Git release command destination differs from authorized target')
        if self._git('status', '--porcelain=v1', '--untracked-files=all').strip():
            raise EngineError('Release needs a clean working tree')
        if argv is not None and argv != release['argv']:
            raise EngineError('Release command differs from configured command')
        artifact = self._completion_evidence(state, require_review=True, require_checks=True, for_release=True)
        if decision.category == 'gitpush':
            if not decision.source:
                raise EngineError('Git release command needs an explicit source')
            source = self._git('rev-parse', '--verify', '--end-of-options',
                               decision.source + '^{commit}').decode().strip()
            if source != artifact['head']:
                raise EngineError('Git release source differs from the reviewed HEAD')
        return artifact

    @staticmethod
    def _pre_release_ids(state):
        return {t['id'] for t in state['tasks'].values()
                if not Engine._is_release(t)}

    def _completion_evidence(self, state, require_review=False, require_checks=False, for_release=False):
        if for_release:
            releases = [t for t in state['tasks'].values() if self._is_release(t)]
            if releases and (len(releases) != 1 or releases[0]['state'] != 'running'):
                raise EngineError('The terminal release task must be running')
        required_ids = self._pre_release_ids(state) if for_release else set(state['tasks'])
        if any(state['tasks'][i]['state'] != 'accepted' for i in required_ids):
            raise EngineError('All tasks must be accepted')
        artifact = self.artifact()
        cache = {None: artifact}
        verdicts = self._review_verdicts(state, cache, final=True, keep=True)

        def open_findings(review):
            resolved = cache.get('resolved', {}).get(review['id'])
            if resolved is None:
                return review['findings']
            return [f for key, found in (review.get('task_findings') or {}).items() if key not in resolved for f in found]

        categories = {category for category, review in verdicts.items() if not open_findings(review)}
        if any(open_findings(review) for review in verdicts.values()):
            raise EngineError('Current final review has findings')
        for task_id in state['tasks']:
            if any(self._task_findings(r, task_id) for r in self._review_verdicts(state, cache, task_id=task_id).values()):
                raise EngineError('Current task review has findings: ' + task_id)
        required_categories = set(self._required_lenses(state))
        if (require_review or state['tasks']) and not required_categories <= categories:
            raise EngineError('Current final review coverage is incomplete')
        triaged = {f['fingerprint'] for f in state.get('findings', []) if f['source'].get('kind') == 'out_of_scope'}
        for review in {r['id']: r for r in verdicts.values()}.values():  # SPEC 5.7 item 4
            for item in review.get('out_of_scope', []):
                if _fingerprint(item) not in triaged:
                    raise EngineError('Out-of-scope finding needs triage: ' + item)
        checks = list(self.policy['required_checks'])
        scanner = self.policy['secret_scan']
        if scanner.get('required'):
            if not scanner.get('argv'):
                raise EngineError('Required secret scanner is unavailable')
            checks.append(dict(name='secret-scan', argv=scanner['argv']))
        if require_checks and not checks:
            raise EngineError('Release needs configured required checks')
        for check in checks:
            name = check['name'] if isinstance(check, dict) else check
            expected = check.get('argv') if isinstance(check, dict) else self.policy.get('check_commands', {}).get(name)
            if not expected:
                raise EngineError('Required gate needs configured argv: ' + name)
            matching = [g for g in state['gates'] if g['name'] == name and g['argv'] == expected]
            if not matching or not matching[-1]['passed'] or matching[-1]['artifact'] != artifact or not self._intact(matching[-1]):
                raise EngineError('Required gate is missing, failed, altered or stale: ' + name)
        return artifact

    def check_completion(self, actor, lease):
        """Check completion evidence without changing the active coordinator session."""
        with self._state(False) as state:
            self._lease(state, actor, lease)
            return self._completion_evidence(state)

    def close_session(self, actor, lease):
        """Check and close under one lock, keeping completion distinct from interruption."""
        with self._state() as state:
            self._lease(state, actor, lease)
            artifact = self._completion_evidence(state)
            state['session'].update(active=False, outcome='completed')
            state['permits'] = []
            auto = state['autonomy']
            if auto and auto['active'] and auto.get('relaunch'):
                self._stop_autonomy(state, 'complete')  # SPEC 5.10 item 2: completion ends the relaunch loop
            else:
                self._write_brief(state, 'closed')
            state['autonomy'] = self._kept_autonomy(state)
            return artifact

    def release_permit(self, actor, lease, remote, target, action='release'):
        with self._state() as state:
            self._lease(state, actor, lease)
            self._refuse_under_autonomy(state, 'release_permit', remote, target)
            artifact = self._release_evidence(state, remote, target, action)
            permit = dict(id=uuid.uuid4().hex, action=action, remote=remote, target=target,
                          argv=self.policy['release']['argv'], artifact=artifact, lease=lease)
            state['permits'].append(permit)
            return copy.deepcopy(permit)

    def check_release(self, remote, target, action='release', argv=None):
        with self._state(False) as state:
            session = state['session']
            if not session or not session['active']:
                raise EngineError('No active release session')
            self._refuse_under_autonomy(state, 'check_release', remote, target)
            artifact = self._release_evidence(state, remote, target, action, argv)
            for permit in reversed(state['permits']):
                if (permit['artifact'] == artifact and permit['remote'] == remote and permit['target'] == target
                        and permit['action'] == action and permit['lease'] == session['lease']):
                    return copy.deepcopy(permit)
            raise EngineError('No current explicit release permit')

    @staticmethod
    def _autonomy_on(state):
        """Armed autonomy with an active session, or armed `relaunch` autonomy between passes (SPEC 5.10 item 3)."""
        auto = state['autonomy']
        if not (auto and auto['active']):
            return False
        return bool(auto.get('relaunch') or (state['session'] and state['session']['active']))

    def _refuse_under_autonomy(self, state, action, remote=None, target=None):
        """A permit or its check passes only for the exact pair the ledger pre-authorized (SPEC 5.8 item 8.3)."""
        if not self._autonomy_on(state):
            return
        release = state['autonomy'].get('release')
        if (action in ('release_permit', 'check_release') and release
                and (remote, target) == (release['remote'], release['target'])):
            return
        raise EngineError('Release and permits are approval boundaries while autonomy is active')

    def autonomy_active(self):
        with self._state(False) as state:
            return self._autonomy_on(state)

    def arm_autonomy(self, home=None, relaunch=False):
        """Arm the loop from `<state>/autonomy.md` (SPEC 12.1). Takes no lease, by design (O8)."""
        path = self.state_dir / 'autonomy.md'
        with self._state() as state:
            if not state['session'] or not state['session']['active']:
                raise EngineError('Autonomy needs an armed run (an active session)')
            if not path.is_file():
                shutil.copyfile(AUTONOMY_TEMPLATE, path)
                raise EngineError('Ledger template written to %s: fill the ledger, then arm again' % path)
            data = path.read_bytes()
            fields = parse_ledger(data.decode(errors='replace'), self._clock())
            snapshot = self._snapshot(path, 'ledger')
            if snapshot['sha256'] != _hash(data):
                raise EngineError('Ledger changed while arming; arm again')
            release = fields.get('release')
            policy = self.policy['release']
            if release and not (policy.get('enabled') is True and policy.get('remote') == release['remote']
                                and policy.get('target') == release['target']):
                raise EngineError('Release pre-authorization must match policy.release')
            if relaunch:
                fields['relaunch'] = True
            state['autonomy'] = dict(
                active=True, ledger=snapshot, passes=0, stalls=0, armed_at=self._clock(),
                armed_gates=len(state['gates']), armed_reviews=len(state['reviews']),
                accepted=self._accepted(state), **fields)
        return dict(active=True, ledger=str(path), preconditions=autonomy_preconditions(self.repo, home))

    def disarm_autonomy(self):
        """Safe at any time; a no-op never rewrites state.json."""
        with self._state(False) as state:
            auto = state['autonomy']
            if not auto or (not auto['active'] and 'report' not in auto):
                return dict(was_active=False)
        with self._state() as state:
            auto = state['autonomy']
            if not auto:
                return dict(was_active=False)
            if auto['active']:
                return dict(was_active=True, reason='disarmed', text=self._stop_autonomy(state, 'disarmed'))
            auto.pop('report', None)  # clear the report shown from the previous stop
            return dict(was_active=False)

    def autonomy_status(self):
        with self._state(False) as state:
            auto = state['autonomy'] or {}
            parked = [dict(id=t['id'], reason=t.get('parked_reason', ''))
                      for t in state['tasks'].values() if t['state'] == 'parked']
            keys = ('passes', 'max_passes', 'stalls', 'max_stalls', 'deadline')
            return dict(active=self._autonomy_on(state), parked=parked, signature=self._signature(state),
                        last_stop_reason=auto.get('last_stop_reason'), **{k: auto.get(k) for k in keys})

    @staticmethod
    def _signature(state):
        """SPEC 5.10 item 7: SHA-256 of canonical JSON of the sorted (id, state, report fingerprint, repaired_by)
        tuples and the counts of reviews, gates and findings. A pass that leaves it unchanged is a stall."""
        tasks = sorted([t['id'], t['state'], (t.get('report_artifact') or {}).get('fingerprint'), t.get('repaired_by')]
                       for t in state['tasks'].values())
        return _digest(dict(tasks=tasks, reviews=len(state['reviews']), gates=len(state['gates']),
                            findings=len(state.get('findings', []))))

    def autonomy_report(self):
        """The morning report shown at SessionStart, or None. Read-only."""
        with self._state(False) as state:
            return copy.deepcopy((state['autonomy'] or {}).get('report'))

    @staticmethod
    def _accepted(state):
        return sorted(t['id'] for t in state['tasks'].values() if t['state'] == 'accepted')

    def _write_brief(self, state, reason, stops=False):
        """SPEC 5.9: append the run brief to progress.md and remember it as `last_brief`. A stopped run's brief stays
        the remembered one when an end path that does not stop autonomy follows it (the progress entry still lands)."""
        at = datetime.fromtimestamp(self._clock(), timezone.utc).isoformat(timespec='seconds')
        text = self._brief_text(state, reason, at)
        _append_progress(self.state_dir, text)
        brief = dict(reason=reason, at=at, text=text, path=str(self.state_dir / 'progress.md'))
        if stops or not self._stopped_report_kept(state):
            state['last_brief'] = brief
        return brief

    def brief(self):
        """The newest run brief's text, or None. Lease-free and read-only."""
        with self._state(False) as state:
            return (state.get('last_brief') or {}).get('text')

    def _stop_autonomy(self, state, reason):
        auto = state['autonomy']
        auto.update(active=False, last_stop_reason=reason)
        brief = self._write_brief(state, reason, stops=True)
        auto['report'] = dict(brief)
        return brief['text']

    def _brief_text(self, state, reason, at):
        """The run brief of SPEC 5.9: what needs the owner first, the 2.1 report lines last."""
        def listing(items):
            return ['  - ' + i for i in items] or ['  - none']

        def section(title, items):
            return ['### ' + title, *listing(items)]

        auto = state['autonomy']
        tasks = state['tasks']
        findings = state.get('findings', [])
        chain_of = lambda tip: self._brief_chain(tasks, tip)
        header = ['## Run brief ' + at, '', '- stop reason: ' + reason]
        if auto:
            header += ['- deadline: ' + str(auto.get('deadline')),
                       '- passes: %d' % auto['passes'],
                       '- stalls: %d' % auto['stalls']]
            caps = ['%s %d' % (k, auto[k]) for k in ('max_passes', 'max_stalls') if k in auto]
            if caps:
                header += ['- caps from the 2.1 ledger: %s (recorded, not enforced)' % ', '.join(caps)]
        else:
            header += ['- autonomy: not armed']
        parked = ['%s: %s' % (t['id'], t.get('parked_reason', '')) for t in tasks.values() if t['state'] == 'parked']
        needs = list(parked)
        needs += ['%s -- %s' % (e['text'], e['reason']) for e in findings if e['disposition'] == 'brief']
        needs += ['%s -- %s' % (e['text'], e['reason']) for e in findings if e['disposition'] == 'deferred']
        if (reason in ('closed', 'complete') and not any(self._is_release(t) for t in tasks.values())
                and not (auto or {}).get('release')):
            needs.append('ready to release')
        cleared_by = {}
        for review in state['reviews']:
            if review.get('final'):
                cleared_by.update(review.get('cleared') or {})
        held_tips = [t for t in tasks.values() if t.get('held_finding')]
        if any(t['state'] == 'parked' and not self._is_release(t) for t in tasks.values()):
            needs += ['%s (chain %s): held -- %s' % (t['id'], ', '.join(chain_of(t['id'])), t['held_finding'])
                      for t in held_tips if t['id'] not in cleared_by and not t.get('repaired_by')]
        failing = []
        cache = {}
        for task in tasks.values():
            if task['role'] != 'builder' or task.get('repaired_by') or task['state'] == 'held':
                continue
            try:
                verdicts = self._review_verdicts(state, cache, task_id=task['id'])
            except EngineError:
                continue
            blocking = list(dict.fromkeys(f for r in verdicts.values() for f in self._task_findings(r, task['id'])))
            if blocking:
                failing.append('%s (chain %s): %s' % (task['id'], ', '.join(chain_of(task['id'])), '; '.join(blocking)))
        for tip in held_tips:
            if tip['id'] in cleared_by or tip.get('repaired_by'):
                continue
            rounds = [t['final_round'] for t in tasks.values() if t.get('final_round') and t.get('repair_of') in chain_of(tip['id'])]
            failing.append('%s (chain %s): %s; final round: %s' % (
                tip['id'], ', '.join(chain_of(tip['id'])), tip['held_finding'], max(rounds) if rounds else 'none'))
        held_log = []
        for tip in held_tips:
            if tip.get('repaired_by'):
                fix = tasks[tip['repaired_by']]
                status = ('fixed in final round %s by %s' % (fix['final_round'], fix['id']) if fix.get('final_round')
                          else 'repaired by ' + fix['id'])
            elif tip['id'] in cleared_by:
                status = 'cleared by a lens: ' + cleared_by[tip['id']]
            else:
                status = 'still ' + tip['state']
            held_log.append('%s (chain %s): %s -- %s' % (tip['id'], ', '.join(chain_of(tip['id'])), tip['held_finding'], status))
        rounds = {}
        for task in tasks.values():
            if task.get('final_round'):
                rounds.setdefault(task['final_round'], []).append(task)
        final_rounds = []
        for number in sorted(rounds):
            cards = sorted(rounds[number], key=lambda t: t.get('seq', 0))
            open_ = [t for t in cards if t['state'] != 'accepted']
            names = ', '.join('%s (chain %s)' % (t['id'], ', '.join(self._brief_chain(tasks, t['id'], full=True))) for t in cards)
            cleared = list(dict.fromkeys(f for t in cards for f in t.get('final_findings', [])))
            final_rounds.append('round %d: %s %s: %s' % (number, names, 'open' if open_ else 'cleared', '; '.join(cleared) or 'none'))
        notes = [str(n) for r in state['reviews'] for n in r.get('notes', [])]
        deferred = ['%s -- %s' % (e['text'], e['reason']) for e in findings if e['disposition'] == 'deferred']
        accepted = []
        for t in tasks.values():
            if t['state'] != 'accepted':
                continue
            line = '%s (%s/%s)' % (t['id'], t['role'], t['mode'])
            if t.get('repair_of') or t.get('repaired_by'):
                line += ' repaired (%s)' % ', '.join(self._brief_chain(tasks, t['id'], full=True))
            accepted.append(line)
        start_gates = auto['armed_gates'] if auto else 0
        start_reviews = auto['armed_reviews'] if auto else 0
        failures = ['gate %s: exit %d' % (g['name'], g['exit_code']) for g in state['gates'][start_gates:] if not g['passed']]
        failures += ['review %s: BLOCKED (%s)' % (r['reviewer'], '; '.join(map(str, r['findings'])))
                     for r in state['reviews'][start_reviews:] if r['findings']]
        lines = header + ['']
        for part in (section('Needs you', needs), section('Still failing / next phase', failing),
                     section('Held log', held_log), section('Final rounds', final_rounds), section('Notes', notes),
                     section('Deferred findings', deferred), section('Parked', parked), section('Accepted', accepted),
                     section('Failures', failures)):
            lines += part
        return '\n'.join(lines)

    @staticmethod
    def _brief_chain(tasks, tip, full=False):
        """Card ids of a repair chain: tip first (as `hold` logs it), or oldest first from the whole chain of `tip`."""
        chain = [tip]
        while tasks[chain[-1]].get('repair_of'):
            chain.append(tasks[chain[-1]]['repair_of'])
        if not full:
            return chain
        chain.reverse()
        while tasks[chain[-1]].get('repaired_by'):
            chain.append(tasks[chain[-1]]['repaired_by'])
        return chain

    def _complete(self, state):
        """SPEC 5.8 item 3: the cheap all-accepted check first, then the ledger checks, then the completion evidence."""
        if any(t['state'] != 'accepted' for t in state['tasks'].values()):
            return False
        auto = state['autonomy']
        matches = []
        for check in auto['checks']:
            same = [g for g in state['gates'] if g['name'] == check['name'] and g['argv'] == check['argv']]
            if not same or not same[-1]['passed'] or not self._intact(same[-1]):
                return False
            matches.append(same[-1])
        artifact = self.artifact()
        if not all(g['artifact'] == artifact for g in matches):
            return False
        try:
            self._completion_evidence(state)
        except EngineError:
            return False
        return True

    def _stop_check(self, state, count):
        """The stop conditions shared by `hook_stop` and `settle`: (reason, message). `count` records the pass,
        signature and stall bookkeeping; `settle` never counts."""
        auto = state['autonomy']
        tasks = state['tasks'].values()
        if not self._intact(auto['ledger']):
            return 'ledger-tampered', None
        if self._clock() >= datetime.fromisoformat(auto['deadline']).timestamp():
            return 'deadline', None
        if self._complete(state):
            return 'complete', None
        signature = self._signature(state)
        if count:
            if auto['passes'] > 0:  # the arming turn is not a pass
                auto['stalls'] = auto['stalls'] + 1 if signature == auto.get('signature') else 0
            auto['signature'] = signature
            auto['accepted'] = self._accepted(state)
        parked = any(t['state'] == 'parked' for t in tasks)
        held = (any(t['state'] == 'held' for t in tasks)
                and not any(t['state'] == 'parked' and not self._is_release(t) for t in tasks))
        live = any(t['state'] in ('running', 'reported') for t in tasks) or bool(self._ready(state))
        final_open = not live and any(t['role'] == 'builder' and t['state'] == 'accepted' and not t.get('repaired_by')
                                      and self._final_blocks(state, t['id']) for t in tasks)
        if not live and not held and not final_open:
            return ('parked-only' if parked else 'no-ready-card'), None
        if not count:
            return None, None
        auto['passes'] += 1
        if live:
            return None, ('Autonomy pass %d: continue with the next ready card; park any card that '
                          'reaches an approval boundary.' % auto['passes'])
        if final_open:
            return None, ('Autonomy pass %d: start the final repair round; a current final finding is still '
                          'open.' % auto['passes'])
        return None, ('Autonomy pass %d: start or continue the final phase; held work is still owed a '
                      'final review.' % auto['passes'])

    def hook_stop(self):
        """The Stop continuation of SPEC 5.8: no count stops it, only the deadline, completion, tamper, disarm and
        an idle run. Caller identifiers do not authenticate. Under `relaunch` (SPEC 5.10 items 5.6, 5.8.7) it is a
        no-op without an active session, and inside a pass it counts but continues nothing: the harness is the loop."""
        def runnable(state):
            session = state['session']
            return bool(session and session['active'] and self._autonomy_on(state))

        with self._state(False) as state:
            if not runnable(state):
                return None  # Read-only unless autonomy is active in a session
        with self._state() as state:
            if not runnable(state):
                return None
            reason, message = self._stop_check(state, True)
            if reason is None:
                return None if state['autonomy'].get('relaunch') else message
            self._stop_autonomy(state, reason)
            return None

    def settle(self):
        """SPEC 5.10 item 4: lease-free; evaluates the stop conditions of an armed autonomy, with or without a
        session, without counting a pass, and stops autonomy (brief written) when one holds."""
        with self._state(False) as state:
            if not (state['autonomy'] and state['autonomy']['active']):
                return self._settled(state)  # not armed: read-only
        with self._state() as state:
            auto = state['autonomy']
            if auto and auto['active']:
                reason, _ = self._stop_check(state, False)
                if reason is not None:
                    self._stop_autonomy(state, reason)
            return self._settled(state)

    def _settled(self, state):
        auto = state['autonomy'] or {}
        stopped = bool(auto) and not auto['active'] and bool(auto.get('last_stop_reason'))
        return dict(armed=bool(auto.get('active')), stopped=stopped,
                    reason=auto.get('last_stop_reason') if stopped else None,
                    signature=self._signature(state), passes=auto.get('passes'), stalls=auto.get('stalls'))
