"""Native hook adapter. Shell inspection and caller identity are best effort.

Reference wire contracts: https://learn.chatgpt.com/docs/hooks and
https://code.claude.com/docs/en/hooks (checked 2026-09-30).
"""
import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from . import portable
import json
import os
from pathlib import Path
import re
import sys
import subprocess
import time

from .guards import RULES, classify_command, guard_digest, runs_test_suite

_PROTECTED = RULES['protected']
_MARKER = RULES['marker']
_MOD_TOOLS = {'Bash', 'Edit', 'Write', 'MultiEdit'}  # The mod guards only these; any other tool needs Python.
_EDIT_TOOLS = set(RULES['tools']['edit'])
_SHELL_TOOLS = set(RULES['tools']['shell'])
_REBIND_SOURCES = ('clear', 'resume', 'fork')
STOP_LOCK_BUDGET = 8.0  # SPEC 5.16 item 4: seconds from hook start that a busy-state Stop waits for the lock
LOCK_WAIT = 2.0  # SPEC 5.16 item 3: seconds a hook read waits for the state lock
MISSING_CWD = 'Session directory no longer exists: cd to an existing directory, then retry'
BUSY = 'Orchestra state is busy; retry'
AGENT_GUARD = 'Orchestra run active: use an orchestra:* agent (investigator-code for search, builder for edits)'
_REVIEWER_TYPES = ('orchestra:code-reviewer', 'orchestra:critic')
SUBAGENT_GUARD = ('Orchestra run active: this agent is not an orchestra:* agent; stop and report. '
                  'Start Agent and Workflow workers with an orchestra:<role> type')


CONTEXT = (
    'Orchestra is enabled. You are the main coordinator. Read the orchestra skill '
    'before substantial work. Own assignments, bounded file reservations, exact '
    'artifact evidence, independent review and integration. Workers never delegate '
    'or change coordinator state. Session start injects context only; do not repair '
    'the repository, resume prior runs or arm autonomy without an explicit request. '
    'Release needs configured authorization and current evidence. Native hook '
    'identity and shell inspection are best effort, not hostile-worker isolation.'
)
WORKER_CONTEXT = 'Orchestra worker: follow the assigned brief, own only assigned files, return evidence, and never delegate or change coordinator state.'


@dataclass(frozen=True)
class HookResult:
    output: dict
    exit_code: int = 0


def _deny(reason, malformed=False):
    return HookResult({'hookSpecificOutput': {'hookEventName': 'PreToolUse',
                        'permissionDecision': 'deny',
                        'permissionDecisionReason': reason}}, 2 if malformed else 0)


def _marker_dir():
    base = Path(os.environ.get('XDG_STATE_HOME') or Path.home() / '.local/state')
    return (base.expanduser() / 'orchestra' / 'mods').resolve()


def _protected(path, cwd, state_dir):
    resolved = (Path(cwd) / path).resolve()
    if state_dir:
        state = Path(state_dir).expanduser().resolve()
        if resolved == state or state in resolved.parents:
            # Coordinator-authored notes at the state root stay writable (A8).
            return not (resolved.parent == state and resolved.name in _PROTECTED['state_root_exceptions'])
    marker = _marker_dir()
    if resolved == marker or marker in resolved.parents:
        return True
    parts = resolved.parts
    if _PROTECTED['component'] in parts:
        return True
    # Every harness directory in the path counts, not only the first (B-F4).
    for i, part in enumerate(parts):
        if part in _PROTECTED['harness_dirs']:
            tail = parts[i + 1:]
            if tail and (tail[0] in _PROTECTED['files'] or
                         (tail[0] == 'agents' and any(x.startswith(tuple(_PROTECTED['agents_prefixes'])) for x in tail[1:]))):
                return True
    return False


def _patch_paths(command):
    if not isinstance(command, str) or not command.startswith('*** Begin Patch\n') or not command.rstrip().endswith('*** End Patch'):
        raise ValueError('Malformed patch payload')
    paths = []
    for line in command.splitlines():
        match = re.fullmatch(r'\*\*\* (?:Add File|Update File|Delete File|Move to): (.+)', line)
        if match:
            paths.append(match.group(1))
    if not paths:
        raise ValueError('Patch has no file operations')
    return paths


def handle_event(event, payload, *, harness='claude', state_dir=None, engine=None, armed=False, autonomy=False,
                 busy=False, missing_cwd=False, started=None):
    """Decide output; optional engine adapter owns locked state operations.

    `armed` marks a run whose state could not be loaded: release classes deny (fail closed).
    `autonomy` marks such a state whose raw autonomy flag is true or unreadable (O29): the
    autonomy-active column applies to every class. A loaded engine implies an armed run; neither means unarmed.
    `busy` marks a state lock held past the read wait, `missing_cwd` a payload cwd that no longer exists: the
    delegated classes (release, release-multi, boundary) deny; the other classes keep their ordinary path.
    """
    if harness != 'claude':
        raise ValueError('Unsupported harness')
    if not isinstance(payload, dict):
        return _deny('Malformed hook payload', True) if event == 'PreToolUse' else HookResult({})
    if event == 'SessionStart':
        # Native agent_type, where supplied, is a routing hint, never authentication.
        agent_type = payload.get('agent_type')
        worker = (bool(agent_type) and agent_type not in ('orchestra:orchestrator', 'orchestra_orchestrator', 'orchestra-orchestrator')) or os.environ.get('ORCHESTRA_ROLE', 'main') != 'main'
        skill = Path(__file__).resolve().parents[2] / 'skills/orchestra/SKILL.md'
        context = WORKER_CONTEXT if worker else CONTEXT + ' Skill: ' + str(skill)
        session_id = payload.get('session_id')
        if not worker and harness == 'claude' and engine is not None and payload.get('source') in _REBIND_SOURCES \
                and isinstance(session_id, str) and session_id:
            try:
                engine.apply_harness_rebind(session_id)  # B-F5: the one SessionStart write
            except Exception:
                pass  # An unloadable state or changed contract never blocks the context
        if not worker and engine is not None:
            context += _report_context(engine)
        if not worker and isinstance(session_id, str) and session_id:
            context += ' Harness session id: ' + session_id + '. Pass --harness-session ' + session_id + ' to orchestra.py start.'
        return HookResult({'hookSpecificOutput': {'hookEventName': event, 'additionalContext': context}})
    if event == 'SubagentStart':
        # A11: only Orchestra agents get worker context.
        agent_type = payload.get('agent_type')
        if isinstance(agent_type, str) and agent_type.startswith('orchestra:'):
            return HookResult({'hookSpecificOutput': {'hookEventName': event, 'additionalContext': WORKER_CONTEXT}})
        if _run_active(engine):  # SubagentStart cannot block; the PreToolUse deny below enforces
            return HookResult({'hookSpecificOutput': {'hookEventName': event, 'additionalContext': SUBAGENT_GUARD}})
        return HookResult({})
    if event == 'SessionEnd':
        session_id = payload.get('session_id')
        if engine is None or not isinstance(session_id, str) or not session_id:
            return HookResult({})
        try:
            if payload.get('reason') in ('clear', 'resume'):
                engine.mark_harness_rebind(session_id)  # The process continues under a new id (O6)
            else:
                engine.end_harness_session(session_id)
        except (OSError, ValueError, KeyError, RuntimeError) as exc:
            if not _raw_session_active(engine.state_path):
                return HookResult({})  # O35: an ended run has nothing to record
            return HookResult({'systemMessage': 'Orchestra session end could not be recorded: ' + str(exc)})
        return HookResult({})
    if event == 'Interrupt':
        if engine is not None:
            try:
                engine.interrupt_active()
            except (OSError, ValueError, KeyError, RuntimeError) as exc:
                return HookResult({'systemMessage': 'Orchestra interruption could not be recorded: ' + str(exc)})
        return HookResult({})
    if event == 'Stop':
        if engine is None:
            return HookResult({})
        if busy:
            if not (_raw_autonomy_active(engine.state_path) and _raw_session_active(engine.state_path)):
                return HookResult({})  # Unarmed and busy, or between relaunch passes: nothing to stop, nothing to write
            if not _wait_for_lock(engine.state_dir / 'state.lock', started):
                from .engine import write_busy_brief  # Lazy: tests replace the engine module
                try:
                    write_busy_brief(engine.state_dir, datetime.now(timezone.utc).isoformat(timespec='seconds'))
                except OSError:
                    pass
                return HookResult({})  # Allow the stop; autonomy.active stays true
        if _other_session(engine, payload.get('session_id')):
            return HookResult({})  # O37: a Stop from another harness session neither continues nor spends a pass
        try:
            reason = engine.hook_stop()
            return HookResult({'decision': 'block', 'reason': reason}) if isinstance(reason, str) and reason else HookResult({})
        except (OSError, ValueError, KeyError, RuntimeError, AttributeError):
            return HookResult({})  # Corrupt/unarmed state never creates continuation.
    if event != 'PreToolUse':
        return HookResult({})
    name, data = payload.get('tool_name'), payload.get('tool_input')
    if not isinstance(name, str) or not name or not isinstance(data, dict):
        return _deny('Malformed tool payload', True)
    role = os.environ.get('ORCHESTRA_ROLE', 'main')  # Advisory, caller-controlled marker.
    if harness == 'claude' and isinstance(payload.get('agent_id'), str) and payload['agent_id']:
        role = 'subagent'  # Claude Code sets agent_id only for calls made inside a subagent.
    if role != 'main' and name in {'Agent', 'Task', 'spawn_agent', 'create_thread', 'send_message_to_thread'}:
        return _deny('Workers do not delegate')
    unloaded_run = engine is None and armed and (state_dir is None or _raw_session_active(Path(state_dir) / 'state.json'))
    if role == 'subagent' and _foreign_subagent(payload) and (_run_active(engine) or unloaded_run):
        return _deny(SUBAGENT_GUARD)  # item 9: a Workflow agent never passes the Agent/Task check above it
    if name in {'Agent', 'Task'} and (_run_active(engine) or unloaded_run):  # item 9, failing closed when busy or unloadable
        kind = data.get('subagent_type')
        if not (isinstance(kind, str) and kind.startswith('orchestra:')):
            return _deny(AGENT_GUARD)
    if 'cwd' in payload:
        cwd = payload['cwd']
        if not isinstance(cwd, str):
            return _deny('Malformed cwd', True)
        if not cwd:
            cwd, missing_cwd = None, True  # An empty cwd is a missing one, as main() reads it
    else:
        try:
            cwd = os.getcwd()
        except OSError:  # The process cwd was removed: a missing cwd, never a crash that lets the call run
            cwd, missing_cwd = None, True
    if name in _EDIT_TOOLS:
        try:
            if name == 'apply_patch':
                paths = _patch_paths(data.get('command', data.get('patch')))
            else:
                path = data.get('file_path', data.get('path'))
                if not isinstance(path, str) or not path:
                    raise ValueError('Missing file path')
                paths = [path]
            if cwd is None and not all(os.path.isabs(path) for path in paths):
                return _deny(MISSING_CWD)
            if any(_protected(path, cwd or '/', state_dir) for path in paths):
                return _deny('Use the structured coordinator API for state; protect installed runtime configuration')
        except (ValueError, OSError) as exc:
            return _deny(str(exc), True)
    if name not in _SHELL_TOOLS:
        return HookResult({})
    command = data.get('command', data.get('cmd'))
    if not isinstance(command, str):
        return _deny('Missing shell command', True)
    decision = classify_command(command)
    klass = decision.klass
    if klass == 'deny':
        return _deny(decision.reason, decision.category == 'malformed')
    if klass in {'release', 'release-multi', 'boundary'}:
        if missing_cwd:
            return _deny(MISSING_CWD)
        if busy:
            return _deny(BUSY)
    if role == 'subagent' and str(payload.get('agent_type')).startswith(_REVIEWER_TYPES) and runs_test_suite(command):
        gates = _gate_ids(engine)
        if gates:
            return _deny('Cite gate receipt ' + ', '.join(gates) + '; reviewers do not rerun suites')
    active = (engine is not None and _autonomy_active(engine)) or (engine is None and armed and autonomy)
    if decision.category == 'merged-delete':
        # SPEC 5.14 item 4: before the autonomy-off allow, and with or without an engine.
        denied = _merged_delete_check(decision, cwd, active)
        if denied:
            return HookResult(denied)
    if active:
        # Checked before any permit: a permit never opens a boundary while autonomy is active (12.4).
        if klass in {'release', 'release-multi'} and not (klass == 'release' and _preauthorized(engine, decision)):
            return _deny('Autonomy is active: ' + _PARK_HINT)
        if decision.boundary == 'delete':
            return _deny('Approval boundary under autonomy: ' + _PARK_HINT)
        if decision.category == 'boundary' and decision.boundary == 'merge' and _on_default_branch(cwd):
            return _deny('Approval boundary under autonomy: no merge on the default branch. ' + _PARK_HINT)
    if klass in {'release', 'release-multi'} and (engine is not None or armed):
        if klass == 'release-multi':
            return _deny(decision.reason)
        if engine is None or not decision.remote or not decision.target:
            return _deny('Release needs a configured exact structured command and current permit')
        try:
            permit = engine.check_release(decision.remote, decision.target, argv=list(decision.argv))
            if not permit:
                raise ValueError('No current release permit')
        except (OSError, ValueError, KeyError, RuntimeError, AttributeError) as exc:
            return _deny('Release denied: ' + str(exc))
    return HookResult({})  # allow, boundary (autonomy off) and unarmed release classes


_PARK_HINT = 'park this card with `orchestra.py park TASK --reason ...` and continue with other cards.'


def _wait_for_lock(lock_path, started):
    """Poll for the exclusive state lock until STOP_LOCK_BUDGET seconds after `started`; True when it freed (and is released)."""
    end = (started if started is not None else time.monotonic()) + STOP_LOCK_BUDGET
    with open(lock_path, 'a+') as lock:
        while True:
            try:
                portable.flock(lock, portable.LOCK_EX | portable.LOCK_NB)
                return True  # Closing the file releases it
            except OSError:
                if time.monotonic() >= end:
                    return False
                time.sleep(0.05)


def _autonomy_active(engine):
    try:
        return engine.autonomy_active() is True  # Strict: an opaque adapter never reads as active.
    except Exception:
        return True  # O29: an error while reading autonomy status counts as active.


def _foreign_subagent(payload):
    """A call made inside a subagent whose type is not orchestra:* (a Workflow agent without agentType is
    'workflow-subagent'). agent_type is a routing hint, never authentication."""
    agent_type = payload.get('agent_type')
    return bool(payload.get('agent_id')) and not (isinstance(agent_type, str) and agent_type.startswith('orchestra:'))


def _reviewer_call(payload):
    """A call made inside a reviewer or critic: the mod does not know the test-suite rule, so Python always guards it."""
    return bool(payload.get('agent_id')) and str(payload.get('agent_type')).startswith(_REVIEWER_TYPES)


def _run_active(engine):
    """Item 9: a loaded engine whose session is active. An engine that cannot say counts as active only when the
    raw state shows (or cannot show otherwise) an active session; an inactive raw session allows."""
    if engine is None:
        return False
    try:
        session = engine.status()['session']
        return bool(session) and session.get('active') is True
    except Exception:
        try:
            return _raw_session_active(engine.state_path)
        except Exception:
            return True


def _gate_ids(engine):
    """Item 10: ids of the passed gate receipts for the current artifact; [] with no engine, no method or any error."""
    try:
        ids = engine.current_gate_ids()
        return [str(item) for item in ids] if isinstance(ids, (list, tuple)) else []
    except Exception:  # Includes AttributeError: an engine without the method has no receipts to cite.
        return []


def _preauthorized(engine, decision):
    """SPEC 5.8 item 8.3: the ledger pre-authorized exactly this remote and target. Any doubt reads as no (fail closed);
    the normal permit check still runs after it."""
    try:
        release = engine.status()['autonomy']['release']
        return (isinstance(decision.remote, str) and bool(decision.remote) and isinstance(decision.target, str)
                and bool(decision.target) and release['remote'] == decision.remote and release['target'] == decision.target)
    except Exception:
        return False


def _raw_relaunch_active(state_file):
    """SPEC 5.10 item 3: armed `relaunch` autonomy in a state file the engine cannot load counts as armed."""
    data = _raw_state(state_file)
    auto = data.get('autonomy') if isinstance(data, dict) else None
    return isinstance(auto, dict) and auto.get('active') is True and auto.get('relaunch') is True


def _raw_state(state_file):
    """The unvalidated state of a file the engine cannot load; None when it is unreadable or unparseable."""
    try:
        return json.loads(Path(state_file).read_text())
    except (OSError, ValueError, UnicodeError):
        return None


def _raw_autonomy_active(state_file):
    """O29: the unvalidated `autonomy.active` flag of a state file the engine cannot load; unparseable counts as active."""
    data = _raw_state(state_file)
    if data is None:
        return True
    auto = data.get('autonomy') if isinstance(data, dict) else None
    return isinstance(auto, dict) and auto.get('active') is True


def _other_session(engine, session_id):
    """O37: the run is bound to a harness session and the payload names a different one. Either missing: False."""
    if not isinstance(session_id, str) or not session_id:
        return False
    try:
        bound = engine.status()['session'].get('harness_session')
    except Exception:
        return False  # Opaque adapters and unreadable sessions keep the Stop behavior they had.
    return isinstance(bound, str) and bool(bound) and bound != session_id


def _raw_session_active(state_file):
    """O35: an ended run under a changed policy is unarmed; an unparseable or active state stays armed."""
    data = _raw_state(state_file)
    if not isinstance(data, dict) or 'session' not in data:
        return True  # Unparseable or not a recorded session: fail closed.
    session = data['session']
    return not (session is None or (isinstance(session, dict) and session.get('active') is False))


def _report_context(engine):
    try:
        brief = engine.status().get('last_brief')
        if isinstance(brief, dict) and isinstance(brief.get('text'), str):
            return ' Run brief (' + str(brief.get('reason')) + '): ' + brief['text'][:2000] \
                + ' Full report: ' + str(brief.get('path')) + '.'
        report = engine.autonomy_report()
    except Exception:
        return ''
    if not isinstance(report, dict) or not isinstance(report.get('text'), str):
        return ''
    return ' Autonomy report (' + str(report.get('reason')) + '): ' + report['text'][:2000] \
        + ' Full report: ' + str(report.get('path')) + '.'


def _git_out(repo, *args, timeout=10):
    """(returncode, stdout) of a git command in repo; a spawn error or timeout is (1, '') so callers fail closed."""
    try:
        done = subprocess.run(['git', '-C', str(repo), *args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              stdin=subprocess.DEVNULL, timeout=timeout)
        return done.returncode, done.stdout.decode(errors='replace').strip()
    except (OSError, subprocess.SubprocessError):
        return 1, ''


def _first_parent_trees(repo, default):
    """The trees of the first-parent commits of default, at most 2000 (one rev-list call)."""
    code, out = _git_out(repo, 'rev-list', '--first-parent', '-n2000', '--format=%T', default, timeout=30)
    return {line for line in out.splitlines() if line and not line.startswith('commit ')} if code == 0 else set()


def _branch_merged(repo, tip, default):
    """SPEC 5.14 item 4.5: tip is an ancestor of default, or its tree is a first-parent tree of default,
    or tip is an ancestor of a local or remote-tracking ref whose tree is (evaluated afresh at each delete)."""
    if _git_out(repo, 'merge-base', '--is-ancestor', tip, default)[0] == 0:
        return True
    trees = _first_parent_trees(repo, default)
    if not trees:
        return False
    code, tree = _git_out(repo, 'rev-parse', '--verify', '--quiet', tip + '^{tree}')
    if code == 0 and tree in trees:
        return True
    code, out = _git_out(repo, 'for-each-ref', '--contains', tip, '--format=%(refname)%09%(tree)', 'refs/heads', 'refs/remotes', timeout=30)
    if code != 0:
        return False
    return any(line.partition('\t')[2] in trees for line in out.splitlines() if '\t' in line)


def _remote_tip_matches(repo, remote, branch):
    """SPEC 5.14 item 4.4: `git ls-remote` reports the branch at the remote-tracking tip. Prompts are off and
    the call has a 3 s limit; any failure, timeout or difference is False."""
    code, tracking = _git_out(repo, 'rev-parse', '--verify', '--quiet', 'refs/remotes/%s/%s' % (remote, branch))
    if code != 0 or not tracking:
        return False
    env = dict(os.environ, GIT_TERMINAL_PROMPT='0')
    try:
        proc = subprocess.Popen(['git', '-C', str(repo), 'ls-remote', remote, 'refs/heads/' + branch], env=env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                start_new_session=True)
    except OSError:
        return False
    try:
        out, _ = proc.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            portable.kill_tree(proc)
        except OSError:
            pass
        proc.communicate()
        return False
    if proc.returncode != 0:
        return False
    rows = [line.split() for line in out.decode(errors='replace').splitlines() if line.strip()]
    return len(rows) == 1 and len(rows[0]) == 2 and rows[0][0] == tracking and rows[0][1] == 'refs/heads/' + branch


def _merged_delete_check(decision, cwd, autonomy):
    """SPEC 5.14 item 4: a deny payload for a merged-delete that is not safe, else None."""
    if autonomy:
        return _deny('Approval boundary under autonomy: ' + _PARK_HINT).output
    branch, remote = decision.branch, decision.remote if decision.kind == 'remote' else None
    if not branch:
        return _deny('Branch deletion must run plainly in the session repository').output
    if remote and _git_out(cwd, 'config', '--get', 'remote.%s.url' % remote)[1] == '':
        return _deny('Remote %s is not configured' % remote).output
    if remote:
        # The delete goes to the push URL and ls-remote reads the fetch URL: both must name one repository.
        code, fetch = _git_out(cwd, 'remote', 'get-url', remote)
        pcode, pushes = _git_out(cwd, 'remote', 'get-url', '--push', '--all', remote)
        if code != 0 or pcode != 0 or not fetch or any(url != fetch for url in pushes.splitlines() or ['']):
            return _deny('Remote %s push URL differs from its fetch URL; refusing to delete %s' % (remote, branch)).output
    # Full refnames only (R2): a local branch or tag named origin/main must not shadow the default, and a ref
    # is read only after it exists exactly, so rev-parse's short-name lookup never finds a decoy (G2f).
    tracked = 'refs/remotes/%s/' % (remote or 'origin')
    heads = [tracked + 'HEAD', tracked + 'main'] + ([] if remote else ['refs/heads/main'])
    default = sha = None
    for ref in heads:
        if ref.endswith('/HEAD'):
            ref = _git_out(cwd, 'symbolic-ref', '--quiet', ref)[1]
        if not ref or _git_out(cwd, 'show-ref', '--verify', '--quiet', ref)[0] != 0:
            continue
        code, target = _git_out(cwd, 'rev-parse', '--verify', '--quiet', ref + '^{commit}')
        if code == 0 and target:
            default, sha = ref, target
            break
    if sha is None:
        return _deny('The default branch cannot be resolved; refusing to delete %s' % branch).output
    if default.startswith(tracked):
        name, label = default[len(tracked):], default[len('refs/remotes/'):]
    elif default.startswith('refs/heads/'):
        name = label = default[len('refs/heads/'):]
    else:
        return _deny('The default branch cannot be resolved; refusing to delete %s' % branch).output
    # FS2-1: on a case-insensitive filesystem refs/heads/Main is the file refs/heads/main.
    fold = (lambda text: text.casefold()) if _git_out(cwd, 'config', '--bool', 'core.ignorecase')[1] == 'true' else (lambda text: text)
    if fold(branch) == fold(name):
        return _deny('Branch %s is the default branch' % branch).output
    code, current = _git_out(cwd, 'symbolic-ref', '--short', '-q', 'HEAD')
    if code == 0 and fold(current) == fold(branch):
        return _deny('Branch %s is checked out' % branch).output
    namespace = 'refs/remotes/%s/' % remote if remote else 'refs/heads/'
    tracking = namespace + branch
    # The tip comes from the exact listed row: rev-parse would resolve a case variant to another branch's tip,
    # and with a case twin (FC3) git deletes both refs, so a twin is never deleted whatever core.ignorecase says.
    code, listing = _git_out(cwd, 'for-each-ref', '--format=%(refname)%09%(objectname)', namespace)
    rows = dict(line.split('\t', 1) for line in listing.splitlines() if '\t' in line) if code == 0 else {}
    if tracking not in rows:
        return _deny('Branch %s does not exist' % branch).output
    if any(ref != tracking and ref.casefold() == tracking.casefold() for ref in rows):
        return _deny('Branch %s has a case-variant twin; refusing to delete' % branch).output
    code, tip = _git_out(cwd, 'rev-parse', '--verify', '--quiet', rows[tracking] + '^{commit}')
    if code != 0 or not tip:
        return _deny('Branch %s does not exist' % branch).output
    if remote and not _remote_tip_matches(cwd, remote, branch):
        return _deny('Remote %s does not report %s at the tracking tip' % (remote, branch)).output
    if not _branch_merged(cwd, tip, sha):
        return _deny('Branch %s is not merged into %s (no ancestor, tree or covering-branch evidence)' % (branch, label)).output
    return None


def _on_default_branch(cwd):
    """SPEC 5.1: the branch is read from the payload cwd's own worktree; any doubt counts as the default branch."""
    try:
        current = subprocess.check_output(['git', '-C', str(cwd), 'symbolic-ref', '--short', 'HEAD'],
                                          stderr=subprocess.PIPE, timeout=10).decode().strip()
    except (OSError, subprocess.SubprocessError):
        return True  # Detached HEAD or a git error: fail closed.
    try:
        head = subprocess.check_output(['git', '-C', str(cwd), 'symbolic-ref', '--short', 'refs/remotes/origin/HEAD'],
                                       stderr=subprocess.PIPE, timeout=10).decode().strip()
        default = head[len('origin/'):] if head.startswith('origin/') else head
    except (OSError, subprocess.SubprocessError):
        default = 'main'
    return current == default


def _main_worktree(cwd):
    """A15: the main worktree of a linked worktree; None for a bare common directory."""
    common = subprocess.check_output(['git', '-C', str(cwd), 'rev-parse', '--git-common-dir'],
                                     stderr=subprocess.PIPE).decode().strip()
    path = (Path(cwd) / common).resolve()  # A relative result is relative to cwd; an absolute one wins the join.
    return path.parent if path.name == '.git' else None


def _run_location(cwd):
    """Return (repo, state_dir) of the run that governs this cwd; own state first (A15)."""
    from .paths import repository, state_location
    repo = repository(cwd)
    state_dir = state_location(repo)
    if not (state_dir / 'state.json').is_file():
        main = _main_worktree(cwd)
        if main is not None and main != repo and (state_location(main) / 'state.json').is_file():
            return main, state_location(main)
    return repo, state_dir


def _mod_is_live(payload):
    """A12: a fresh marker carrying this copy's rules hash means the mod already guarded."""
    session = payload.get('session_id')
    if not isinstance(session, str) or not re.fullmatch(_MARKER['session_id_pattern'], session):
        return False
    try:
        marker = json.loads((_marker_dir() / (session + '.json')).read_text())
        age = int(time.time() * 1000) - marker['heartbeat_ms']
        return (marker['session_id'] == session and not isinstance(marker['heartbeat_ms'], bool)
                and 0 <= age < _MARKER['fresh_ms']
                and marker['rules_sha256'] == guard_digest())
    except (OSError, ValueError, KeyError, TypeError):
        return False


def main(argv=None):
    started = time.monotonic()
    parser = argparse.ArgumentParser()
    parser.add_argument('event', choices=['SessionStart', 'PreToolUse', 'SubagentStart', 'Stop', 'Interrupt', 'SessionEnd'])
    parser.add_argument('--harness', choices=['claude'], default='claude')
    parser.add_argument('--from-mod', action='store_true')
    args = parser.parse_args(argv)
    try:
        payload = json.load(sys.stdin)
    except (ValueError, UnicodeError):
        payload = None
    if (args.event == 'PreToolUse' and args.harness == 'claude' and not args.from_mod
            and isinstance(payload, dict) and payload.get('tool_name') in _MOD_TOOLS and not _reviewer_call(payload)
            and not _foreign_subagent(payload)
            and _mod_is_live(payload)):
        print('{}')
        return 0
    state_dir = os.environ.get('ORCHESTRA_STATE_DIR')
    engine = None
    armed = False
    autonomy = False
    busy = False
    missing_cwd = False
    build_error = None
    if args.event in {'PreToolUse', 'Interrupt', 'Stop', 'SubagentStart'} and isinstance(payload, dict) and isinstance(payload.get('cwd'), str):
        missing_cwd = args.event == 'PreToolUse' and not os.path.isdir(payload['cwd'])
        try:
            from .paths import load_policy
            repo, state_dir = _run_location(payload['cwd'])
            # Discovery is read-only. Construct the engine only for an existing run.
            if (state_dir / 'state.json').is_file():
                armed = True  # A state file that cannot be loaded fails closed: armed, no permit.
                try:
                    from .engine import Engine
                    engine = Engine(state_dir, repo, policy=load_policy(state_dir), lock_wait=LOCK_WAIT)
                    try:
                        session = engine.status()['session']
                        armed = bool(session and session.get('active'))
                        if not armed and engine.autonomy_active() is True:
                            armed = True  # SPEC 5.10 item 3: armed relaunch autonomy applies between passes
                    except (TypeError, KeyError, AttributeError):
                        pass  # Opaque engine adapters stay armed.
                except Exception as exc:
                    busy = type(exc).__name__ == 'StateBusy'  # By name: the engine module may be replaced in tests
                    if not (busy and args.event != 'PreToolUse'):
                        engine = None  # A busy Stop or Interrupt keeps its engine: Stop polls the lock, Interrupt blocks on it
                    armed = (_raw_session_active(state_dir / 'state.json')  # O35
                             or _raw_relaunch_active(state_dir / 'state.json'))
                    autonomy = _raw_autonomy_active(state_dir / 'state.json')
                if args.event in {'PreToolUse', 'SubagentStart'} and not armed:
                    engine = None  # An inactive session is an unarmed run.
        except (ImportError, OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            pass
    if (args.event in {'SessionStart', 'SessionEnd'} and isinstance(payload, dict) and isinstance(payload.get('cwd'), str)
            and (args.event == 'SessionStart' or args.event == 'SessionEnd')):
        try:
            from .paths import load_policy
            from .engine import Engine
            repo, state_dir = _run_location(payload['cwd'])
            if (state_dir / 'state.json').is_file():
                engine = Engine(state_dir, repo, policy=load_policy(state_dir), lock_wait=LOCK_WAIT)
        except Exception as exc:
            engine = None  # Unloadable state: SessionStart still returns context; a lost lease is recovered by hand
            if (args.event == 'SessionEnd' and state_dir is not None and (Path(state_dir) / 'state.json').is_file()
                    and _raw_session_active(Path(state_dir) / 'state.json')):  # O35: an ended run has nothing to record
                build_error = exc
    result = handle_event(args.event, payload, harness=args.harness, state_dir=state_dir, engine=engine, armed=armed,
                          autonomy=autonomy, busy=busy, missing_cwd=missing_cwd, started=started)
    if build_error is not None and not result.output:
        result = HookResult({'systemMessage': 'Orchestra session end could not be recorded: ' + str(build_error)
                             + '. A run that holds a lost lease is recovered by hand with '
                             + '`orchestra.py --actor A --lease L interrupt` (A and L from the start receipt).'})
    print(json.dumps(result.output))
    if result.exit_code == 2:
        print(result.output['hookSpecificOutput']['permissionDecisionReason'], file=sys.stderr)
    return result.exit_code


if __name__ == '__main__':
    sys.exit(main())
