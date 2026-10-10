#!/usr/bin/env python3
"""Portable Orchestra CLI. Each command prints a JSON receipt."""
import argparse
from orchestra_core import portable
import json
import os
from pathlib import Path
import shlex
import signal
import math
import subprocess
import sys
import uuid

from orchestra_core.engine import ACTIVE_MISMATCH, ASKS_ERROR, Engine, EngineError
from orchestra_core.guards import classify_command
from orchestra_core.paths import atomic, load_policy, repository, state_location
from orchestra_core import relaunch

ROOT = Path(__file__).resolve().parents[1]


def read_json(path):
    return json.loads(Path(path).read_text())


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', default=os.getcwd())
    p.add_argument('--state', help='External run directory; defaults to user state for this repository')
    p.add_argument('--actor', default='main', help='Workflow identity, not an authenticated principal')
    p.add_argument('--lease', help='Coordinator lease returned by start')
    sub = p.add_subparsers(dest='command', required=True)
    start = sub.add_parser('start')
    start.add_argument('--policy', help='Explicit JSON policy; copied outside the application')
    start.add_argument('--harness-session', help='Harness session id (from the SessionStart context); ending that session releases the run')
    start.add_argument('--size', choices=['tiny', 'medium', 'large'], help='Size of the largest ask in the request (required when '
                       'this opens a new run): tiny up to 50 changed lines, medium up to 400; large only with --owner-request')
    start.add_argument('--asks', help='Number of separately stated asks (default 1); the size-check budget is the tier guide times it')
    start.add_argument('--owner-request', action='store_true', help='The owner asked for a map: allows a large start and plan cards')
    start.add_argument('--items', type=int, help='The 2.4 flag; refused, start with --size')
    start.add_argument('--new-run', action='store_true', help='Archive a previously inactive run before starting')
    sub.add_parser('where', help='Print the repository, state directory and whether standing-orders.md exists')
    for name in ['status','ready','board','interrupt','finish','scan']:
        sub.add_parser(name)
    sub.add_parser('brief', help='Print the newest run brief; no lease, read-only')
    art = sub.add_parser('artifact', help='Print the whole-repo artifact, or with --tasks the artifact scoped to those cards\' reserved files')
    art.add_argument('--tasks', help='Comma-separated task IDs')
    sub.add_parser('prepr', help='Print the pre-PR size check and reviewer choice; no lease, read-only')
    route = sub.add_parser('route', help='Change the size tier (--size, optionally --asks), or on a 2.4 run the item count '
                                         '(--items; 1 to 5 inline, 6 or more workflow), and log the reason')
    route.add_argument('--size', choices=['tiny', 'medium', 'large'])
    route.add_argument('--asks', help='With --size: the new count of separately stated asks; default keeps the current count')
    route.add_argument('--items', type=int, help='2.4 runs only')
    route.add_argument('--reason', required=True)
    add = sub.add_parser('add', help='Add a card from a task JSON file. Inline route: no designer-planner plan card. '
                                     'Order cards with dependencies')
    add.add_argument('task', help='Task JSON path')
    dispatch = sub.add_parser('dispatch')
    dispatch.add_argument('task_id')
    dispatch.add_argument('worker')
    dispatch.add_argument('--helper', metavar='REASON', help='Why a helper does this builder card instead of the main session: '
                          'required for a tiny unit on a size run, and for a 2.4 inline route. 2.4 workflow route: a builder '
                          'card needs an accepted designer-planner plan card first')
    inline = sub.add_parser('inline', help='Reserve a card for execution by the main coordinator')
    inline.add_argument('task_id')
    report = sub.add_parser('report')
    report.add_argument('worker')
    report.add_argument('token')
    report.add_argument('report', help='Nonempty result file')
    accept = sub.add_parser('accept')
    accept.add_argument('task_id')
    review = sub.add_parser('review')
    review.add_argument('report', help='Structured review JSON path')
    gate = sub.add_parser('gate')
    gate.add_argument('name')
    gate.add_argument('--again', action='store_true', help='Rerun a gate that already passed on this artifact')
    gate.add_argument('--timeout', type=float, help='Seconds for this run; overrides gate_timeout_seconds')
    gate.add_argument('argv', nargs=argparse.REMAINDER)
    finding = sub.add_parser('finding', help='Record or list dispositions of review findings')
    findings = finding.add_subparsers(dest='finding_command', required=True)
    fadd = findings.add_parser('add')
    fadd.add_argument('--review', required=True)
    fadd.add_argument('--kind', required=True, choices=['finding', 'out_of_scope'])
    fadd.add_argument('--index', required=True, type=int)
    fadd.add_argument('--disposition', required=True)
    fadd.add_argument('--reason', required=True)
    fadd.add_argument('--card')
    flist = findings.add_parser('list')
    flist.add_argument('--for-brief', action='store_true')
    for name in ['permit','release']:
        action = sub.add_parser(name)
        action.add_argument('remote')
        action.add_argument('target')
    autonomy = sub.add_parser('autonomy', help='Arm, disarm or inspect the autonomous loop; takes no lease')
    autonomy.add_argument('action', choices=['arm','disarm','status','settle'])
    autonomy.add_argument('--relaunch', action='store_true', help='With arm: keep autonomy armed between sessions for the relaunch harness')
    rl = sub.add_parser('relaunch', help='Run fresh `claude -p` passes until autonomy stops; run it in your terminal with no session active')
    rl.add_argument('--permission-mode', required=True, help='Permission mode for each pass; no default')
    rl.add_argument('--model', help='Model id for each pass; unset by default')
    rl.add_argument('--launcher', nargs=argparse.REMAINDER, help='Replace the claude command with this argv (prompt on stdin); must come last')
    park = sub.add_parser('park', help='Set a card aside at an approval boundary')
    park.add_argument('task_id')
    park.add_argument('--reason', required=True)
    unpark = sub.add_parser('unpark', help='Return a parked card to the queue')
    unpark.add_argument('task_id')
    hold = sub.add_parser('hold', help='End the repair ladder: move a blocked repair chain to held and log the finding')
    hold.add_argument('task_id')
    hold.add_argument('--finding', required=True)
    classify = sub.add_parser('classify')
    classify.add_argument('shell_command')
    return p


def parse_asks(text):
    if text is None:
        return None
    try:
        return int(text)
    except ValueError:
        raise EngineError(ASKS_ERROR) from None


def archive_inactive(state,engine):
    with (state/'state.lock').open('a') as stream:
        portable.flock(stream,portable.LOCK_EX)
        source = state/'state.json'
        if not source.exists():
            return
        old = read_json(source)
        if old.get('session',{}).get('active'):
            if old.get('repo') != str(engine.repo) or not engine.binds(old):
                raise EngineError(ACTIVE_MISMATCH)  # O35: same recovery as the engine gives
            raise EngineError('Stop or finish the active run before starting another')
        archive = {'state':old,'policy':load_policy(state)}
        atomic(state/'history'/('run-'+uuid.uuid4().hex+'.json'),json.dumps(archive,indent=2).encode())
        source.unlink()  # Receipts and logs remain at their existing immutable paths.


def execute(args):
    if args.command == 'classify':
        return classify_command(args.shell_command).__dict__,0
    repo = repository(args.repo)
    state = Path(args.state).expanduser().resolve() if args.state else state_location(repo)
    if args.command=='where':
        return {'repo':str(repo),'state':str(state),'standing_orders':(state/'standing-orders.md').is_file()},0
    if args.command=='relaunch':
        return None,relaunch.run(repo,state,args.permission_mode,model=args.model,launcher=args.launcher or None)
    policy = read_json(args.policy) if args.command=='start' and args.policy else load_policy(state)
    engine = Engine(state,repo,policy)
    if args.command=='start':
        if args.items is not None:
            raise EngineError('--items is the 2.4 flag; start with --size')
        asks = parse_asks(args.asks)
        if args.new_run:  # refuse before archiving, so the ended run stays in place
            engine._check_start(args.size,asks,args.owner_request)
            archive_inactive(state,engine)
        lease = engine.open_session(args.actor,args.harness_session,relaunch_pass=os.environ.get('ORCHESTRA_RELAUNCH_PASS') or None,
                                    size=args.size,asks=asks,owner_request=args.owner_request,require_size=True)
        if args.policy:
            atomic(state/'policy.json',(json.dumps(policy,indent=2)+'\n').encode())
        return {'lease':lease,'state':str(state),'repo':str(repo)},0
    if args.command=='status':
        return engine.status(lenses=True),0
    if args.command=='prepr':  # lease-free and read-only, like status
        result=engine.prepr()
        if result['warning']:
            print(result['warning'],file=sys.stderr)
        return result,0
    if args.command=='brief':  # lease-free and read-only, like status
        text=engine.brief()
        return ({'brief':text} if text else {'brief':None,'message':'No run brief yet'}),0
    if args.command=='autonomy':  # O8: no lease, so the ledger is armed from outside the run
        if args.relaunch and args.action!='arm':
            raise EngineError('--relaunch is only valid with arm')
        if args.action=='arm':
            return engine.arm_autonomy(relaunch=args.relaunch),0
        return {'disarm':engine.disarm_autonomy,'status':engine.autonomy_status,'settle':engine.settle}[args.action](),0
    if args.command=='artifact':
        ids=[i for i in (args.tasks or '').split(',') if i]
        if args.tasks is not None and not ids:
            raise EngineError('--tasks needs at least one task id')
        return engine.artifact(engine.scope_for(ids) if ids else None),0
    if args.command=='inline':
        return {'token':engine.start_inline(args.actor,args.lease,args.task_id), 'executor':args.actor, 'inline':True},0
    if args.command=='finding' and args.finding_command=='list':  # lease-free, like status
        result = engine.list_findings(args.for_brief)
        return ({'findings':result} if isinstance(result,str) else result),0
    if args.command=='board':
        cards = engine.status()['tasks'].values()
        board = {}
        for card in cards:
            board.setdefault(card['role'],{}).setdefault(card['state'],[]).append(card['id'])
        return board,0
    if args.command=='report':
        engine.report(args.worker,args.token,Path(args.report).read_text())
        return {'reported':args.token},0
    if not args.lease:
        raise EngineError('Supply --lease from start for coordinator actions')
    if args.command=='ready':
        return {'ready':engine.ready(args.actor,args.lease)},0
    if args.command in ['interrupt','finish']:
        if args.command=='finish':
            engine.close_session(args.actor,args.lease)
        else:
            engine.interrupt(args.actor,args.lease)
        return {'session':args.command,'state':str(state)},0
    if args.command=='add':
        engine.add_task(args.actor,args.lease,read_json(args.task))
        return {'added':read_json(args.task)['id']},0
    if args.command=='dispatch':
        token = engine.dispatch(args.actor,args.lease,args.task_id,args.worker,helper=args.helper)
        return {'assignment':token,'task':args.task_id,'worker':args.worker},0
    if args.command=='accept':
        engine.accept(args.actor,args.lease,args.task_id)
        return {'accepted':args.task_id},0
    if args.command=='review':
        review = read_json(args.report)
        result = engine.record_review(args.actor,args.lease,review['reviewer'],args.report,
                                     review['categories'],review['tasks'],review['final'],review['findings'])
        return result,0
    if args.command=='gate':
        argv, again, timeout = args.argv, args.again, args.timeout
        while argv[:1] in (['--again'], ['--timeout']):  # REMAINDER swallows flags written after NAME
            if argv[0]=='--again':
                argv, again = argv[1:], True
            else:
                try:
                    argv, timeout = argv[2:], float(argv[1])
                except (IndexError, ValueError):
                    raise EngineError('Gate timeout must be positive and finite') from None
        argv = argv[1:] if argv[:1]==['--'] else argv
        result = engine.run_gate(args.actor,args.lease,args.name,argv,again=again,timeout=timeout)
        return result,0 if result['passed'] else 1
    if args.command=='finding':
        return engine.add_finding(args.actor,args.lease,args.review,args.kind,args.index,args.disposition,args.reason,args.card),0
    if args.command=='scan':
        result=engine.run_secret_scan(args.actor,args.lease)
        return result,0 if result.get('passed') or result.get('unavailable') else 1
    if args.command=='permit':
        return engine.release_permit(args.actor,args.lease,args.remote,args.target),0
    if args.command=='release':
        engine.validate_lease(args.actor,args.lease)
        argv = engine.policy['release']['argv']
        engine.check_release(args.remote,args.target,argv=argv)
        # Reject destructive forms even when an operator accidentally configures one.
        if classify_command(shlex.join(argv)).action=='deny':
            raise EngineError('Configured release command violates the shared guard')
        timeout=engine.policy.get('release_timeout_seconds',600)
        if isinstance(timeout,bool) or not isinstance(timeout,(int,float)) or not math.isfinite(timeout) or timeout<=0:
            raise EngineError('Release timeout must be positive and finite')
        before=engine.artifact()
        log=state/('release-'+uuid.uuid4().hex+'.log')
        with log.open('xb') as stream:
            try:
                engine.validate_lease(args.actor,args.lease)
                engine.check_release(args.remote,args.target,argv=argv)
                process=subprocess.Popen(argv,cwd=repo,stdout=stream,stderr=subprocess.STDOUT,
                                         start_new_session=True)
                try:
                    code=process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    try:
                        portable.kill_tree(process)
                    except ProcessLookupError:
                        pass
                    process.wait()
                    raise
            except subprocess.TimeoutExpired:
                code=124
                stream.write(b'Release timed out; inspect remote state before any retry.\n')
            except OSError as exc:
                code=127
                stream.write(str(exc).encode())
            stream.flush()
            os.fsync(stream.fileno())
        import hashlib
        receipt={'action':'release','argv':argv,'exit_code':code,'artifact':before,
                 'after':engine.artifact(),'log':str(log),'sha256':hashlib.sha256(log.read_bytes()).hexdigest(),
                 'remote':args.remote,'target':args.target}
        atomic(state/('release-receipt-'+uuid.uuid4().hex+'.json'),json.dumps(receipt,indent=2).encode())
        return receipt,0 if code==0 else 1
    if args.command=='park':
        engine.park(args.actor,args.lease,args.task_id,args.reason)
        return {'parked':args.task_id},0
    if args.command=='unpark':
        engine.unpark(args.actor,args.lease,args.task_id)
        return {'unparked':args.task_id},0
    if args.command=='hold':
        return engine.hold(args.actor,args.lease,args.task_id,args.finding),0
    if args.command=='route':
        return engine.set_route(args.actor,args.lease,args.items,args.reason,size=args.size,asks=parse_asks(args.asks)),0
    raise EngineError('Unsupported command')


def main(argv=None):
    args=parser().parse_args(argv)
    try:
        result,code=execute(args)
    except (EngineError,ValueError,OSError,KeyError,subprocess.SubprocessError) as exc:
        print(json.dumps({'error':str(exc)}),file=sys.stderr)
        return 2
    if result is not None:
        print(json.dumps(result,indent=2))
    return code


if __name__=='__main__':
    sys.exit(main())
