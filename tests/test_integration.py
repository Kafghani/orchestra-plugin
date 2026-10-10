"""Exercise a real local repository and release target through the public CLI."""
import contextlib
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import shutil
import tempfile
import unittest

FIXTURES=Path(__file__).resolve().parent/'fixtures'
PLUGIN=Path(__file__).resolve().parents[1]/'plugins/orchestra'

CLI=PLUGIN/'scripts/orchestra.py'
SH=shutil.which('sh') or '/bin/sh'
HOOK=PLUGIN/'scripts/run-hook.sh'
CATEGORIES=['requirements','correctness','security','tests','architecture','standards','cleanup']
BASE=['requirements','correctness','tests','architecture']
SELF_REVIEW='ARTIFACT: fixture\nSELF_REVIEW: '+json.dumps(dict(checks=[dict(command='fixture check',exit_code=0)],
                                          criteria=[dict(criterion='fixture outcome',met=True,evidence='Inspected fixture.')]))


class WorkflowIntegration(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='Orchestra integration spaces ')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.repo=self.root/'project with spaces'
        self.repo.mkdir()
        self.state=self.root/'outside run state'
        self.git('init','-b','main')
        self.git('config','user.name','Integration')
        self.git('config','user.email','integration@example.invalid')
        (self.repo/'fixture.txt').write_text('ready\n')
        self.git('add','fixture.txt')
        self.git('commit','-m','Fixture')
        self.remote=self.root/'local bare target'
        subprocess.run(['git','init','--bare',str(self.remote)],check=True,capture_output=True)
        self.git('remote','add','fixture-remote',str(self.remote))
        self.check=[sys.executable,'-c',"from pathlib import Path; assert Path('fixture.txt').read_text() == 'ready\\n'"]
        policy={'schema_version':1,'required_checks':[{'name':'fixture','argv':self.check}],
                'release':{'enabled':True,'authorization':'Isolated local fixture push only',
                           'remote':'fixture-remote','target':'main','argv':['git','push','fixture-remote','main']}}
        self.policy=self.write('policy.json',policy)
        self.lease=self.cli('start','--size','medium','--policy',str(self.policy))[1]['lease']

    def git(self,*args):
        return subprocess.check_output(['git','-C',str(self.repo),*args],stderr=subprocess.PIPE).decode().strip()

    def write(self,name,data):
        p=self.root/name
        p.write_text(json.dumps(data) if not isinstance(data,str) else data)
        return p

    def cli(self,*args,lease=False,expected=0):
        cmd=[sys.executable,str(CLI),'--repo',str(self.repo),'--state',str(self.state)]
        if lease:
            cmd+=['--lease',self.lease]
        args=list(args)
        if args[:1]==['dispatch']:  # a helper is accepted and ignored on a medium card
            args+=['--helper','fixture helper']
        if args[:1]==['report']:
            path=Path(args[3])
            if 'SELF_REVIEW:' not in path.read_text():
                path.write_text(path.read_text()+'\n'+SELF_REVIEW+'\n')
        result=subprocess.run(cmd+args,capture_output=True,text=True,timeout=25)
        self.assertEqual(result.returncode,expected,result.stderr+result.stdout)
        return result,json.loads(result.stdout if expected==0 else result.stderr)

    def review(self,ids,final=False,summary='Inspected fixture source and concrete failure checks.'):
        assert final, 'only the pre-PR review is recorded'
        artifact=self.cli('artifact')[1]
        ids=list(self.cli('status')[1]['tasks'])
        p=self.write('final.json',
                     dict(reviewer='independent-reviewer',categories=BASE,tasks=ids,findings=[],issues=[],
                          verdict='CLEAN',final=True,summary=summary,artifact=artifact))
        self.cli('review',str(p),lease=True)

    def configure_local_release(self, argv, timeout=2):
        self.cli('interrupt', lease=True)
        policy=json.loads(self.policy.read_text())
        policy['release']['argv']=argv
        policy['release_timeout_seconds']=timeout
        self.policy.write_text(json.dumps(policy))
        self.lease=self.cli('start','--new-run','--size','medium','--policy',str(self.policy))[1]['lease']
        self.cli('gate','fixture','--',*self.check,lease=True)
        self.review([],True)
        self.cli('permit','fixture-remote','main',lease=True)

    def release_process(self, actor='main', lease=None):
        return subprocess.run([sys.executable,str(CLI),'--repo',str(self.repo),'--state',str(self.state),
                               '--actor',actor,'--lease',lease or self.lease,
                               'release','fixture-remote','main'],capture_output=True,text=True,timeout=10)

    def test_release_rejects_wrong_actor_and_stale_lease_before_execution(self):
        flag=self.root/'release executed'
        self.configure_local_release([sys.executable,'-c',f'from pathlib import Path; Path({str(flag)!r}).touch()'])
        for actor,lease in [('worker',self.lease),('main','stale-lease')]:
            with self.subTest(actor=actor):
                result=self.release_process(actor,lease)
                self.assertEqual(result.returncode,2,result.stdout+result.stderr)
                self.assertFalse(flag.exists())
                self.assertEqual(list(self.state.glob('release-*.log')),[])

    def test_release_timeout_kills_descendants(self):
        flag=self.root/'descendant survived'
        started=self.root/'descendant started'
        child=f"import time; from pathlib import Path; Path({str(started)!r}).touch(); time.sleep(1); Path({str(flag)!r}).touch()"
        parent=f"import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', {child!r}]); time.sleep(5)"
        self.configure_local_release([sys.executable,'-c',parent],timeout=0.5)
        result=self.release_process()
        self.assertEqual(result.returncode,1,result.stderr)
        self.assertEqual(json.loads(result.stdout)['exit_code'],124)
        import time
        self.assertTrue(started.exists(),'Release must start the child before the timeout')
        time.sleep(1.2)
        self.assertFalse(flag.exists(),'Timed out release left a running child')

    def test_release_spawn_failure_has_actual_exit_receipt(self):
        self.configure_local_release([str(self.root/'missing-executable')])
        result=self.release_process()
        self.assertEqual(result.returncode,1,result.stderr)
        receipt=json.loads(result.stdout)
        self.assertEqual(receipt['exit_code'],127)
        self.assertRegex(Path(receipt['log']).read_text(),'No such file|cannot find the file')
        self.assertEqual(len(list(self.state.glob('release-receipt-*.json'))),1)

    def test_local_release_and_repeated_run(self):
        for ident,file in [('B1','one.txt'),('B2','two.txt')]:
            task=dict(id=ident,role='builder',mode='implementation',inputs=['fixture outcome'],acceptance=['fixture check'],
                      files=[file],resources=[],dependencies=[],outcome='fixture outcome')
            self.cli('add',str(self.write(ident+'.json',task)),lease=True)
            token=self.cli('dispatch',ident,'worker-'+ident,lease=True)[1]['assignment']
            self.cli('report','worker-'+ident,token,str(self.write(ident+'.txt','Inspected fixture; no source change needed.')))
        self.assertNotIn('lease',json.dumps(self.cli('status')[1]))
        for removed in ('audit-policy','review-groups'):
            result=subprocess.run([sys.executable,str(CLI),'--repo',str(self.repo),'--state',str(self.state),removed],
                                  capture_output=True,text=True,timeout=25)
            self.assertNotEqual(result.returncode,0,removed)
        self.cli('finish',lease=True,expected=2)
        for ident in ['B1','B2']:
            self.cli('accept',ident,lease=True)
        self.cli('gate','fixture','--',*self.check,lease=True)
        self.review(['B1','B2'],True)
        self.cli('permit','fixture-remote','main',lease=True)
        payload=json.dumps({'cwd':str(self.repo),'tool_name':'Bash','tool_input':{'command':'git push fixture-remote main'}})
        result=subprocess.run([SH,str(HOOK),'PreToolUse','--harness','claude'],input=payload,capture_output=True,text=True,
                              env={**os.environ,'ORCHESTRA_STATE_DIR':str(self.state)},timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn('permissionDecision',result.stdout)
        self.cli('release','fixture-remote','main',lease=True)
        remote_head=subprocess.check_output(['git','--git-dir',str(self.remote),'rev-parse','refs/heads/main']).decode().strip()
        self.assertEqual(remote_head,self.git('rev-parse','HEAD'))
        self.cli('finish',lease=True)
        self.lease=self.cli('start','--new-run','--size','medium')[1]['lease']
        self.assertEqual(self.cli('status')[1]['tasks'],{})
        self.assertEqual(len(list((self.state/'history').glob('*.json'))),1)
        self.assertEqual(self.git('status','--porcelain'),'')

    def test_inline_card_uses_main_actor_and_accepts_on_self_review(self):
        task=dict(id='INLINE',role='builder',mode='implementation',inputs=['fixture'],
                  acceptance=['fixture check'],files=['fixture.txt'],resources=[],dependencies=[])
        self.cli('add',str(self.write('inline.json',task)),lease=True)
        result=self.cli('inline','INLINE',lease=True)[1]
        self.assertEqual(result['executor'],'main')
        self.assertTrue(result['inline'])
        self.cli('report','main',result['token'],str(self.write('inline.txt','Inspected fixture source.')))
        self.cli('accept','INLINE',lease=True)

    def test_scoped_artifact_ignores_sibling_edits(self):
        task=dict(id='T',role='builder',mode='implementation',inputs=['fixture'],
                  acceptance=['fixture check'],files=['fixture.txt'],resources=[],dependencies=[])
        self.cli('add',str(self.write('T.json',task)),lease=True)
        token=self.cli('dispatch','T','worker',lease=True)[1]['assignment']
        self.cli('report','worker',token,str(self.write('t.txt','Inspected fixture source.')))
        artifact=self.cli('artifact','--tasks','T')[1]
        self.assertEqual(['fixture.txt'],artifact['scope'])
        self.assertNotIn('scope',self.cli('artifact')[1])
        (self.repo/'sibling.txt').write_text('sibling uncommitted edit\n')
        self.cli('accept','T',lease=True)
        self.cli('artifact','--tasks','NOPE',expected=2)

    def test_dirty_candidate_invalidates_review_and_permit(self):
        task=dict(id='I',role='investigator',mode='code',inputs=['fixture'],acceptance=['inspect'],files=[],resources=[],dependencies=[])
        self.cli('add',str(self.write('I.json',task)),lease=True)
        token=self.cli('dispatch','I','reader',lease=True)[1]['assignment']
        self.cli('report','reader',token,str(self.write('result.txt','Read fixture.txt: ready')))
        self.cli('accept','I',lease=True)
        self.cli('gate','fixture','--',*self.check,lease=True)
        self.review(['I'],True)
        (self.repo/'fixture.txt').write_text('changed\n')
        self.cli('permit','fixture-remote','main',lease=True,expected=2)
        self.cli('finish',lease=True,expected=2)

    LENSES=(['requirements','correctness','tests','architecture'],['security'],['standards','cleanup'])

    def card(self,ident,**kw):
        task=dict(id=ident,role='builder',mode='implementation',inputs=['fixture outcome'],acceptance=['fixture check'],
                  files=[ident+'.txt'],resources=[],dependencies=[])
        task.update(kw)
        self.cli('add',str(self.write(ident+'.json',task)),lease=True)

    def run_card(self,ident):
        worker='worker-'+ident
        token=self.cli('dispatch',ident,worker,lease=True)[1]['assignment']
        self.cli('report',worker,token,str(self.write(ident+'.txt','Inspected fixture; nothing to change.')))

    def built(self,ident,**kw):
        self.card(ident,**kw)
        self.run_card(ident)

    def receipt(self,name,ids,categories,final=False,findings=(),**extra):
        artifact=self.cli('artifact')[1] if final else self.cli('artifact','--tasks',','.join(ids))[1]
        body=dict(reviewer='reviewer-'+name,categories=categories,tasks=ids,findings=list(findings),
                  issues=[dict(text=f,severity='blocking',impact='Fixture impact: a requirement is unmet.') for f in findings],
                  verdict='BLOCKED' if findings else 'CLEAN',final=final,artifact=artifact,
                  summary='Inspected fixture source and concrete failure checks.')
        body.update(extra)
        return self.cli('review',str(self.write('receipt-'+name+'.json',body)),lease=True)[1]

    def lens_round(self,tag,specs):
        """SPEC 5.5 item 9: add every card of the round, report them all, then record the receipts."""
        existing=list(self.cli('status')[1]['tasks'])
        names=['%s%d'%(tag,n) for n in range(len(specs))]
        for name in names:
            self.card(name,role='code-reviewer',mode='final',files=[],review_of=existing)
        for name in names:
            self.run_card(name)
        everything=list(self.cli('status')[1]['tasks'])
        for name,(categories,extra) in zip(names,specs):
            extra=dict(extra)
            self.receipt(name,everything,categories,final=True,findings=extra.pop('findings',()),**extra)
        return names

    def accept_all(self,*ids):
        for ident in ids:
            self.cli('accept',ident,lease=True)

    def status_task(self,ident):
        return self.cli('status')[1]['tasks'][ident]

    def test_final_lens_then_repair_then_completion(self):
        self.built('B1')
        self.built('B2')
        self.accept_all('B1','B2')
        self.cli('gate','fixture','--',*self.check,lease=True)
        lens=self.lens_round('L',[(self.LENSES[0],dict(findings=['f'],task_findings={'B2':['f']})),(self.LENSES[1],{}),(self.LENSES[2],{})])
        self.card('R1',mode='repair',repair_of='B2',files=['B2.txt'])
        self.assertEqual((1,['f']),(self.status_task('R1')['final_round'],self.status_task('R1')['final_findings']))
        self.cli('dispatch','R1','worker-R1',lease=True,expected=2)  # the lens cards are acceptable and still reported
        self.accept_all(*lens)
        self.run_card('R1')
        again=self.lens_round('M',[(self.LENSES[0],{}),(self.LENSES[1],{}),(self.LENSES[2],{})])
        self.accept_all('R1','B2',*again)
        self.cli('finish',lease=True)

    def test_final_round_repairs_held_and_lens_chains_then_completes(self):
        self.built('B1')
        self.accept_all(*self.lens_round('F',[(CATEGORIES,dict(findings=['f'],task_findings={'B1':['f']}))]))
        self.card('R1',mode='repair',repair_of='B1',files=['B1.txt'])
        self.run_card('R1')
        self.receipt('check',['R1','B1'],['correctness'],findings=['g'],task_findings={'R1':['g'],'B1':[]},repair_check=True)
        self.cli('hold','R1','--finding','g',lease=True)
        self.built('B2')
        self.accept_all('B2')
        self.cli('gate','fixture','--',*self.check,lease=True)
        lens=self.lens_round('L',[
            (self.LENSES[0],dict(findings=['g persists'],task_findings={'R1':['g persists']})),
            (self.LENSES[1],dict(findings=['leak in B2'],task_findings={'B2':['leak in B2']},cleared={'R1':'no security defect'})),
            (self.LENSES[2],dict(cleared={'R1':'no standards defect'}))])
        self.accept_all(*lens)
        self.card('R2',mode='repair',repair_of='R1',files=['B1.txt'])
        self.card('R3',mode='repair',repair_of='B2',files=['B2.txt'])
        self.assertEqual([(2,['g persists']),(2,['leak in B2'])],
                         [(self.status_task(i)['final_round'],self.status_task(i)['final_findings']) for i in ('R2','R3')])
        self.run_card('R2')
        self.run_card('R3')
        again=self.lens_round('M',[(self.LENSES[0],{}),(self.LENSES[1],{}),(self.LENSES[2],{})])
        self.accept_all('R2','R1','B1','R3','B2',*again)
        self.cli('finish',lease=True)

    def test_final_rounds_repeat_until_clean_with_no_cap(self):
        self.built('B1')
        self.accept_all('B1')
        self.cli('gate','fixture','--',*self.check,lease=True)
        tip,repairs=['B1'],[]
        for k in range(1,6):
            lens=self.lens_round('L%d-'%k,[(CATEGORIES,dict(findings=['defect %d'%k],task_findings={tip[0]:['defect %d'%k]}))])
            self.accept_all(*lens)
            repair='R%d'%k
            self.card(repair,mode='repair',repair_of=tip[0],files=['B1.txt'])
            self.run_card(repair)
            tip,repairs=[repair],repairs+[repair]
        self.assertEqual([1,2,3,4,5],[self.status_task(r)['final_round'] for r in repairs])
        clean=self.lens_round('Z',[(CATEGORIES,{})])
        self.accept_all(*reversed(repairs),'B1',*clean)
        self.cli('finish',lease=True)

    def test_final_receipt_stale_when_card_added_after_it(self):
        self.built('B1')
        self.accept_all('B1')
        self.cli('gate','fixture','--',*self.check,lease=True)
        first=self.lens_round('L',[(CATEGORIES,{})])
        self.accept_all(*first)
        self.card('L9',role='code-reviewer',mode='final',files=[],review_of=['B1'])
        self.run_card('L9')
        self.accept_all('L9')
        self.cli('finish',lease=True,expected=2)  # every card is accepted, but the receipt predates L9
        self.receipt('late',list(self.cli('status')[1]['tasks']),CATEGORIES,final=True)
        self.cli('finish',lease=True)


class LinkedWorktreeHook(unittest.TestCase):
    """A15 through the real hook script: a linked worktree follows the main worktree's run."""

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='Orchestra linked ')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.env={**os.environ,'XDG_STATE_HOME':str(self.root/'xdg')}
        self.env.pop('ORCHESTRA_STATE_DIR',None)
        self.repo=self.root/'main checkout'
        self.repo.mkdir()
        self.git(self.repo,'init','-q','-b','main')
        self.git(self.repo,'config','user.name','Integration')
        self.git(self.repo,'config','user.email','integration@example.invalid')
        (self.repo/'fixture.txt').write_text('ready\n')
        self.git(self.repo,'add','fixture.txt')
        self.git(self.repo,'commit','-q','-m','Fixture')
        self.linked=self.root/'linked checkout'
        self.git(self.repo,'worktree','add','-q',str(self.linked),'-b','side')

    def git(self,cwd,*args):
        return subprocess.check_output(['git','-C',str(cwd),*args],stderr=subprocess.PIPE).decode().strip()

    def hook(self,cwd,command):
        payload={'cwd':str(cwd),'tool_name':'Bash','tool_input':{'command':command}}
        result=subprocess.run([SH,str(HOOK),'PreToolUse','--harness','claude'],input=json.dumps(payload),
                              capture_output=True,text=True,env=self.env,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        return json.loads(result.stdout).get('hookSpecificOutput',{}).get('permissionDecision')

    def test_push_from_linked_worktree_follows_the_main_checkout_run(self):
        command='git push origin side'
        self.assertIsNone(self.hook(self.linked,command))
        lease=json.loads(subprocess.run([sys.executable,str(CLI),'--repo',str(self.repo),'start','--size','medium'],env=self.env,
                                        capture_output=True,text=True,check=True).stdout)['lease']
        self.assertEqual(self.hook(self.linked,command),'deny')
        self.assertEqual(self.hook(self.repo,command),'deny')
        self.assertIsNone(self.hook(self.linked,'git status'))
        subprocess.run([sys.executable,str(CLI),'--repo',str(self.repo),'--lease',lease,'interrupt'],env=self.env,
                       capture_output=True,text=True,check=True)
        self.assertIsNone(self.hook(self.linked,command))

    def test_bare_common_directory_stays_unarmed(self):
        # A15: a worktree of a bare repository has no main worktree, so it is never armed,
        # even with a run state sitting at the bare directory's parent.
        bare=self.root/'bare.git'
        subprocess.run(['git','clone','-q','--bare',str(self.repo),str(bare)],check=True,capture_output=True)
        self.git(bare,'worktree','add','-q',str(self.root/'bare checkout'),'main')
        subprocess.run([sys.executable,str(CLI),'--repo',str(self.repo),'start','--size','medium'],env=self.env,
                       capture_output=True,text=True,check=True)
        parent_state=subprocess.run([sys.executable,'-c',
                                     'import sys;sys.path.insert(0,sys.argv[1]);'
                                     'from orchestra_core.paths import state_location;from pathlib import Path;'
                                     'print(state_location(Path(sys.argv[2])))',
                                     str(CLI.parent),str(self.root)],env=self.env,capture_output=True,text=True,check=True).stdout.strip()
        Path(parent_state).mkdir(parents=True)
        (Path(parent_state)/'state.json').write_text('{}')
        for command in ['git push origin main','git push origin main && git status']:
            with self.subTest(command=command):
                self.assertIsNone(self.hook(self.root/'bare checkout',command))


class HarnessSessionIntegration(unittest.TestCase):
    """B-F5 through the real CLI and run-hook.sh."""

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='Orchestra harness session ')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.repo=self.root/'repo'
        self.repo.mkdir()
        self.state=self.root/'state'
        for args in (['init','-b','main'],['config','user.name','T'],['config','user.email','t@example.invalid']):
            subprocess.run(['git','-C',str(self.repo),*args],check=True,capture_output=True)
        (self.repo/'f').write_text('x')
        subprocess.run(['git','-C',str(self.repo),'add','f'],check=True,capture_output=True)
        subprocess.run(['git','-C',str(self.repo),'commit','-qm','f'],check=True,capture_output=True)
        self.env=dict(os.environ,ORCHESTRA_STATE_DIR=str(self.state))

    def cli(self,*args,expected=0):
        args=list(args)
        if args[:1]==['start'] and '--size' not in args and (
                '--new-run' in args or not (self.state/'state.json').exists()):
            args+=['--size','medium']  # a new run needs its size; a resumed one refuses it
        result=subprocess.run([sys.executable,str(CLI),'--repo',str(self.repo),*args],env=self.env,
                              capture_output=True,text=True,timeout=25)
        self.assertEqual(result.returncode,expected,result.stderr+result.stdout)
        return json.loads(result.stdout) if expected==0 else result.stderr

    def hook(self,event,**payload):
        payload.setdefault('cwd',str(self.repo))
        result=subprocess.run([SH,str(HOOK),event,'--harness','claude'],input=json.dumps(payload),env=self.env,
                              capture_output=True,text=True,timeout=25)
        self.assertEqual(result.returncode,0,result.stderr)
        return json.loads(result.stdout)

    def session(self):
        return self.cli('status')['session']

    def test_session_end_releases_so_a_new_run_starts(self):
        self.cli('start','--harness-session','S')
        self.assertEqual(self.session()['harness_session'],'S')
        self.cli('start',expected=2)  # still armed
        self.hook('SessionEnd',session_id='S',reason='prompt_input_exit')
        self.assertFalse(self.session()['active'])
        self.cli('start','--new-run')

    def foreign_policy(self):
        """A plugin upgrade or policy edit: the stored policy hash no longer matches."""
        path=self.state/'state.json'
        data=json.loads(path.read_text())
        data['policy']='0'*64
        path.write_text(json.dumps(data))

    def test_new_run_archives_an_ended_run_under_a_changed_policy(self):
        lease=self.cli('start')['lease']
        self.cli('--lease',lease,'interrupt')
        self.foreign_policy()
        self.assertIn('start --new-run',self.cli('status',expected=2))
        self.assertIn('start --new-run',self.cli('start',expected=2))
        push=self.hook('PreToolUse',tool_name='Bash',tool_input={'command':'git push origin main'})
        self.assertEqual(push,{})  # O35: an ended run is unarmed
        self.cli('start','--new-run')
        self.assertEqual(len(list((self.state/'history').glob('run-*.json'))),1)
        self.assertTrue(self.session()['active'])

    def test_changed_policy_message_depends_on_whether_the_run_is_active(self):
        lease=self.cli('start')['lease']
        self.foreign_policy()
        active=self.cli('status',expected=2)
        self.assertNotIn('start --new-run',active)
        self.assertIn('state.json',active)
        self.assertIn('version that started',active)
        self.cli('start','--new-run',expected=2)
        path=self.state/'state.json'
        data=json.loads(path.read_text())
        data['session']['active']=False
        path.write_text(json.dumps(data))
        self.assertIn('start --new-run',self.cli('status',expected=2))

    def test_new_run_refuses_an_active_run_under_a_changed_policy(self):
        self.cli('start')
        self.foreign_policy()
        refused=self.cli('start','--new-run',expected=2)  # FX6: the engine's recovery steps, not interrupt/finish
        self.assertIn('version that started',refused)
        self.assertIn('state.json',refused)
        self.assertNotIn('Stop or finish',refused)
        self.assertFalse((self.state/'history').exists())
        push=self.hook('PreToolUse',tool_name='Bash',tool_input={'command':'git push origin main'})
        self.assertEqual(push['hookSpecificOutput']['permissionDecision'],'deny')

    def test_new_run_refuses_an_active_run_under_the_current_policy(self):
        self.cli('start')
        self.assertIn('Stop or finish the active run',self.cli('start','--new-run',expected=2))
        self.assertFalse((self.state/'history').exists())

    def test_clear_and_resume_rebind_then_exit_releases(self):
        for reason in ('clear','resume'):
            with self.subTest(reason=reason):
                self.cli('start','--new-run','--harness-session','S')
                self.hook('SessionEnd',session_id='S',reason=reason)
                self.assertTrue(self.session()['active'])
                out=self.hook('SessionStart',session_id='S2',source=reason)
                self.assertIn('--harness-session S2',out['hookSpecificOutput']['additionalContext'])
                self.assertEqual(self.session()['harness_session'],'S2')
                self.hook('SessionEnd',session_id='S',reason='prompt_input_exit')
                self.assertTrue(self.session()['active'])  # the old id no longer owns the run
                self.hook('SessionEnd',session_id='S2',reason='prompt_input_exit')
                self.assertFalse(self.session()['active'])
                lease=self.cli('start','--new-run')['lease']
                self.cli('--lease',lease,'interrupt')

    def test_unbound_run_ignores_session_end_and_where_hides_the_lease(self):
        self.cli('start')
        self.hook('SessionEnd',session_id='S',reason='prompt_input_exit')
        self.assertTrue(self.session()['active'])
        where=self.cli('where')
        self.assertEqual(set(where),{'repo','state','standing_orders'})
        self.assertEqual((where['repo'],where['state'],where['standing_orders']),(str(self.repo),str(self.state),False))
        (self.state/'standing-orders.md').write_text('rules\n')
        self.assertTrue(self.cli('where')['standing_orders'])


class AutonomyIntegration(unittest.TestCase):
    """SPEC 12 through the real CLI and run-hook.sh."""

    def ledger(self,passes='1'):
        from datetime import datetime,timedelta,timezone
        sys.path.insert(0,str(PLUGIN/'scripts'))
        from orchestra_core.engine import AUTONOMY_FIXED
        when=(datetime.now(timezone.utc)+timedelta(hours=2)).isoformat(timespec='seconds')
        text=['goal: integration','max_passes: '+passes,'max_stalls: 2','deadline: '+when,'','## Completion checks','',
              'never: '+sys.executable+' -c "import sys; sys.exit(1)"','','## Approval boundaries','',*AUTONOMY_FIXED]
        (self.state/'autonomy.md').write_text('\n'.join(text)+'\n')

    def card(self,name):
        task=self.root/(name+'.json')
        task.write_text(json.dumps(dict(id=name,role='builder',mode='implementation',inputs=['s'],acceptance=['a'],
                                        files=[name],resources=[],dependencies=[])))
        self.cli('--lease',self.lease,'add',str(task))

    cli=HarnessSessionIntegration.cli
    hook=HarnessSessionIntegration.hook

    def setUp(self):
        HarnessSessionIntegration.setUp(self)
        self.lease=self.cli('start')['lease']

    def test_arm_needs_no_lease_writes_the_template_then_arms_and_reports_preconditions(self):
        message=self.cli('autonomy','arm',expected=2)
        self.assertIn('fill the ledger, then arm again',message)
        self.assertTrue((self.state/'autonomy.md').is_file())
        self.ledger()
        armed=self.cli('autonomy','arm')
        self.assertTrue(armed['active'])
        self.assertIn('permission_mode',armed['preconditions'])
        self.assertTrue(self.cli('autonomy','status')['active'])
        self.assertTrue(self.cli('autonomy','disarm')['was_active'])
        self.assertFalse(self.cli('autonomy','status')['active'])

    def test_park_and_unpark_take_the_lease_and_a_reason(self):
        self.card('c1')
        self.cli('park','c1','--reason','x',expected=2)  # no lease
        self.cli('--lease',self.lease,'park','c1',expected=2)  # --reason is required
        self.cli('--lease',self.lease,'park','c1','--reason','needs a push')
        self.assertEqual(self.cli('status')['tasks']['c1']['state'],'parked')
        self.cli('--lease',self.lease,'unpark','c1')
        self.assertEqual(self.cli('status')['tasks']['c1']['state'],'queued')

    def test_stop_continues_then_parks_then_session_start_shows_the_report(self):
        self.card('c1')
        self.ledger('1')
        self.cli('autonomy','arm')
        first=self.hook('Stop')
        self.assertEqual(first['decision'],'block')
        self.cli('--lease',self.lease,'park','c1','--reason','needs a push')
        self.assertEqual(self.hook('Stop'),{})
        self.assertEqual(self.cli('autonomy','status')['last_stop_reason'],'parked-only')
        context=self.hook('SessionStart',session_id='S3',source='startup')['hookSpecificOutput']['additionalContext']
        self.assertIn('parked-only',context)
        self.assertIn('Run brief',context)
        self.assertIn('progress.md',context)

    def test_hook_denies_boundary_only_while_active(self):
        self.card('c1')
        self.ledger()
        self.cli('autonomy','arm')
        out=self.hook('PreToolUse',tool_name='Bash',tool_input={'command':'rm -rf build'})
        self.assertEqual(out['hookSpecificOutput']['permissionDecision'],'deny')
        self.cli('autonomy','disarm')
        self.assertEqual(self.hook('PreToolUse',tool_name='Bash',tool_input={'command':'rm -rf build'}),{})

    def test_cli_autonomy_arm_relaunch_and_settle(self):
        self.card('c1')
        self.ledger()
        armed=self.cli('autonomy','arm','--relaunch')
        self.assertTrue(armed['active'])
        self.assertTrue(self.cli('autonomy','status')['active'])
        settled=self.cli('autonomy','settle')
        self.assertEqual((settled['armed'],settled['stopped'],settled['reason']),(True,False,None))
        self.assertEqual(settled['passes'],0)
        self.assertEqual(len(settled['signature']),64)
        self.assertEqual(set(settled),{'armed','stopped','reason','signature','passes','stalls'})

    def test_cli_gate_again_reruns(self):
        first=self.cli('--lease',self.lease,'gate','ok','--',sys.executable,'-c','pass')
        self.assertTrue(first['passed'])
        refused=self.cli('--lease',self.lease,'gate','ok','--',sys.executable,'-c','pass',expected=2)
        self.assertIn('pass --again to rerun',refused)
        again=self.cli('--lease',self.lease,'gate','--again','ok','--',sys.executable,'-c','pass')
        self.assertTrue(again['passed'])
        self.assertNotEqual(again['id'],first['id'])
        trailing=self.cli('--lease',self.lease,'gate','ok','--again','--',sys.executable,'-c','pass')
        self.assertTrue(trailing['passed'])
        self.assertNotIn(trailing['id'],(first['id'],again['id']))

    def test_cli_gate_timeout_overrides_policy_for_one_run(self):
        hang=[sys.executable,'-c','import time; time.sleep(10)']
        for flags in (['--timeout','0.2','slow'],['slow','--timeout','0.2','--again']):
            with self.subTest(flags=flags):
                result=subprocess.run([sys.executable,str(CLI),'--repo',str(self.repo),'--lease',self.lease,'gate',*flags,'--',*hang],
                                      env=self.env,capture_output=True,text=True,timeout=25)
                self.assertEqual(1,result.returncode,result.stderr)
                self.assertEqual(124,json.loads(result.stdout)['exit_code'])
        for bad in ('0','-1','nan','x'):
            with self.subTest(bad=bad):
                refused=self.cli('--lease',self.lease,'gate','slow','--timeout',bad,'--',*hang,expected=2)
                self.assertIn('Gate timeout must be positive and finite',refused)


FAKE_PASS = r"""
import json, os, signal, subprocess, sys, time
from pathlib import Path
plan_path, repo, cli = sys.argv[1:4]
root = Path(plan_path).parent
counter = root / 'count.txt'
n = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(n))
plan = json.loads(Path(plan_path).read_text())
steps = plan[min(n, len(plan)) - 1]
(root / ('prompt-%d.txt' % n)).write_text(sys.stdin.read())
state = Path(os.environ['ORCHESTRA_STATE_DIR'])
CATEGORIES = ['requirements', 'correctness', 'security', 'tests', 'architecture', 'standards', 'cleanup']
SELF_REVIEW = 'ARTIFACT: fixture\nSELF_REVIEW: ' + json.dumps(dict(checks=[dict(command='fixture check', exit_code=0)],
                                                criteria=[dict(criterion='fixture outcome', met=True, evidence='Inspected.')]))

def run(*args, env=None, lease=True):
    cmd = [sys.executable, cli, '--repo', repo]
    if lease:
        cmd += ['--lease', (root / 'lease.txt').read_text()]
    done = subprocess.run(cmd + list(args), capture_output=True, text=True, env=env)
    if done.returncode:
        sys.exit('fake pass: %s failed: %s' % (args, done.stderr))
    return json.loads(done.stdout)

def review(ids, final):
    artifact = run('artifact')
    path = root / 'review.json'
    path.write_text(json.dumps(dict(reviewer='independent-reviewer', categories=CATEGORIES, tasks=ids, findings=[],
                                    issues=[], verdict='CLEAN', final=final, summary='Inspected fixture source.',
                                    artifact=artifact)))
    run('review', str(path))

def start(env=None):
    (root / 'lease.txt').write_text(run('start', '--harness-session', 'S%d' % n, env=env, lease=False)['lease'])

for step in steps:
    if step == 'start':
        start()
    elif step == 'start_unbound':
        done = subprocess.run([sys.executable, cli, '--repo', repo, 'start'], capture_output=True, text=True)
        if done.returncode:
            sys.exit('fake pass: unbound start failed: ' + done.stderr)
        (root / 'lease.txt').write_text(json.loads(done.stdout)['lease'])
    elif step == 'start_noenv':
        names = sorted(p.name for p in (state / 'relaunch').glob('pass-*.marker'))
        (root / 'markers.json').write_text(json.dumps(names))
        start({k: v for k, v in os.environ.items() if k != 'ORCHESTRA_RELAUNCH_PASS'})
    elif step == 'start_foreign':
        (state / 'relaunch' / 'pass-other.marker').write_text('other\n')
        start({k: v for k, v in os.environ.items() if k != 'ORCHESTRA_RELAUNCH_PASS'})
    elif step == 'work1':
        token = run('dispatch', 'B1', 'worker', '--helper', 'fixture helper')['assignment']
        (root / 'b1.txt').write_text('Inspected fixture; no source change needed.\n' + SELF_REVIEW + '\n')
        run('report', 'worker', token, str(root / 'b1.txt'), lease=False)
    elif step == 'work2':
        run('accept', 'B1')
        run('gate', 'ok', '--', sys.executable, '-c', 'pass')
        review(['B1'], True)
        run('finish')
    elif step == 'disarm':
        run('autonomy', 'disarm', lease=False)
    elif step == 'wait_signal':
        def on_signal(signum, frame):
            status = run('autonomy', 'status', lease=False)
            (root / 'signal.json').write_text(json.dumps(dict(signum=signum, active=status['active'],
                                                              last_stop_reason=status['last_stop_reason'])))
            sys.exit(0)
        signal.signal(signal.SIGINT, on_signal)
        signal.signal(signal.SIGTERM, on_signal)
        (root / 'ready.txt').write_text('ready')
        time.sleep(60)
"""


DEADLOCK_DRIVER = r"""
import os, signal, sys, time
sys.path.insert(0, sys.argv[1])
from pathlib import Path
from orchestra_core import relaunch
repo, state = Path(sys.argv[2]), Path(sys.argv[3])
sent = []

class Holder(relaunch.Engine):
    def settle(self):
        if not sent:
            sent.append(1)
            with self._state():  # the main thread holds the state lock while the signal lands
                os.kill(os.getpid(), signal.SIGINT)
                time.sleep(0.3)
        return super().settle()

relaunch.Engine = Holder
sys.exit(relaunch.run(repo, state, 'default', launcher=[sys.argv[4], '-c', 'pass']))
"""


def load_2_4_state(state,repo):
    """Write a 2.4 run (`start --items 3`) into the state directory, bound to the repository and its HEAD; returns its lease."""
    data=json.loads((FIXTURES/'state-2.4.json').read_text())
    data['repo']=str(Path(repo).resolve())
    data['session']['base']=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD']).decode().strip()
    Path(state).mkdir(parents=True,exist_ok=True)
    (Path(state)/'state.json').write_text(json.dumps(data))
    return data['session']['lease']


class RouteCliIntegration(unittest.TestCase):
    """The 2.4 routing contract through the real CLI, against a 2.4 state: route --items, dispatch --helper and the help text."""

    def setUp(self):
        HarnessSessionIntegration.setUp(self)

    def raw(self,*args,expected=0):
        result=subprocess.run([sys.executable,str(CLI),'--repo',str(self.repo),*args],env=self.env,
                              capture_output=True,text=True,timeout=25)
        self.assertEqual(result.returncode,expected,result.stderr+result.stdout)
        return json.loads(result.stdout) if expected==0 else result.stderr+result.stdout

    def test_route_items_changes_the_route_of_a_2_4_run(self):
        lease=load_2_4_state(self.state,self.repo)
        session=self.raw('status')['session']
        self.assertEqual((session['items'],session['route']),(3,'inline'))
        self.raw('route','--items','9','--reason','the brief grew',expected=2)  # the route needs the lease
        self.raw('--lease',lease,'route','--items','9','--reason','the brief grew')
        self.assertEqual(self.raw('status')['session']['route'],'workflow')
        self.raw('--lease',lease,'route','--items','2','--reason','scope shrank')
        session=self.raw('status')['session']
        self.assertEqual((session['items'],session['route']),(2,'inline'))
        self.assertEqual([(e['items'],e['reason']) for e in session['route_log']],[(9,'the brief grew'),(2,'scope shrank')])
        self.assertIn('This run routes by items',self.raw('--lease',lease,'route','--size','tiny','--reason','r',expected=2))

    def test_inline_route_refuses_a_helper_without_a_reason(self):
        lease=load_2_4_state(self.state,self.repo)
        task=self.root/'B1.json'
        task.write_text(json.dumps(dict(id='B1',role='builder',mode='implementation',inputs=['s'],acceptance=['a'],
                                        files=['b1.txt'],resources=[],dependencies=[])))
        self.raw('--lease',lease,'add',str(task))
        self.assertIn('pass --helper REASON',self.raw('--lease',lease,'dispatch','B1','worker',expected=2))
        self.assertTrue(self.raw('--lease',lease,'dispatch','B1','worker','--helper','needs a second pair of hands')['assignment'])

    def test_a_2_4_run_resumes_without_flags(self):
        lease=load_2_4_state(self.state,self.repo)
        self.raw('--lease',lease,'interrupt')
        self.assertTrue(self.raw('start')['lease'])
        self.assertEqual(self.raw('status')['session']['items'],3)

    def test_help_text_matches_the_contract(self):
        def helptext(*cmd):
            return subprocess.run([sys.executable,str(CLI),*cmd,'--help'],capture_output=True,text=True,timeout=25).stdout
        start=helptext('start')
        self.assertTrue(all(flag in start for flag in ('--size','--asks','--owner-request')))
        route=helptext('route')
        self.assertTrue(all(flag in route for flag in ('--size','--items','--reason')))
        self.assertIn('--helper REASON',helptext('dispatch'))
        self.assertIn('prepr',subprocess.run([sys.executable,str(CLI),'--help'],capture_output=True,text=True,timeout=25).stdout)
        self.assertNotIn('wave',helptext('add').lower())
        self.assertNotIn('supersede',subprocess.run([sys.executable,str(CLI),'--help'],capture_output=True,text=True,timeout=25).stdout)


class SizeCli(unittest.TestCase):
    """Contract items 2 to 7 through the real CLI."""

    def setUp(self):
        HarnessSessionIntegration.setUp(self)

    def raw(self,*args,expected=0,both=False):
        result=subprocess.run([sys.executable,str(CLI),'--repo',str(self.repo),*args],env=self.env,
                              capture_output=True,text=True,timeout=25)
        self.assertEqual(result.returncode,expected,result.stderr+result.stdout)
        if both:
            return result
        return json.loads(result.stdout) if expected==0 else result.stderr+result.stdout

    def card(self,lease,name,**extra):
        task=self.root/(name+'.json')
        task.write_text(json.dumps(dict(id=name,role='builder',mode='implementation',inputs=['s'],acceptance=['a'],
                                        files=[name+'.txt'],resources=[],dependencies=[],**extra)))
        self.raw('--lease',lease,'add',str(task))

    def write(self,lines,name='big.txt'):
        (self.repo/name).write_text('x\n'*lines)

    def test_start_without_size_exits_nonzero_naming_size(self):
        self.assertIn('--size',self.raw('start',expected=2))

    def test_start_size_large_exits_nonzero_naming_escalation(self):
        self.assertIn('escalate',self.raw('start','--size','large',expected=2))
        self.assertTrue(self.raw('start','--size','large','--owner-request')['lease'])
        self.assertTrue(self.raw('status')['session']['owner_request'])

    def test_start_size_medium_with_asks_prints_a_lease(self):
        out=self.raw('start','--size','medium','--asks','2')
        self.assertTrue(out['lease'])
        session=self.raw('status')['session']
        self.assertEqual((session['size'],session['asks'],session['owner_request']),('medium',2,False))
        self.assertNotIn('items',session)

    def test_start_items_is_refused_pointing_to_size(self):
        self.assertIn('--items is the 2.4 flag; start with --size',self.raw('start','--items','3',expected=2))
        self.assertIn('--items is the 2.4 flag; start with --size',self.raw('start','--items','3','--size','tiny',expected=2))
        self.assertFalse((self.state/'state.json').exists())

    def test_start_flags_on_a_resumed_run_exit_nonzero(self):
        lease=self.raw('start','--size','medium')['lease']
        self.raw('--lease',lease,'interrupt')
        for flags in (['--size','tiny'],['--asks','2'],['--owner-request']):
            self.assertIn('apply to a new run',self.raw('start',*flags,expected=2))
        self.assertTrue(self.raw('start')['lease'])
        self.assertEqual(self.raw('status')['session']['size'],'medium')

    def test_new_run_with_bad_size_asks_or_large_leaves_the_ended_run_in_place(self):
        lease=self.raw('start','--size','tiny')['lease']
        self.raw('--lease',lease,'interrupt')
        for flags in ([],['--size','large'],['--size','huge'],['--size','tiny','--asks','0'],['--size','tiny','--asks','many']):
            self.raw('start','--new-run',*flags,expected=2)
        self.assertFalse((self.state/'history').exists())  # the ended run was not archived
        self.assertFalse(self.raw('status')['session']['active'])
        self.raw('start','--new-run','--size','medium')
        self.assertTrue((self.state/'history').exists())

    def test_route_needs_exactly_one_of_size_or_items(self):
        lease=self.raw('start','--size','tiny')['lease']
        self.assertIn('exactly one',self.raw('--lease',lease,'route','--reason','r',expected=2))
        self.assertIn('exactly one',self.raw('--lease',lease,'route','--size','medium','--items','3','--reason','r',expected=2))
        self.assertIn('This run routes by size',self.raw('--lease',lease,'route','--items','3','--reason','r',expected=2))

    def test_route_size_logs_and_exits_zero(self):
        lease=self.raw('start','--size','tiny','--asks','2')['lease']
        out=self.raw('--lease',lease,'route','--size','medium','--reason','the diff grew')
        self.assertEqual((out['size'],out['asks']),('medium',2))
        self.raw('--lease',lease,'route','--size','tiny','--asks','4','--reason','four tweaks')
        session=self.raw('status')['session']
        self.assertEqual([(e['size'],e['asks'],e['reason']) for e in session['route_log']],
                         [('medium',2,'the diff grew'),('tiny',4,'four tweaks')])
        self.raw('--lease',lease,'route','--size','tiny','--asks','0','--reason','r',expected=2)

    def test_dispatch_tiny_card_without_helper_exits_nonzero(self):
        lease=self.raw('start','--size','tiny')['lease']
        self.card(lease,'B1')
        self.assertIn('Tiny unit',self.raw('--lease',lease,'dispatch','B1','worker',expected=2))
        self.assertTrue(self.raw('--lease',lease,'dispatch','B1','worker','--helper','a disjoint file')['assignment'])

    def test_dispatch_medium_card_exits_zero(self):
        lease=self.raw('start','--size','medium')['lease']
        self.card(lease,'B1')
        self.assertTrue(self.raw('--lease',lease,'dispatch','B1','worker')['assignment'])

    def test_prepr_over_budget_prints_warning_and_exits_zero(self):
        self.raw('start','--size','tiny')
        self.write(60)
        result=self.raw('prepr',both=True)
        out=json.loads(result.stdout)
        warning=('Size warning: declared tiny with 1 ask(s) budgets 50 changed lines; the diff has 60. '
                 'Run route --size TIER --reason TEXT if the work grew.')
        self.assertEqual((out['warning'],out['over_budget'],out['budget'],out['changed_lines']),(warning,True,50,60))
        self.assertEqual(result.stderr.strip(),warning)

    def test_prepr_names_the_reviewer_agent_for_each_band(self):
        self.raw('start','--size','tiny','--asks','9')
        for lines,agent in ((10,'orchestra:code-reviewer-medium'),(100,'orchestra:code-reviewer-medium'),
                            (450,'orchestra:code-reviewer')):
            self.write(lines)
            out=self.raw('prepr')
            self.assertEqual((out['agent'],out['changed_lines']),(agent,lines))
        self.assertIn('correctness',out['lenses'])

    def test_prepr_on_a_2_3_state_exits_zero_with_nulls(self):
        data=json.loads((FIXTURES/'state-2.3.json').read_text())
        data['repo']=str(self.repo)
        self.state.mkdir(parents=True,exist_ok=True)
        (self.state/'state.json').write_text(json.dumps(data))
        result=self.raw('prepr',both=True)
        out=json.loads(result.stdout)
        self.assertEqual((out['base'],out['changed_lines'],out['reviewer'],out['agent'],out['warning']),
                         (None,None,'full','orchestra:code-reviewer',None))
        self.assertEqual(result.stderr,'')


class RelaunchIntegration(unittest.TestCase):
    """SPEC 5.10 items 5 and 10: the harness drives a fake launcher; the clock and sleep are injected."""

    def setUp(self):
        HarnessSessionIntegration.setUp(self)
        self.fake=self.root/'fake_pass.py'
        self.fake.write_text(FAKE_PASS)
        self.plan_path=self.root/'plan.json'
        lease=self.cli('start')['lease']
        task=self.root/'B1.json'
        task.write_text(json.dumps(dict(id='B1',role='builder',mode='implementation',inputs=['s'],acceptance=['a'],
                                        files=['b1.txt'],resources=[],dependencies=[])))
        self.cli('--lease',lease,'add',str(task))
        self.arm()
        self.cli('--lease',lease,'interrupt')

    cli=HarnessSessionIntegration.cli

    def arm(self,hours=1):
        from datetime import datetime,timedelta,timezone
        sys.path.insert(0,str(PLUGIN/'scripts'))
        from orchestra_core.engine import AUTONOMY_FIXED
        when=(datetime.now(timezone.utc)+timedelta(hours=hours)).isoformat(timespec='seconds')
        text=['goal: relaunch','deadline: '+when,'','## Completion checks','','ok: '+shlex.join([sys.executable,'-c','pass']),'','## Approval boundaries','',*AUTONOMY_FIXED]
        (self.state/'autonomy.md').write_text('\n'.join(text)+'\n')
        self.cli('autonomy','arm','--relaunch')

    def plan(self,steps):
        self.plan_path.write_text(json.dumps(steps))
        return [sys.executable,str(self.fake),str(self.plan_path),str(self.repo),str(CLI)]

    def harness(self,steps,clock=None,sleep=None):
        sys.path.insert(0,str(PLUGIN/'scripts'))
        from orchestra_core import relaunch
        env=os.environ.copy()
        os.environ['ORCHESTRA_STATE_DIR']=str(self.state)
        self.addCleanup(lambda: (os.environ.clear(),os.environ.update(env)))
        kw={}
        if clock:
            kw.update(clock=clock,sleep=sleep)
        with contextlib.redirect_stderr(io.StringIO()):
            return relaunch.run(self.repo,self.state,'default',launcher=self.plan(steps),**kw)

    def fake_time(self):
        import time
        now=[time.time()]
        sleeps=[]
        def sleep(seconds):
            sleeps.append(seconds)
            now[0]+=seconds
        return (lambda: now[0]),sleep,sleeps

    def brief(self):
        return (self.state/'progress.md').read_text()

    def test_relaunch_runs_passes_until_complete(self):
        code=self.harness([['start','work1'],['start','work2']])
        self.assertEqual(code,0)
        harness=json.loads((self.state/'relaunch/harness.json').read_text())
        self.assertEqual((harness['pass'],harness['stalled_streak']),(2,0))
        self.assertEqual(len(harness['signature']),64)
        self.assertTrue((self.state/'relaunch/pass-1.log').is_file())
        self.assertIn('orchestra',(self.root/'prompt-1.txt').read_text())
        self.assertIn('stop reason: complete',self.brief())
        self.assertEqual(self.cli('status')['tasks']['B1']['state'],'accepted')
        self.assertEqual(list((self.state/'relaunch').glob('pass-*.marker')),[])

    def test_relaunch_refuses_with_active_session(self):
        self.cli('start')
        self.assertEqual(self.harness([['start']]),2)
        self.assertTrue(self.session()['active'])
        self.assertFalse((self.root/'count.txt').exists())  # no pass was launched

    session=HarnessSessionIntegration.session

    def test_relaunch_requires_permission_mode(self):
        message=self.cli('relaunch','--launcher',sys.executable,'-c','pass',expected=2)
        self.assertIn('--permission-mode',message)
        self.assertFalse((self.state/'relaunch').exists())

    def test_relaunch_backs_off_after_stall_and_never_exits_on_stalls(self):
        clock,sleep,sleeps=self.fake_time()
        code=self.harness([['nothing']],clock,sleep)
        self.assertEqual(code,4)  # only the deadline stopped it
        self.assertEqual(sleeps[:6],[60,120,240,480,900,900])
        self.assertLessEqual(max(sleeps),900)
        harness=json.loads((self.state/'relaunch/harness.json').read_text())
        self.assertEqual((harness['pass'],harness['stalled_streak']),(len(sleeps),len(sleeps)))

    def test_relaunch_ends_orphaned_pass_session(self):
        clock,sleep,sleeps=self.fake_time()
        code=self.harness([['start'],['disarm']],clock,sleep)
        self.assertEqual(code,5)
        session=self.session()
        self.assertEqual((session['active'],session['outcome']),(False,'pass-exited'))
        self.assertIn('stop reason: ended',self.brief())

    def test_relaunch_ends_orphaned_unbound_pass_session(self):
        clock,sleep,sleeps=self.fake_time()
        code=self.harness([['start_unbound'],['disarm']],clock,sleep)
        self.assertEqual(code,5)
        session=self.session()
        self.assertNotIn('harness_session',session)
        self.assertEqual((session['active'],session['outcome']),(False,'pass-exited'))
        self.assertTrue(self.cli('start')['lease'])  # a following start succeeds

    @unittest.skipIf(os.name == 'nt', 'POSIX signal delivery to a relaunch child')
    def test_relaunch_signal_during_engine_call_disarms_without_deadlock(self):
        driver=self.root/'driver.py'
        driver.write_text(DEADLOCK_DRIVER)
        process=subprocess.Popen([sys.executable,str(driver),str(PLUGIN/'scripts'),str(self.repo),str(self.state),
                                  sys.executable],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.addCleanup(process.kill)
        try:
            out,err=process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            self.fail('the harness deadlocked on the state lock')
        self.assertEqual(process.returncode,130,err)
        self.assertFalse(self.cli('autonomy','status')['active'])

    def test_relaunch_leaves_foreign_session_and_exits_2(self):
        self.assertEqual(self.harness([['start_foreign']]),2)
        session=self.session()
        self.assertTrue(session['active'])
        self.assertNotIn('relaunch_pass',session)
        self.assertEqual([p.name for p in (self.state/'relaunch').glob('pass-*.marker')],['pass-other.marker'])
        self.assertTrue(self.cli('autonomy','status')['active'])

    @unittest.skipIf(os.name == 'nt', 'POSIX signal delivery to a relaunch child')
    def test_relaunch_sigint_disarms_before_forwarding(self):
        import signal,time
        cmd=[sys.executable,str(CLI),'--repo',str(self.repo),'relaunch','--permission-mode','default','--launcher',
             *self.plan([['start','wait_signal']])]
        process=subprocess.Popen(cmd,env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.addCleanup(process.kill)
        ready=self.root/'ready.txt'
        for _ in range(300):
            if ready.exists() or process.poll() is not None:
                break
            time.sleep(0.1)
        self.assertTrue(ready.exists(),process.poll())
        process.send_signal(signal.SIGINT)
        out,err=process.communicate(timeout=30)
        self.assertEqual(process.returncode,130,err)
        received=json.loads((self.root/'signal.json').read_text())
        self.assertEqual(received['signum'],signal.SIGINT)
        self.assertFalse(received['active'])  # already disarmed when the pass saw the signal
        self.assertEqual(received['last_stop_reason'],'disarmed')
        self.assertIn('stop reason: disarmed',self.brief())

    def test_relaunch_pass_marker_binds_session_without_env(self):
        marks=self.state/'relaunch'
        marks.mkdir(parents=True,exist_ok=True)
        (marks/'pass-stale.marker').write_text('stale\n')
        clock,sleep,sleeps=self.fake_time()
        code=self.harness([['start_noenv'],['disarm']],clock,sleep)
        self.assertEqual(code,5)  # not 2: the marker bound the pass
        seen=json.loads((self.root/'markers.json').read_text())
        self.assertEqual(len(seen),1)
        self.assertNotEqual(seen[0],'pass-stale.marker')
        self.assertEqual(self.session()['outcome'],'pass-exited')
        self.assertEqual(list(marks.glob('pass-*.marker')),[])

    def test_relaunch_exits_127_when_the_launcher_is_missing(self):
        sys.path.insert(0,str(PLUGIN/'scripts'))
        from orchestra_core import relaunch
        with contextlib.redirect_stderr(io.StringIO()):
            code=relaunch.run(self.repo,self.state,'default',launcher=[str(self.root/'no-such-launcher')])
        self.assertEqual(code,127)
        self.assertEqual(list((self.state/'relaunch').glob('pass-*.marker')),[])


if __name__=='__main__':
    unittest.main()
