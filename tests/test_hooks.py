import hashlib
import json
import io
import shutil
import time
import types
import os
import re
from pathlib import Path
import socket
import subprocess
import sys
import threading
import unittest
from unittest import mock
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'plugins/orchestra/scripts'))
from orchestra_core.guards import classify_command, guard_digest, RULES, RULES_PATH
from orchestra_core import hooks as hooks_module
from orchestra_core.hooks import _main_worktree, handle_event, main

SH = shutil.which('sh') or '/bin/sh'  # Git for Windows ships sh; /bin/sh does not resolve outside MSYS.
PLUGIN = Path(__file__).resolve().parents[1] / 'plugins/orchestra'
CLI = PLUGIN / 'scripts/orchestra.py'
RUN_HOOK = PLUGIN / 'scripts/run-hook.sh'

# Command lists shared with tests/test_guard_corpus.py, which requires each one in the corpus.
DENY_COMMANDS = [
    'git reset --hard', 'git clean -fd',
    'git checkout -- .', 'git restore .', 'git stash push',
    'git add -A', 'git add .', 'git add -u src', 'git commit -am done',
    'exec env X=1 git -C "a b" -c color.ui=never reset --hard',
    'true && git clean -f', "sh -c 'git reset --hard'", 'git push --force origin main', 'git clean -f -e "--dry-run"',
    '2>/dev/null sudo -n git reset --hard',
    '> /dev/null nice -n 5 git reset --hard',
    '2>&1 command -p git reset --hard',
    'sudo -n git reset --hard', "env --split-string='git reset --hard'",
    "env -S 'git reset --hard'", "bash -s -c 'git reset --hard'", "bash --norc -c 'git reset --hard'",
    "bash -O extglob -lc 'git reset --hard'",
    'nice -n 5 git reset --hard', 'timeout -s TERM 5 git reset --hard',
    'time git reset --hard', 'time -p git reset --hard',
    "builtin eval 'git reset --hard'", 'command -p git reset --hard', 'builtin command git reset --hard',
    "eval 'git reset --hard'", 'git --exec-path /tmp reset --hard',
    'git reset --hard=HEAD', 'cd other && git push origin main',
]
# SPEC 5.14: classified boundary/delete with Decision category merged-delete; the hook decides on merge evidence.
MERGED_DELETE_COMMANDS = ['git branch -D topic', 'git branch --delete --force topic']
DENY_GROUPED = ['sudo -nu root git reset --hard',
                'sudo -nuroot git reset --hard',
                'sudo -nEu root git reset --hard',
                'env -iS "git reset --hard"',
                'env -iS"git reset --hard"',
                'env -iugone git reset --hard']
ALLOW_GROUPED = ['sudo -nu root git commit -m "-a"',
                 'env -iS "echo git reset --hard"',
                 "echo 'env -iS git reset --hard'"]
ALLOW_SEMANTIC = ['git add src/a.py', 'git commit -m "--all --dry-run"',
                  'echo "git reset --hard"', "bash --norc -c 'echo safe'",
                  "sudo -n git commit -m '-a'", "bash -c 'git commit -m \"-a\"'", 'git log --oneline',
                  'git clean --dry-run', 'git push --dry-run origin main',
                  'git checkout feature', 'git add -- -A', 'echo ";"', 'wrangler dev']
DENY_SEMANTIC = ['git reset --hard "--dry-run"']
RELEASE_COMMANDS = ['git push origin HEAD:main', 'gh pr merge 3',
                    'az repos pr update --id 4 --status completed',
                    'npm publish', 'vercel --prod', 'az deployment group create',
                    'git push -o "--dry-run" origin main', 'git push -o "--force" origin main']
DENY_PUSH_DESTINATION = ['git push origin main side', 'git push --all origin',
                         'git push --tags origin',
                         'git push origin :main', "git push origin 'refs/heads/*:refs/heads/*'",
                         'git push --follow-tags origin main']
DENY_MALFORMED = ["git 'reset"]

# A1 to A7 and A14: each command with its state-independent class (and boundary category).
UNARMED_RELEASES = ['git push origin feat/v2-roles-guard-mods', 'git push origin v2.0.0',
                    'gh pr merge 12 --squash --delete-branch',
                    'gh release create v2.0.0 dist/a.tgz --verify-tag --notes-file notes.md',
                    'npm publish', 'pnpm publish', 'vercel --prod', 'az deployment group create --name x']
MULTI_RELEASES = ['git push origin x && gh pr create', 'git push origin a && git push origin b',
                  'git tag v2.0.0 && git push origin v2.0.0', 'cd sub && git push origin x',
                  'gh pr merge 3 --squash; echo done']
STASH_DENIED = ['git stash', 'git stash push', 'git stash pop', 'git stash apply', 'git stash drop',
                'git stash clear', 'git stash save wip', 'git stash branch topic', 'git stash create',
                'git stash store abc', 'git stash list', 'git stash show', 'git stash show -p stash@{1}',
                'git stash show --stat']
# Plugin 2.1.0: every stash form, wholesale add and commit -a deny at any command boundary or prefix.
_BOUNDARIES = ['{}', 'FOO=1 {}', 'sudo {}', 'sudo -u root {}', 'env X=1 {}', 'command {}', 'nohup {}',
               'true && {}', 'false || {}', 'echo x; {}', 'echo x | {}', '({})', 'cd sub && {}']
_STASH_FORMS = ['git stash', 'git stash list', 'git stash show', 'git stash show -p stash@{1}', 'git stash pop',
                'git stash push -m x', 'git -C wt stash list', 'git -c core.pager=cat stash show',
                'git --git-dir=.git stash list', 'git --work-tree=. stash drop', 'git --git-dir .git stash clear']
_ADD_FORMS = ['git add -A', 'git add --all', 'git add -u', 'git add --update', 'git add --no-ignore-removal',
              'git add -Av', 'git add -vA', 'git add -nu', 'git add -v -u src', 'git add src/a.ts -A',
              'git add src/a.ts --all', 'git add .', 'git add ./', 'git add ..', 'git add ../', 'git add :/',
              'git add :/.', 'git add *', "git add '*'", 'git add "*"', 'git add src/a.ts .', 'git add -- .',
              'git add -f .', 'git add -- ../', 'git -C wt add -A', 'git -c core.x=y add .',
              'git --git-dir=a --work-tree=b add .', 'git --work-tree b add -u']
_COMMIT_FORMS = ['git commit -a', 'git commit --all', 'git commit --all -m x', 'git commit -am x',
                 'git commit -m x -a', 'git commit -sam x', 'git -C wt commit -am x', 'git commit -a -m x']
DENY_GIT_21 = sorted({b.format(f) for f in _STASH_FORMS + _ADD_FORMS + _COMMIT_FORMS for b in _BOUNDARIES})
ALLOW_GIT_21 = ['git add src/a.ts docs/b.md', 'git add ./src/x.ts', 'git add src/*.ts', 'git add docs/',
                'git add .gitignore', 'git add ..foo', 'git add -p src/a.ts', 'git add -f src/a.ts',
                'git add -- -A', 'git commit -m "never run git add -A or git stash"',
                "git commit -m 'git add . && git commit -a'", 'git commit -m "git stash list"',
                'git commit -m "-a --all"', 'git commit -F msg.txt', 'git commit -m done',
                'git clean -n -f', 'git status', 'echo git stash', 'echo "git add -A"',
                'FOO=1 git add src/a.ts', 'sudo git commit -m "use git add . later"',
                'true && git add ./src/x.ts && git commit -m "no git stash here"']
RESTORE_ALLOWED = ['git restore --staged .', 'git restore -S .', 'git restore --staged src/a.py',
                   'git restore --staged :/']
RESTORE_DENIED = ['git restore --staged --worktree .', 'git restore -SW .', 'git restore -W .',
                  'git restore --worktree .', 'git restore .']
SWITCH_DENIED = ['git switch -f main', 'git switch --force main', 'git switch --discard-changes main',
                 'git switch -c topic -f']
AZ_ALLOWED = ['az deployment group show --name x -g g', 'az deployment group list -g g',
              'az deployment group what-if --name x -g g', 'az group list']
BOUNDARY_DELETE = ['rm -rf build', 'rm file.txt', 'rmdir empty', 'unlink link', 'find . -name "*.o" -delete',
                   'git rm src/a.py', 'git branch -d topic', 'git branch --delete topic', 'git tag -d v1',
                   'git tag --delete v1', 'git worktree remove ../wt', 'git worktree prune',
                   'gh repo delete owner/name --yes', 'gh release delete v1', 'sudo rm -r x',
                   'git -C other rm a.py']
BOUNDARY_MERGE = ['git merge topic', 'git pull', 'git pull --rebase origin main', 'git rebase main',
                  'git cherry-pick abc123']
HEREDOC_DENIED = ["bash <<'EOF'\ngit reset --hard\nEOF",
                  'sh <<EOF\ngit reset --hard\nEOF',
                  "sudo bash <<'EOF'\ngit clean -f\nEOF",
                  "env X=1 sh <<-EOF\n\tgit reset --hard\n\tEOF",
                  'cat <<EOF && git reset --hard\nbody\nEOF',
                  'cat <<EOF\nbody\nEOF\ngit reset --hard',
                  'cat <<EOF\nnever ends',
                  # R2 F1 shapes (SPEC A5 rules 1 to 5, amended D3).
                  "cat <<'EOF' | bash\ngit reset --hard\nEOF",
                  "cat <<'EOF' | sudo bash\ngit reset --hard\nEOF",
                  "bash -c \"$(cat)\" <<'EOF'\ngit reset --hard\nEOF",
                  'cat <<EOF\n$(git reset --hard)\nEOF',
                  "cat <<EOF\necho '$(git reset --hard)'\nEOF",
                  'cat <<EOF\nrun `git reset --hard`\nEOF',
                  "source /dev/stdin <<'EOF'\ngit reset --hard\nEOF",
                  "cat <<'EOF' | . /dev/stdin\ngit reset --hard\nEOF",
                  "cat <<'EOF' | eval\ngit reset --hard\nEOF",
                  "bash -c \"$(cat <<'EOF'\ngit reset --hard\nEOF\n)\"",
                  "bash <(cat <<'EOF'\ngit reset --hard\nEOF\n)",
                  # Rule 5: a bare destructive line denies whatever the consumer (accepted v1 cost).
                  "cat <<'EOF'\ngit reset --hard\nEOF",
                  'cat <<EOF\ngit reset --hard\nEOF',
                  "bash -c 'cat' <<EOF\ngit reset --hard\nEOF",
                  "bash -c 'cat' <<'EOF'\nit's data\ngit reset --hard\nEOF",
                  "cat <<'EOF'\ngit reset \\\n--hard\nEOF"]
HEREDOC_ALLOWED = ["cat <<'EOF'\nit's fine\nEOF",
                   "cat <<'EOF' > f\nit's fine\nEOF",
                   "git commit -F - <<'EOF'\nmessage with a quote's apostrophe\nEOF",
                   "cat <<-EOF\n\tit's tabbed\n\tEOF\ngit status",
                   "cat <<EOF > f\nit's $(date)\nEOF",
                   "bash -c 'cat > f' <<'EOF'\nit's data\nEOF",
                   'cat <<EOF\necho "\\$(git reset --hard)" "$((1 + 2))"\nEOF',
                   "cat <<'EOF'\n$(date)\nEOF",
                   'cat <<< "git reset --hard"',
                   'echo $((1 << 2))']
# G2f item 4: raw ref deletion skips the branch-delete rules, so it denies; a create or move stays allowed.
UPDATE_REF_DENIED = ['git update-ref -d refs/heads/x', 'git update-ref --delete refs/heads/x',
                     'git update-ref --stdin', 'git update-ref -z --stdin', 'git update-ref --std',
                     'git update-ref --no-deref -d refs/heads/x', 'git update-ref -m why -d refs/heads/x',
                     'git -C wt update-ref -d refs/heads/x', 'true && git update-ref -d refs/heads/x',
                     'git update-ref refs/heads/x ' + '0' * 40]
UPDATE_REF_ALLOWED = ['git update-ref refs/heads/x HEAD', 'git update-ref refs/heads/x abc123 def456',
                      'git update-ref -m dated refs/heads/x HEAD']
LINKED_WORKTREE_COMMANDS = {'git push origin side': 'release', 'git -C ../linked push origin side': 'release',
                            'git push origin side && git status': 'release-multi'}


def decision_of(result):
    return result.output.get('hookSpecificOutput', {}).get('permissionDecision')


class GuardsTest(unittest.TestCase):
    def test_destructive_and_wholesale(self):
        for command in DENY_COMMANDS:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).action, 'deny')

    def test_merged_delete_commands_are_boundary_delete_with_the_merged_delete_category(self):
        for command in MERGED_DELETE_COMMANDS:
            with self.subTest(command=command):
                decision = classify_command(command)
                self.assertEqual((decision.klass, decision.action, decision.boundary, decision.category),
                                 ('boundary', 'allow', 'delete', 'merged-delete'))

    def test_grouped_wrapper_options(self):
        for command in DENY_GROUPED:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).action, 'deny')
        for command in ALLOW_GROUPED:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).action, 'allow')

    def test_push_source_metadata(self):
        for refspec,source,target in [('main','main','main'), ('HEAD:main','HEAD','main'),
                                      ('topic:refs/heads/main','topic','main'),
                                      ('HEAD~1:main','HEAD~1','main')]:
            with self.subTest(refspec=refspec):
                decision=classify_command('git push origin '+refspec)
                self.assertEqual((decision.source,decision.target),(source,target))
        self.assertEqual(classify_command('sudo -nu root git push origin HEAD:main').source,'HEAD')
        self.assertIsNone(classify_command('git push origin').source)
        self.assertIsNone(classify_command('git -C elsewhere push origin HEAD:main').source)
        self.assertIsNone(classify_command('echo "git push origin HEAD:main"').source)
        self.assertEqual(classify_command('git push origin HEAD:main:other').action,'deny')

    def test_semantic_arguments(self):
        for command in ALLOW_SEMANTIC:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).action, 'allow')
        for command in DENY_SEMANTIC:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).action, 'deny')

    def test_release(self):
        for command in RELEASE_COMMANDS:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).action, 'release')
        decision = classify_command('git push origin HEAD:main')
        self.assertEqual((decision.remote, decision.target), ('origin', 'main'))
        dry_run = classify_command('git push --dry-run origin main')
        self.assertEqual((dry_run.action, dry_run.category, dry_run.remote, dry_run.target),
                         ('allow', 'gitpush', 'origin', 'main'))
        self.assertEqual(classify_command('env --chdir=other git push origin main').argv[0], 'env')
        self.assertEqual(classify_command("sh -c 'git push origin main'").argv[0], 'sh')

    def test_push_requires_one_destination(self):
        for command in DENY_PUSH_DESTINATION:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).action, 'deny')

    def test_malformed(self):
        for command in DENY_MALFORMED:
            self.assertEqual(classify_command(command).action, 'deny')

    def test_a1_release_classes_are_state_independent(self):
        for command in UNARMED_RELEASES:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).klass, 'release')
        for command in MULTI_RELEASES:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).klass, 'release-multi')
        self.assertEqual(classify_command('git push origin x && git reset --hard').klass, 'deny')
        self.assertEqual(classify_command('git reset --hard && git push origin x').klass, 'deny')

    def test_a2_always_deny_rules_remain(self):
        for command in ['git push --force origin x', 'git push -f origin x', 'git push --mirror origin',
                        'git push origin +x', 'git push --all origin', 'git push --tags origin',
                        'git push origin a b', 'git reset --hard',
                        'git clean -f', 'git add -A', 'git commit -a -m x',
                        'git checkout .', 'git checkout -f x', 'git restore .']:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).klass, 'deny')

    def test_a3_every_stash_form_denies(self):
        for command in STASH_DENIED:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).klass, 'deny')

    def test_git_21_stash_wholesale_add_and_commit_all_deny(self):
        for command in DENY_GIT_21:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).klass, 'deny', command)

    def test_git_21_explicit_paths_and_message_words_still_allow(self):
        for command in ALLOW_GIT_21:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).klass, 'allow', command)

    def test_a4_restore_staged(self):
        for command in RESTORE_ALLOWED:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).klass, 'allow')
        for command in RESTORE_DENIED:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).klass, 'deny')

    def test_a5_heredoc_bodies(self):
        for command in HEREDOC_DENIED:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).klass, 'deny')
        for command in HEREDOC_ALLOWED:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).klass, 'allow')
        self.assertEqual(classify_command('bash <<EOF\ngit push origin x\nEOF').klass, 'release')
        self.assertEqual(classify_command('cat <<EOF\nnever ends').category, 'malformed')

    def test_a5_f1_shapes_deny_and_apostrophe_bodies_allow(self):
        hard = 'git reset ' + '--hard'
        deny = ["cat <<'EOF' | bash\n" + hard + "\nEOF",
                'bash -c "$(cat)" <<\'EOF\'\n' + hard + '\nEOF',
                'cat <<EOF\nx $(' + hard + ')\nEOF',
                "source /dev/stdin <<'EOF'\n" + hard + "\nEOF"]
        for command in deny:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).klass, 'deny')
        self.assertEqual(classify_command("cat <<'EOF' > f\nit's fine\nEOF").klass, 'allow')
        self.assertEqual(classify_command("bash <<'EOF'\n" + hard + "\nEOF").klass, 'deny')

    def test_a5_unquoted_scan_is_quote_blind_but_skips_escapes_and_arithmetic(self):
        hard = 'git reset ' + '--hard'
        self.assertEqual(classify_command('cat <<EOF\n"$(' + hard + ')"\nEOF').klass, 'deny')
        self.assertEqual(classify_command("cat <<EOF\n`" + hard + "` it's\nEOF").klass, 'deny')
        self.assertEqual(classify_command('cat <<EOF\necho "\\$(' + hard + ')" "\\`' + hard + '\\`"\nEOF').klass, 'allow')
        self.assertEqual(classify_command('cat <<EOF\necho "$((1+2))" it\'s\nEOF').klass, 'allow')
        # A quoted delimiter performs no substitution; only rule 5 sees a bare line.
        self.assertEqual(classify_command("cat <<'EOF'\necho '$(" + hard + ")'\nEOF").klass, 'allow')

    def test_a5_unparsable_body_under_dash_c_is_ignored_not_denied(self):
        self.assertEqual(classify_command("bash -c 'cat > f' <<'EOF'\nit's data\nEOF").klass, 'allow')
        self.assertEqual(classify_command("bash <<'EOF'\nit's data\nEOF").category, 'malformed')

    def test_a5_rule6_deny_cases(self):
        """SPEC A5 rule (6): script text fed to a shell without a heredoc."""
        for command in [
                "bash <<< 'git reset --hard'", "bash <<<'git reset --hard'",
                "bash /dev/fd/3 3<<< 'git reset --hard'", "bash <<< $'git reset --hard'",
                "sudo bash <<< 'git reset --hard'", "sh -s <<< 'git reset --hard'",
                "xargs -I{} sh -c '{}' <<< 'git reset --hard'",
                "bash <(echo 'git reset --hard')", "bash < <(echo 'git reset --hard')",
                "bash -s < <(echo 'git reset --hard')", "source <(echo 'git reset --hard')",
                ". <(echo 'git reset --hard')",
                "echo 'git reset --hard' | bash", "echo git reset --hard | bash",
                "cat <(echo 'git reset --hard') | bash", 'bash <<< "$(echo \'git reset --hard\')"',
                "printf 'git status\\ngit reset --hard\\n' | bash", "(echo 'git reset --hard') | bash",
                "echo 'git reset --hard' | sudo bash", 'bash -c "$(echo \'git reset --hard\')"',
                'eval "$(echo \'git reset --hard\')"', "eval `echo 'git reset --hard'`",
                "bash -c 'eval \"$1\"' _ 'git reset --hard'",
                "echo 'git reset --hard' | xargs -I{} sh -c '{}'", "xargs sh -c 'git reset --hard'",
                "git branch --merged | grep -v main | xargs git branch -D",
                "xargs -a list.txt git branch -D", r"find . -maxdepth 0 -exec git reset --hard \;",
                "doas git reset --hard", "stdbuf -o0 git reset --hard",
                "flock /tmp/l git reset --hard", "flock -w 5 /tmp/l git reset --hard",
                "flock /tmp/l -c 'git reset --hard'", "watch 'git reset --hard'",
                "watch -n1 git reset --hard", "doas -u root git reset --hard",
                "rg -l 'git push --force' docs | xargs sh -c 'wc -l \"$@\"' _"]:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).klass, 'deny')

    def test_a5_rule6_allow_cases(self):
        for command in [
                'cat <<< "git reset --hard"', "echo 'git reset --hard' | cat", "echo 'git status' | bash",
                "bash <<< 'git status'", "bash <(echo 'git log')",
                'bash -c "$(curl -fsSL https://example.com/i.sh)"', 'eval "$(ssh-agent -s)"',
                "find . -name '*.sh' | xargs -n1 bash -n", "xargs -n1 echo",
                "echo 'git reset --hard | bash'", "diff <(echo 'git reset --hard') f",
                "watch -n 5 git status", "flock /tmp/l git status", "stdbuf -oL git log",
                "doas git status", "find . -name x -exec echo {} +",
                "printf \"it's\\n\" | bash"]:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).klass, 'allow')

    def test_a5_rule6_here_string_release_and_nesting(self):
        self.assertEqual(classify_command("bash <<< 'gh pr merge 1'").klass, 'release')
        self.assertEqual(classify_command("bash <<< 'git push origin x'").klass, 'release')
        self.assertEqual(classify_command("echo $(bash <<< 'git reset --hard')").klass, 'deny')
        self.assertEqual(classify_command("bash <<< 'git status' && git reset --hard").klass, 'deny')

    def test_a5_rule6_runners_get_the_real_class(self):
        """SPEC A5 rule (6c) accepted cost: runner commands take the class of what they run."""
        for command in ['echo x | xargs rm', 'find . -name x -exec rm {} +', 'echo b | xargs git branch -d',
                        r"find . -name x -execdir rm {} \;", 'xargs -n1 rm', "watch rm x"]:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).klass, 'boundary')
        for command in ['xargs git push origin', 'xargs -n1 gh pr merge 1', "flock /tmp/l git push origin x", "doas git push origin x"]:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).klass, 'release')

    def test_a5_rule6_unparsable_piece_is_skipped_and_eval_heredoc_still_denies(self):
        self.assertEqual(classify_command("printf \"it's\\n\" | bash").klass, 'allow')
        self.assertEqual(classify_command("eval cat <<'EOF'\nx\nEOF").category, 'malformed')

    def test_a6_az_release_needs_deployment_create(self):
        for command in AZ_ALLOWED:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).klass, 'allow')
        self.assertEqual(classify_command('az deployment sub create --name x').klass, 'release')
        self.assertEqual(classify_command('az repos pr update --id 4 --status completed').klass, 'release')
        self.assertEqual(classify_command('az repos pr update --id 4 --status active').klass, 'allow')

    def test_a7_switch_force_denies_like_checkout(self):
        reason = classify_command('git checkout -f main').reason
        for command in SWITCH_DENIED:
            with self.subTest(command=command):
                decision = classify_command(command)
                self.assertEqual((decision.klass, decision.reason), ('deny', reason))
        self.assertEqual(classify_command('git switch main').klass, 'allow')
        self.assertEqual(classify_command('git switch -c topic').klass, 'allow')

    def test_a14_boundary_class(self):
        for command in BOUNDARY_DELETE:
            with self.subTest(command=command):
                decision = classify_command(command)
                self.assertEqual((decision.klass, decision.boundary, decision.action), ('boundary', 'delete', 'allow'))
        for command in BOUNDARY_MERGE:
            with self.subTest(command=command):
                decision = classify_command(command)
                self.assertEqual((decision.klass, decision.boundary), ('boundary', 'merge'))
        for command in ['git branch', 'git branch -a', 'git tag v1', 'git worktree list', 'git log', 'ls rm',
                        'echo rm -rf x', 'gh pr view 3', 'gh release view v1', 'find . -name x']:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).klass, 'allow')
        self.assertEqual(classify_command('git merge x && rm y').boundary, 'delete')
        self.assertEqual(classify_command('git merge x && git push origin b').klass, 'release-multi')


class HooksTest(unittest.TestCase):
    def pre(self, name, tool_input, cwd=None, **kw):
        payload = {'tool_name': name, 'tool_input': tool_input}
        if cwd is not None:
            payload['cwd'] = str(cwd)
        return handle_event('PreToolUse', payload, **kw)

    def test_native_deny(self):
        result = self.pre('Bash', {'command': 'git stash'}, harness='claude')
        self.assertEqual(result.output['hookSpecificOutput']['permissionDecision'], 'deny')
        self.assertEqual(result.exit_code, 0)
        with self.assertRaises(ValueError):
            self.pre('Bash', {'command': 'git status'}, harness='other')

    def test_malformed_relevant(self):
        for payload in [None, [], {}, {'tool_name': 'Bash'},
                        {'tool_name': 'Bash', 'tool_input': {'command': 2}}]:
            self.assertEqual(handle_event('PreToolUse', payload).exit_code, 2)
        self.assertEqual(self.pre('read_file', {'path': 'x'}).output, {})

    def test_release_unconfigured(self):
        # A1: with no armed run (engine None) every release class is allowed.
        for command in UNARMED_RELEASES + MULTI_RELEASES:
            with self.subTest(command=command):
                self.assertEqual(self.pre('Bash', {'command': command}).output, {})

    def test_armed_release_needs_a_permit(self):
        engine = mock.Mock()
        engine.check_release.side_effect = ValueError('No current explicit release permit')
        result = self.pre('Bash', {'command': 'git push origin feat/x'}, engine=engine)
        self.assertEqual(decision_of(result), 'deny')
        self.assertIn('No current explicit release permit', result.output['hookSpecificOutput']['permissionDecisionReason'])

    def test_armed_release_multi_denies_even_with_a_permit(self):
        engine = mock.Mock()
        engine.check_release.return_value = {'id': 'permit'}
        for command in MULTI_RELEASES:
            with self.subTest(command=command):
                self.assertEqual(decision_of(self.pre('Bash', {'command': command}, engine=engine)), 'deny')
        engine.check_release.assert_not_called()

    def test_armed_without_loadable_engine_denies_release_not_ordinary_commands(self):
        for command in ['git push origin feat/x', 'gh release create v1 --verify-tag']:
            self.assertEqual(decision_of(self.pre('Bash', {'command': command}, armed=True)), 'deny')
        self.assertEqual(self.pre('Bash', {'command': 'git status'}, armed=True).output, {})

    def test_update_ref_delete_denied(self):
        for command in UPDATE_REF_DENIED:
            with self.subTest(command=command):
                result = self.pre('Bash', {'command': command})
                self.assertEqual(decision_of(result), 'deny')
                self.assertEqual(result.output['hookSpecificOutput']['permissionDecisionReason'],
                                 'Raw ref deletion is not allowed; use git branch -d')
        for command in UPDATE_REF_ALLOWED:
            with self.subTest(command=command):
                self.assertEqual(self.pre('Bash', {'command': command}).output, {})

    def test_edit_relative_path_with_empty_cwd_denies_missing_cwd(self):
        with tempfile.TemporaryDirectory() as state, mock.patch.dict(os.environ, {'XDG_STATE_HOME': state}):
            for name in ('Edit', 'Write'):
                with self.subTest(tool=name):
                    result = handle_event('PreToolUse', {'cwd': '', 'tool_name': name,
                                                         'tool_input': {'file_path': 'notes.txt'}})
                    self.assertEqual(decision_of(result), 'deny')
                    self.assertEqual(result.output['hookSpecificOutput']['permissionDecisionReason'],
                                     'Session directory no longer exists: cd to an existing directory, then retry')
            # An absolute path needs no cwd and keeps its ordinary verdict.
            self.assertEqual(handle_event('PreToolUse', {'cwd': '', 'tool_name': 'Edit',
                                                         'tool_input': {'file_path': '/tmp/notes.txt'}}).output, {})

    def test_boundary_class_is_allowed_without_autonomy(self):
        for command in BOUNDARY_DELETE + BOUNDARY_MERGE:
            with self.subTest(command=command):
                self.assertEqual(self.pre('Bash', {'command': command}).output, {})
                self.assertEqual(self.pre('Bash', {'command': command}, armed=True, engine=mock.Mock()).output, {})

    def test_session_context_only(self):
        result = handle_event('SessionStart', {'source': 'startup'})
        context = result.output['hookSpecificOutput']['additionalContext']
        self.assertIn('main coordinator', context)
        worker = handle_event('SessionStart', {'agent_type': 'orchestra-builder'})
        self.assertNotIn('main coordinator', worker.output['hookSpecificOutput']['additionalContext'])
        # A11: worker context only for orchestra: agents; every other subagent gets {}.
        ours = handle_event('SubagentStart', {'agent_type': 'orchestra:builder'}).output['hookSpecificOutput']
        self.assertEqual(ours['hookEventName'], 'SubagentStart')
        self.assertIn('Orchestra worker', ours['additionalContext'])
        for agent in ('orchestra-builder', 'Explore', 'general-purpose', '', None):
            self.assertEqual(handle_event('SubagentStart', {'agent_type': agent}).output, {})
        self.assertEqual(handle_event('SubagentStart', {}).output, {})
        line = handle_event('SessionStart', {'source': 'startup', 'session_id': 'abc-123'}).output
        self.assertIn('--harness-session abc-123', line['hookSpecificOutput']['additionalContext'])
        worker = handle_event('SessionStart', {'agent_type': 'orchestra:builder', 'session_id': 'abc-123'})
        self.assertNotIn('--harness-session', worker.output['hookSpecificOutput']['additionalContext'])

    def test_stop_unarmed_and_interrupt(self):
        self.assertEqual(handle_event('Stop', {}).output, {})
        self.assertEqual(handle_event('Stop', {'stop_hook_active': True}).output, {})
        self.assertEqual(handle_event('Interrupt', {}).exit_code, 0)

    def test_protected_patch_paths(self):
        with tempfile.TemporaryDirectory() as cwd:
            for patch in ['*** Begin Patch\n*** Update File: .orchestra/state.json\n@@\n-x\n+y\n*** End Patch',
                          '*** Begin Patch\n*** Update File: a\n*** Move to: .claude/agents/orchestra-builder.md\n*** End Patch',
                          '*** Begin Patch\n*** Update File: .claude/hooks.json\n@@\n-x\n+y\n*** End Patch']:
                self.assertEqual(decision_of(self.pre('apply_patch', {'command': patch}, cwd=cwd)), 'deny')
            self.assertEqual(self.pre('apply_patch', {'command': 'bad patch'}, cwd=cwd).exit_code, 2)
            self.assertEqual(decision_of(self.pre('Write', {'file_path': '.claude/agents/orchestra-builder.md', 'content': 'x'}, cwd=cwd)), 'deny')
            self.assertEqual(self.pre('apply_patch', {'command': '*** Begin Patch\n*** Add File: a b.py\n+x\n*** End Patch'}, cwd=cwd).output, {})

    def test_protected_path_in_nested_harness_directory_b_f4(self):
        # B-F4: the first `.claude` in the resolved path is not the one that holds hooks.json.
        with tempfile.TemporaryDirectory() as directory:
            cwd = Path(directory) / '.claude' / 'plugins' / 'x'
            cwd.mkdir(parents=True)
            for tool, key in [('Edit', 'file_path'), ('Write', 'file_path'), ('MultiEdit', 'file_path')]:
                self.assertEqual(decision_of(self.pre(tool, {key: '.claude/hooks.json'}, cwd=cwd)), 'deny', tool)
            self.assertEqual(decision_of(self.pre('Write', {'file_path': '.claude/config.toml'}, cwd=cwd)), 'deny')
            self.assertEqual(decision_of(self.pre('Write', {'file_path': '.claude/agents/orchestra_builder.md'}, cwd=cwd)), 'deny')
            self.assertEqual(self.pre('Write', {'file_path': 'notes.md'}, cwd=cwd).output, {})
            self.assertEqual(self.pre('Write', {'file_path': '.claude/plugins/x/readme.md'}, cwd=cwd).output, {})

    def test_a8_settings_json_is_no_longer_protected(self):
        with tempfile.TemporaryDirectory() as cwd:
            for path in ['.claude/settings.json', '.claude/settings.local.json']:
                with self.subTest(path=path):
                    self.assertEqual(self.pre('Write', {'file_path': path}, cwd=cwd).output, {})
            for path in ['.claude/hooks.json', '.claude/config.toml', '.orchestra/x']:
                with self.subTest(path=path):
                    self.assertEqual(decision_of(self.pre('Write', {'file_path': path}, cwd=cwd)), 'deny')

    def test_a8_state_directory_protected_except_coordinator_files(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state'
            state.mkdir()
            for name in ['progress.md', 'standing-orders.md', 'autonomy.md']:
                with self.subTest(name=name):
                    self.assertEqual(self.pre('Write', {'file_path': str(state / name)}, cwd=directory, state_dir=str(state)).output, {})
            for name in ['state.json', 'policy.json', 'sub/progress.md']:
                with self.subTest(name=name):
                    self.assertEqual(decision_of(self.pre('Write', {'file_path': str(state / name)}, cwd=directory, state_dir=str(state))), 'deny')

    def test_a12_marker_directory_is_protected(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {'XDG_STATE_HOME': directory}):
            marker = Path(directory) / 'orchestra' / 'mods' / 's1.json'
            for tool in ['Edit', 'Write', 'MultiEdit']:
                self.assertEqual(decision_of(self.pre(tool, {'file_path': str(marker)}, cwd=directory)), 'deny', tool)
            patch = '*** Begin Patch\n*** Add File: ' + str(marker) + '\n+x\n*** End Patch'
            self.assertEqual(decision_of(self.pre('apply_patch', {'command': patch}, cwd=directory)), 'deny')
            self.assertEqual(decision_of(self.pre('Write', {'file_path': 'mods/../mods/s2.json'}, cwd=marker.parent)), 'deny')
            self.assertEqual(self.pre('Write', {'file_path': str(Path(directory) / 'orchestra' / 'notes.md')}, cwd=directory).output, {})

    def test_windows_executable_spellings_are_judged_like_posix_ones(self):
        for command in ['git.exe reset --hard', 'GIT.EXE reset --hard', '"C:\\Program Files\\Git\\cmd\\git.exe" reset --hard',
                        '/c/Program\\ Files/Git/cmd/git.exe clean -fd', 'git.exe push --force origin main']:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command).action, 'deny')
        self.assertNotEqual(classify_command('git.exe status').action, 'deny')

    def test_a12_marker_directory_defaults_under_home(self):
        with tempfile.TemporaryDirectory() as home, mock.patch.dict(os.environ, {'HOME': home, 'USERPROFILE': home}):
            os.environ.pop('XDG_STATE_HOME', None)
            marker = Path(home) / '.local/state/orchestra/mods/s1.json'
            self.assertEqual(decision_of(self.pre('Write', {'file_path': str(marker)}, cwd=home)), 'deny')

    def test_external_state_path_with_spaces(self):
        with tempfile.TemporaryDirectory(prefix='orchestra path ') as directory:
            state = Path(directory) / 'state dir'
            patch = '*** Begin Patch\n*** Add File: ' + str(state / 'state.json') + '\n+x\n*** End Patch'
            result = self.pre('apply_patch', {'command': patch}, state_dir=str(state))
            self.assertEqual(result.output['hookSpecificOutput']['permissionDecision'], 'deny')
            self.assertFalse(state.exists())

    def test_worker_environment_is_advisory(self):
        with unittest.mock.patch.dict(os.environ, {'ORCHESTRA_ROLE': 'builder'}):
            self.assertEqual(self.pre('spawn_agent', {}).output['hookSpecificOutput']['permissionDecision'], 'deny')

    def test_claude_worker_agent_call_is_denied(self):
        for tool in ['Agent', 'Task']:
            payload = {'tool_name': tool, 'tool_input': {}, 'agent_id': 'a1'}
            result = handle_event('PreToolUse', payload, harness='claude')
            self.assertEqual(result.output['hookSpecificOutput']['permissionDecision'], 'deny', tool)
            self.assertIn('Workers do not delegate', result.output['hookSpecificOutput']['permissionDecisionReason'])

    def test_claude_main_agent_call_is_allowed(self):
        for tool in ['Agent', 'Task']:
            payload = {'tool_name': tool, 'tool_input': {}}
            self.assertEqual(handle_event('PreToolUse', payload, harness='claude').output, {}, tool)

    def test_fresh_marker_does_not_skip_worker_agent_deny(self):
        with tempfile.TemporaryDirectory() as directory:
            mods = Path(directory) / 'orchestra' / 'mods'
            mods.mkdir(parents=True)
            (mods / 's1.json').write_text(json.dumps({'session_id': 's1', 'heartbeat_ms': int(time.time() * 1000),
                                                      'plugin_version': '2.0.0', 'rules_sha256': guard_digest()}))
            payload = {'cwd': directory, 'session_id': 's1', 'tool_name': 'Agent', 'tool_input': {}, 'agent_id': 'a1'}
            code, output = run_main(payload, '--harness', 'claude', env={'XDG_STATE_HOME': directory})
            self.assertEqual(code, 0)
            self.assertEqual(output['hookSpecificOutput']['permissionDecision'], 'deny')

    def test_release_checks_exact_command(self):
        engine = mock.Mock()
        engine.check_release.return_value = {'id': 'permit'}
        command = 'git push origin HEAD:main'
        self.assertEqual(self.pre('Bash', {'command': command}, engine=engine).output, {})
        engine.check_release.assert_called_once_with('origin', 'main', argv=['git', 'push', 'origin', 'HEAD:main'])
        engine.check_release.side_effect = ValueError('stale')
        self.assertIn('stale', self.pre('Bash', {'command': command}, engine=engine).output['hookSpecificOutput']['permissionDecisionReason'])
        self.assertEqual(self.pre('Bash', {'command': 'git -C other push origin main'}, engine=engine).output['hookSpecificOutput']['permissionDecision'], 'deny')

    def test_interrupt_and_bounded_adapter(self):
        engine = mock.Mock()
        handle_event('Interrupt', {}, engine=engine)
        engine.interrupt_active.assert_called_once_with()
        engine.status.assert_not_called()
        engine.interrupt.assert_not_called()
        engine.interrupt_active.side_effect = ValueError('corrupt')
        self.assertIn('could not be recorded', handle_event('Interrupt', {}, engine=engine).output['systemMessage'])
        engine.hook_stop.return_value = 'Continue one authorized bounded pass'
        self.assertEqual(handle_event('Stop', {}, engine=engine).output['decision'], 'block')
        engine.hook_stop.side_effect = ValueError('corrupt')
        self.assertEqual(handle_event('Stop', {}, engine=engine).output, {})

    def test_native_main_preserves_bad_json_exit(self):
        script = Path(__file__).resolve().parents[1] / 'plugins/orchestra/scripts/orchestra_hook.py'
        result = subprocess.run([sys.executable, str(script), 'PreToolUse'],
                                input='{', text=True, capture_output=True)
        self.assertEqual(result.returncode, 2)

    def test_main_uses_existing_repository_state_and_policy(self):
        from orchestra_core.paths import state_location
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {'XDG_STATE_HOME': directory}):
            os.environ.pop('ORCHESTRA_STATE_DIR', None)
            repo = Path(directory) / 'repo'
            repo.mkdir()
            subprocess.run(['git', 'init', '-q', str(repo)], check=True)
            nested = repo / 'nested'
            nested.mkdir()
            state = state_location(repo)
            state.mkdir(parents=True)
            (state / 'state.json').write_text('{}')
            policy = {'schema_version': 1, 'release': {'remote': 'origin'}}
            (state / 'policy.json').write_text(json.dumps(policy))
            constructor = mock.Mock()
            constructor.return_value.check_release.return_value = {'id': 'permit'}
            payload = {'cwd': str(nested), 'tool_name': 'Bash', 'tool_input': {'command': 'git push origin main'}}
            with mock.patch.dict(sys.modules, {'orchestra_core.engine': types.SimpleNamespace(Engine=constructor)}), mock.patch('sys.stdin', io.StringIO(json.dumps(payload))), mock.patch('sys.stdout', new_callable=io.StringIO) as output:
                self.assertEqual(main(['PreToolUse']), 0)
                self.assertEqual(json.loads(output.getvalue()), {})
            constructor.assert_called_once_with(state, repo.resolve(), policy=policy, lock_wait=2.0)

    def test_main_without_run_creates_no_state(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {'ORCHESTRA_STATE_DIR': str(Path(directory) / 'absent')}):
            constructor = mock.Mock()
            with mock.patch.dict(sys.modules, {'orchestra_core.engine': types.SimpleNamespace(Engine=constructor)}), mock.patch('sys.stdin', io.StringIO(json.dumps({'cwd': str(Path.cwd()), 'tool_name': 'read_file', 'tool_input': {}}))), mock.patch('sys.stdout', new_callable=io.StringIO):
                main(['PreToolUse'])
            constructor.assert_not_called()
            self.assertFalse((Path(directory) / 'absent').exists())

    def test_orchestrator_identity_and_skill_path(self):
        result = handle_event('SessionStart', {'agent_type': 'orchestra:orchestrator'})
        context = result.output['hookSpecificOutput']['additionalContext']
        self.assertIn('main coordinator', context)
        self.assertIn(str(Path(__file__).resolve().parents[1] / 'plugins/orchestra/skills/orchestra/SKILL.md'), context)

    def test_underscore_profile_protected(self):
        with tempfile.TemporaryDirectory() as cwd:
            self.assertEqual(decision_of(self.pre('Write', {'file_path': '.claude/agents/orchestra_builder.md'}, cwd=cwd)), 'deny')

    def test_stop_continues_until_engine_cap(self):
        engine = mock.Mock()
        engine.hook_stop.side_effect = ['bounded continuation', None]
        self.assertEqual(handle_event('Stop', {'stop_hook_active': True}, engine=engine).output['decision'], 'block')
        self.assertEqual(handle_event('Stop', {'stop_hook_active': True}, engine=engine).output, {})

    def test_cli_bad_json(self):
        result = subprocess.run([sys.executable, '-m', 'orchestra_core.hooks', 'PreToolUse'],
                                input='{', text=True, capture_output=True,
                                env={**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'plugins/orchestra/scripts')})
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)['hookSpecificOutput']['permissionDecision'], 'deny')

    def test_a9_claude_matcher_is_narrow(self):
        claude = json.loads((PLUGIN / 'hooks/claude.json').read_text())
        matcher = claude['hooks']['PreToolUse'][0]['matcher']
        self.assertEqual(matcher, RULES['tools']['claude_matcher'])
        for tool in ['Bash', 'Edit', 'Write', 'MultiEdit', 'Agent', 'Task']:
            self.assertRegex(tool, '^(?:' + matcher + ')$')
        self.assertNotRegex('Read', '^(?:' + matcher + ')$')

    def test_mod_tools_match_orchestra_ts_guarded(self):
        """_MOD_TOOLS hand-mirrors GUARDED in the TypeScript mod; drift would reopen a marker skip."""
        source = (PLUGIN / 'hooks/mod/orchestra.ts').read_text()
        found = re.search(r'^const GUARDED\s*=\s*\[([^\]]*)\]', source, re.M)
        self.assertIsNotNone(found, 'GUARDED list not found in orchestra.ts')
        guarded = set(re.findall(r"'([^']+)'", found.group(1)))
        self.assertTrue(guarded)
        self.assertEqual(hooks_module._MOD_TOOLS, guarded)


def run_main(payload, *args, env=None):
    """Run the real hook entry point; returns (exit code, decoded stdout)."""
    with mock.patch.dict(os.environ, env or {}), mock.patch('sys.stdin', io.StringIO(json.dumps(payload))), \
            mock.patch('sys.stdout', new_callable=io.StringIO) as output, mock.patch('sys.stderr', new_callable=io.StringIO):
        code = main(['PreToolUse', *args])
        return code, json.loads(output.getvalue())


def git(cwd, *args):
    return subprocess.check_output(['git', '-C', str(cwd), *args], stderr=subprocess.PIPE, text=True).strip()


class MergedDeleteHookTest(unittest.TestCase):
    """SPEC 5.14 item 4: a merged-delete command is checked in Python against merge evidence, whatever the autonomy state."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name).resolve()
        self.origin = root / 'origin.git'
        git(root, 'init', '-q', '--bare', '-b', 'main', str(self.origin))
        self.repo = root / 'work'
        git(root, 'clone', '-q', str(self.origin), str(self.repo))
        for key, value in (('user.name', 'T'), ('user.email', 't@example.invalid')):
            git(self.repo, 'config', key, value)
        git(self.repo, 'checkout', '-q', '-b', 'main')
        self.commit('base.txt', 'base\n')
        git(self.repo, 'push', '-q', 'origin', 'main')
        git(self.repo, 'remote', 'set-head', 'origin', 'main')

    def commit(self, name, text):
        (self.repo / name).write_text(text)
        git(self.repo, 'add', name)
        git(self.repo, 'commit', '-q', '-m', name)

    def side(self, branch, name, text, start='main'):
        """A branch off `start` with one commit; HEAD returns to main."""
        git(self.repo, 'checkout', '-q', '-b', branch, start)
        self.commit(name, text)
        git(self.repo, 'checkout', '-q', 'main')

    def land_squash(self, branch):
        git(self.repo, 'merge', '-q', '--squash', branch)
        git(self.repo, 'commit', '-q', '-m', 'squash ' + branch)
        git(self.repo, 'push', '-q', 'origin', 'main')

    def run_hook(self, command, **kw):
        payload = {'tool_name': 'Bash', 'tool_input': {'command': command}, 'cwd': str(self.repo)}
        return handle_event('PreToolUse', payload, harness='claude', **kw)

    def assertAllowed(self, command, **kw):
        result = self.run_hook(command, **kw)
        self.assertEqual(result.output, {}, command)

    def assertDenied(self, command, text, **kw):
        result = self.run_hook(command, **kw)
        self.assertEqual(decision_of(result), 'deny', command)
        self.assertIn(text, result.output['hookSpecificOutput']['permissionDecisionReason'])

    def is_ancestor(self, tip, ref):
        return subprocess.run(['git', '-C', str(self.repo), 'merge-base', '--is-ancestor', tip, ref]).returncode == 0

    def test_merged_delete_allows_ancestor_branch(self):
        self.side('x', 'x.txt', 'x\n')
        git(self.repo, 'merge', '-q', '--ff-only', 'x')
        git(self.repo, 'push', '-q', 'origin', 'main')
        self.assertTrue(self.is_ancestor('x', 'origin/main'))
        self.assertAllowed('git branch -D x')

    def test_merged_delete_allows_squash_tree_equal_branch(self):
        self.side('x', 'x.txt', 'x\n')
        self.land_squash('x')
        self.assertFalse(self.is_ancestor('x', 'origin/main'))
        self.assertEqual(git(self.repo, 'rev-parse', 'x^{tree}'), git(self.repo, 'rev-parse', 'origin/main^{tree}'))
        self.assertAllowed('git branch -D x')

    def test_merged_delete_allows_branch_covered_by_tree_equal_branch(self):
        self.side('x', 'x.txt', 'x\n')
        self.side('cover', 'cover.txt', 'c\n', start='x')
        self.land_squash('cover')
        self.assertFalse(self.is_ancestor('x', 'origin/main'))
        self.assertNotIn(git(self.repo, 'rev-parse', 'x^{tree}'),
                         git(self.repo, 'rev-list', '--first-parent', '--format=%T', 'origin/main').split())
        self.assertAllowed('git branch -D x')
        # The evidence is read afresh at each delete: without the covering branch the same tip is unmerged.
        git(self.repo, 'branch', '-q', '-D', 'cover')
        self.assertDenied('git branch -D x', 'Branch x is not merged into origin/main')

    def test_merged_delete_denies_unmerged_branch(self):
        self.side('x', 'x.txt', 'x\n')
        self.assertDenied('git branch -D x',
                          'Branch x is not merged into origin/main (no ancestor, tree or covering-branch evidence)')
        self.assertDenied('git branch --delete --force x', 'Branch x is not merged into origin/main')
        self.assertDenied('git branch -D missing', 'does not exist')
        git(self.repo, 'branch', 'y', 'main')
        git(self.repo, 'checkout', '-q', 'y')
        self.assertDenied('git branch -D y', 'checked out')
        git(self.repo, 'checkout', '-q', 'main')
        self.assertDenied('git branch -D main', 'default branch')
        self.assertDenied('git push --delete origin main', 'default branch')

    def test_merged_delete_shadowed_default_ref_denies_unmerged(self):
        # R2: a local branch or tag named origin/main must not stand in for the remote-tracking default.
        self.side('x', 'x.txt', 'x\n')
        git(self.repo, 'remote', 'set-head', 'origin', '-d')
        for kinds in (('branch',), ('tag',), ('branch', 'tag')):
            with self.subTest(shadow=kinds):
                for kind in kinds:
                    git(self.repo, kind, 'origin/main', 'x')
                try:
                    self.assertDenied('git branch -D x', 'Branch x is not merged into origin/main')
                finally:
                    for kind in kinds:
                        git(self.repo, kind, '-D' if kind == 'branch' else '-d', 'origin/main')

    def test_merged_delete_default_branch_denied_with_ambiguous_short_name(self):
        # R2: with a local branch origin/main, `symbolic-ref --short` reads remotes/origin/main; the name comes from the full ref.
        self.remote_branch()
        git(self.repo, 'branch', 'origin/main', 'main')
        git(self.repo, 'checkout', '-q', '-b', 'y')
        self.assertDenied('git branch -D main', 'Branch main is the default branch')
        self.assertDenied('git push --delete origin main', 'Branch main is the default branch')

    def test_merged_delete_case_variant_of_default_denied(self):
        # FS2-1: on a case-insensitive filesystem refs/heads/Main resolves to refs/heads/main.
        git(self.repo, 'config', 'core.ignorecase', 'true')
        git(self.repo, 'remote', 'remove', 'origin')  # the default is the local refs/heads/main
        git(self.repo, 'checkout', '-q', '-b', 'y')
        self.assertDenied('git branch -D Main', 'default branch')
        self.assertEqual(git(self.repo, 'rev-parse', '--verify', 'refs/heads/main'), git(self.repo, 'rev-parse', 'main'))

    def test_merged_delete_case_variant_of_checked_out_denied(self):
        git(self.repo, 'config', 'core.ignorecase', 'true')  # main is checked out; the default compare fires first
        self.assertDenied('git branch -D Main', 'Branch Main is the default branch')

    def test_merged_delete_case_variant_checked_out_reason(self):
        self.side('feat', 'f.txt', 'f\n')
        git(self.repo, 'checkout', '-q', 'feat')
        git(self.repo, 'config', 'core.ignorecase', 'true')
        self.assertDenied('git branch -D Feat', 'Branch Feat is checked out')

    def test_merged_delete_exact_ref_without_ignorecase(self):
        git(self.repo, 'branch', 'feat', 'main')
        git(self.repo, 'config', 'core.ignorecase', 'false')
        self.assertDenied('git branch -D Feat', 'Branch Feat does not exist')

    def test_merged_delete_case_twin_packed_denied(self):
        # FC3: a packed feat and a loose Feat; on a case-insensitive filesystem rev-parse refs/heads/feat reads
        # the loose Feat file, and git deletes both refs. A case-sensitive filesystem keeps two distinct refs.
        self.side('feat', 'f.txt', 'f\n')
        git(self.repo, 'pack-refs', '--all')
        made = subprocess.run(['git', '-C', str(self.repo), 'branch', 'Feat', 'main'], capture_output=True, text=True)
        refs = git(self.repo, 'for-each-ref', '--format=%(refname)', 'refs/heads/').split()
        if made.returncode != 0 or not {'refs/heads/feat', 'refs/heads/Feat'} <= set(refs):
            self.skipTest('git cannot create the case twin here: %s' % made.stderr.strip())
        for ignorecase in ('true', 'false'):
            git(self.repo, 'config', 'core.ignorecase', ignorecase)
            for name in ('feat', 'Feat'):
                with self.subTest(ignorecase=ignorecase, name=name):
                    self.assertDenied('git branch -D ' + name, 'Branch %s has a case-variant twin; refusing to delete' % name)

    def test_merged_delete_unresolvable_default_denies(self):
        self.side('x', 'x.txt', 'x\n')
        git(self.repo, 'merge', '-q', '--ff-only', 'x')
        git(self.repo, 'remote', 'remove', 'origin')
        git(self.repo, 'branch', '-q', '-m', 'main', 'trunk')
        self.assertDenied('git branch -D x', 'cannot be resolved')

    def test_merged_delete_checked_with_autonomy_off_and_no_engine(self):
        self.side('x', 'x.txt', 'x\n')
        self.assertDenied('git branch -D x', 'is not merged')  # engine None
        engine = mock.Mock()
        engine.autonomy_active.return_value = False
        self.assertDenied('git branch -D x', 'is not merged', engine=engine, armed=True)  # armed run, autonomy off
        self.assertDenied('git branch -D x', 'is not merged', armed=True, autonomy=False)  # state unloadable, autonomy off
        git(self.repo, 'merge', '-q', '--ff-only', 'x')
        git(self.repo, 'push', '-q', 'origin', 'main')
        self.assertAllowed('git branch -D x', engine=engine, armed=True)

    def test_merged_delete_denied_under_autonomy(self):
        self.side('x', 'x.txt', 'x\n')
        git(self.repo, 'merge', '-q', '--ff-only', 'x')
        git(self.repo, 'push', '-q', 'origin', 'main')
        self.assertAllowed('git branch -D x')  # merged: the autonomy-off verdict
        engine = mock.Mock()
        engine.autonomy_active.return_value = True
        self.assertDenied('git branch -D x', 'Approval boundary under autonomy', engine=engine, armed=True)
        self.assertDenied('git branch -D x', 'Approval boundary under autonomy', armed=True, autonomy=True)
        flaky = mock.Mock()
        flaky.autonomy_active.side_effect = RuntimeError('state changed')  # O29: an unreadable status counts as active
        self.assertDenied('git branch -D x', 'Approval boundary under autonomy', engine=flaky, armed=True)

    def remote_branch(self):
        """A branch x merged into main and pushed, so origin and the tracking ref both carry it."""
        self.side('x', 'x.txt', 'x\n')
        git(self.repo, 'push', '-q', 'origin', 'x')
        git(self.repo, 'merge', '-q', '--ff-only', 'x')
        git(self.repo, 'push', '-q', 'origin', 'main')

    def test_remote_delete_allowed_when_merged_and_ls_remote_matches(self):
        self.remote_branch()
        self.assertAllowed('git push origin --delete x')
        self.assertAllowed('git push origin -d x')

    def test_remote_delete_denied_when_ls_remote_differs_or_times_out(self):
        self.remote_branch()
        # Moved tip: another clone advanced origin/x after our last fetch.
        other = Path(self.temp.name) / 'other'
        git(Path(self.temp.name), 'clone', '-q', str(self.origin), str(other))
        for key, value in (('user.name', 'T'), ('user.email', 't@example.invalid')):
            git(other, 'config', key, value)
        git(other, 'checkout', '-q', 'x')
        (other / 'late.txt').write_text('late\n')
        git(other, 'add', 'late.txt')
        git(other, 'commit', '-q', '-m', 'late')
        git(other, 'push', '-q', 'origin', 'x')
        self.assertDenied('git push origin --delete x', 'does not report x at the tracking tip')
        git(self.repo, 'fetch', '-q', 'origin')
        # The fetched tip carries the late commit: the ls-remote check passes and the merge evidence now fails.
        self.assertDenied('git push origin --delete x', 'Branch x is not merged into origin/main')

    def test_remote_delete_unreachable_remote_denied(self):
        self.remote_branch()
        probe = socket.socket()
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
        probe.close()  # nothing listens: connection refused
        git(self.repo, 'remote', 'set-url', 'origin', f'git://127.0.0.1:{port}/r.git')
        self.assertDenied('git push origin --delete x', 'does not report x at the tracking tip')

    def test_remote_delete_denied_when_the_remote_hangs(self):
        self.remote_branch()
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(4)
        self.addCleanup(server.close)
        held = []

        def accept():
            try:
                while True:
                    held.append(server.accept()[0])  # accept, never answer
            except OSError:
                pass

        threading.Thread(target=accept, daemon=True).start()
        git(self.repo, 'remote', 'set-url', 'origin', f'git://127.0.0.1:{server.getsockname()[1]}/r.git')
        start = time.monotonic()
        self.assertDenied('git push origin --delete x', 'does not report x at the tracking tip')
        self.assertLess(time.monotonic() - start, 9)
        for conn in held:
            conn.close()

    def divergent_target(self):
        """A second bare repository whose x carries a commit the fetch remote and the tracking ref lack."""
        root = Path(self.temp.name)
        target = root / 'target.git'
        git(root, 'clone', '-q', '--bare', str(self.origin), str(target))
        scratch = root / 'scratch'
        git(root, 'clone', '-q', '-b', 'x', str(target), str(scratch))
        for key, value in (('user.name', 'T'), ('user.email', 't@example.invalid')):
            git(scratch, 'config', key, value)
        (scratch / 'only-there.txt').write_text('unmerged\n')
        git(scratch, 'add', 'only-there.txt')
        git(scratch, 'commit', '-q', '-m', 'unmerged')
        git(scratch, 'push', '-q', 'origin', 'x')
        return target

    def test_merged_remote_delete_denies_divergent_pushurl(self):
        self.remote_branch()
        self.assertAllowed('git push origin --delete x')  # matching push and fetch URL: still allowed
        target = self.divergent_target()
        git(self.repo, 'config', 'remote.origin.pushurl', str(target))
        self.assertDenied('git push origin --delete x', 'push URL')
        self.assertNotEqual(git(target, 'rev-parse', 'refs/heads/x'), git(self.repo, 'rev-parse', 'refs/remotes/origin/x'))

    def test_merged_remote_delete_denies_pushinsteadof(self):
        self.remote_branch()
        target = self.divergent_target()
        git(self.repo, 'config', 'url.%s.pushInsteadOf' % target, str(self.origin))
        self.assertDenied('git push origin --delete x', 'push URL')

    def remove_default_refs(self):
        """No real default ref: origin/HEAD, origin/main and the local main are all absent."""
        git(self.repo, 'remote', 'set-head', 'origin', '-d')
        git(self.repo, 'update-ref', '-d', 'refs/remotes/origin/main')
        git(self.repo, 'branch', '-q', '-m', 'main', 'trunk')

    def assert_decoys_ignored(self, namespace):
        self.side('x', 'x.txt', 'x\n', start='main')
        self.remove_default_refs()
        tip = git(self.repo, 'rev-parse', 'refs/heads/x')
        for name in ('refs/remotes/origin/main', 'refs/remotes/origin/HEAD', 'refs/heads/main'):
            decoy = namespace + name
            with self.subTest(decoy=decoy):
                git(self.repo, 'update-ref', decoy, tip)
                try:
                    self.assertEqual(git(self.repo, 'rev-parse', '--verify', '--quiet', name + '^{commit}'), tip)
                    self.assertDenied('git branch -D x', 'The default branch cannot be resolved; refusing to delete x')
                finally:
                    git(self.repo, 'update-ref', '-d', decoy)

    def test_merged_delete_ignores_decoy_branch_named_like_default_ref(self):
        self.assert_decoys_ignored('refs/heads/')

    def test_merged_delete_ignores_decoy_tag_named_like_default_ref(self):
        self.assert_decoys_ignored('refs/tags/')


class MarkerHandshakeTest(unittest.TestCase):
    """A12: a fresh marker with this copy's rules hash lets Python skip; anything else guards."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.xdg = Path(self.temp.name) / 'xdg'
        self.cwd = Path(self.temp.name) / 'cwd'
        self.cwd.mkdir()
        self.mods = self.xdg / 'orchestra' / 'mods'
        self.mods.mkdir(parents=True)
        self.env = {'XDG_STATE_HOME': str(self.xdg)}
        self.sha = guard_digest()

    def marker(self, session='s1', *, age_ms=0, sha=None, inner=None, name=None):
        data = {'session_id': inner or session, 'heartbeat_ms': int(time.time() * 1000) - age_ms,
                'plugin_version': '2.0.0', 'rules_sha256': self.sha if sha is None else sha}
        (self.mods / ((name or session) + '.json')).write_text(json.dumps(data))

    def call(self, session='s1', *args, harness='claude', command='git stash'):
        payload = {'cwd': str(self.cwd), 'session_id': session, 'tool_name': 'Bash', 'tool_input': {'command': command}}
        code, output = run_main(payload, '--harness', harness, *args, env=self.env)
        self.assertEqual(code, 0)
        return output

    def assertGuards(self, output):
        self.assertEqual(output['hookSpecificOutput']['permissionDecision'], 'deny')

    def test_fresh_marker_with_matching_rules_skips_guarding(self):
        self.marker()
        self.assertEqual(self.call(), {})

    def test_stale_marker_guards(self):
        self.marker(age_ms=20000)
        self.assertGuards(self.call())

    def test_retired_marker_guards(self):
        self.marker()
        data = json.loads((self.mods / 's1.json').read_text())
        data['heartbeat_ms'] = 0
        (self.mods / 's1.json').write_text(json.dumps(data))
        self.assertGuards(self.call())

    def test_marker_just_inside_the_window_skips(self):
        self.marker(age_ms=10000)
        self.assertEqual(self.call(), {})

    def test_wrong_or_missing_rules_hash_guards(self):
        self.marker(sha='0' * 64)
        self.assertGuards(self.call())
        self.marker(sha='')
        data = json.loads((self.mods / 's1.json').read_text())
        data['rules_sha256'] = None
        (self.mods / 's1.json').write_text(json.dumps(data))
        self.assertGuards(self.call())

    def test_missing_unreadable_and_foreign_markers_guard(self):
        self.assertGuards(self.call())
        (self.mods / 's1.json').write_text('{not json')
        self.assertGuards(self.call())
        self.marker(session='s1', inner='other')
        self.assertGuards(self.call())

    def test_malformed_session_id_skips_the_marker_check(self):
        self.marker(session='bad id!')
        self.assertGuards(self.call('bad id!'))
        self.marker(session='escape', name='../escape')
        self.assertGuards(self.call('../escape'))
        self.marker(session='x' * 129)
        self.assertGuards(self.call('x' * 129))
        self.assertGuards(self.call(''))
        self.marker(session='ok_id-1')
        self.assertEqual(self.call('ok_id-1'), {})

    def test_from_mod_skips_the_marker_check(self):
        self.marker()
        self.assertGuards(self.call('s1', '--from-mod'))

    def test_marker_applies_only_to_pre_tool_use(self):
        self.marker()
        payload = {'cwd': str(self.cwd), 'session_id': 's1'}
        with mock.patch.dict(os.environ, self.env), mock.patch('sys.stdin', io.StringIO(json.dumps(payload))), \
                mock.patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(main(['SessionStart', '--harness', 'claude']), 0)
            self.assertIn('additionalContext', output.getvalue())

    def test_reviewer_and_critic_calls_are_never_skipped_by_a_fresh_marker(self):
        self.marker()
        for kind in ('orchestra:code-reviewer', 'orchestra:critic'):
            payload = {'cwd': str(self.cwd), 'session_id': 's1', 'tool_name': 'Bash', 'agent_id': 'a1', 'agent_type': kind,
                       'tool_input': {'command': 'git stash'}}
            code, output = run_main(payload, '--harness', 'claude', env=self.env)
            self.assertGuards(output)
        payload.update(agent_type='orchestra:builder')
        self.assertEqual(run_main(payload, '--harness', 'claude', env=self.env)[1], {})

    def test_fresh_marker_skips_before_any_git_or_engine_work(self):
        self.marker()
        with mock.patch('subprocess.check_output', side_effect=AssertionError('git ran')):
            self.assertEqual(self.call(), {})


class RunStateResolutionTest(unittest.TestCase):
    """A1 states and A15: where the hook looks for the run."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.env = {'XDG_STATE_HOME': str(self.root / 'xdg')}
        patcher = mock.patch.dict(os.environ, self.env)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop('ORCHESTRA_STATE_DIR', None)
        self.repo = self.root / 'main'
        self.repo.mkdir()
        git(self.repo, 'init', '-q', '-b', 'main')
        git(self.repo, 'config', 'user.name', 'T')
        git(self.repo, 'config', 'user.email', 't@example.invalid')
        (self.repo / 'f.txt').write_text('x\n')
        git(self.repo, 'add', 'f.txt')
        git(self.repo, 'commit', '-q', '-m', 'f')
        self.linked = self.root / 'linked'
        git(self.repo, 'worktree', 'add', '-q', str(self.linked), '-b', 'side')

    def start(self, repo):
        out = subprocess.run([sys.executable, str(CLI), '--repo', str(repo), 'start', '--size', 'medium'], env=os.environ,
                             capture_output=True, text=True, check=True).stdout
        return json.loads(out)['lease']

    def interrupt(self, repo, lease):
        subprocess.run([sys.executable, str(CLI), '--repo', str(repo), '--lease', lease, 'interrupt'],
                       env=os.environ, capture_output=True, text=True, check=True)

    def bash(self, cwd, command):
        code, output = run_main({'cwd': str(cwd), 'tool_name': 'Bash', 'tool_input': {'command': command}})
        self.assertEqual(code, 0)
        return output.get('hookSpecificOutput', {}).get('permissionDecision')

    def test_unarmed_repository_allows_release_classes(self):
        for command in UNARMED_RELEASES + MULTI_RELEASES:
            with self.subTest(command=command):
                self.assertIsNone(self.bash(self.repo, command))
        self.assertEqual(self.bash(self.repo, 'git push --force origin x'), 'deny')

    def test_armed_main_checkout_denies_release_without_a_permit(self):
        self.start(self.repo)
        self.assertEqual(self.bash(self.repo, 'git push origin side'), 'deny')
        self.assertEqual(self.bash(self.repo, 'git push origin x && git status'), 'deny')
        self.assertIsNone(self.bash(self.repo, 'git status'))
        self.assertIsNone(self.bash(self.repo, 'rm -rf build'))

    def test_interrupted_run_is_unarmed_again(self):
        lease = self.start(self.repo)
        self.assertEqual(self.bash(self.repo, 'git push origin side'), 'deny')
        self.interrupt(self.repo, lease)
        self.assertIsNone(self.bash(self.repo, 'git push origin side'))

    def test_unloadable_state_file_denies_release(self):
        from orchestra_core.paths import state_location
        state = state_location(self.repo)
        state.mkdir(parents=True)
        for text in ['{not json', '{}', '[]', '{"version": 1, "session": {"active": "yes"}}']:
            (state / 'state.json').write_text(text)
            with self.subTest(text=text):
                self.assertEqual(self.bash(self.repo, 'git push origin side'), 'deny')
                self.assertEqual(self.bash(self.repo, 'gh release create v1 --verify-tag'), 'deny')
                self.assertIsNone(self.bash(self.repo, 'git status'))

    def test_a15_linked_worktree_of_an_armed_repository_denies_release(self):
        self.start(self.repo)
        for command in LINKED_WORKTREE_COMMANDS:
            with self.subTest(command=command):
                self.assertEqual(self.bash(self.linked, command), 'deny')
        self.assertIsNone(self.bash(self.linked, 'git status'))

    def test_a15_linked_worktree_of_an_unarmed_repository_allows_release(self):
        for command in LINKED_WORKTREE_COMMANDS:
            with self.subTest(command=command):
                self.assertIsNone(self.bash(self.linked, command))
        lease = self.start(self.repo)
        self.interrupt(self.repo, lease)
        self.assertIsNone(self.bash(self.linked, 'git push origin side'))

    def test_a15_state_of_the_linked_worktree_itself_wins(self):
        # Its own armed run is found first; the main worktree's inactive state is never consulted.
        self.start(self.linked)
        self.assertEqual(self.bash(self.linked, 'git push origin side'), 'deny')
        self.assertIsNone(self.bash(self.repo, 'git push origin side'))

    def test_a15_protected_state_follows_the_main_worktree(self):
        from orchestra_core.paths import state_location
        self.start(self.repo)
        state = state_location(self.repo)
        payload = {'cwd': str(self.linked), 'tool_name': 'Write', 'tool_input': {'file_path': str(state / 'state.json')}}
        code, output = run_main(payload)
        self.assertEqual(output['hookSpecificOutput']['permissionDecision'], 'deny')

    def test_f8_main_worktree_with_an_absolute_common_dir(self):
        sub = self.linked / 'sub'
        sub.mkdir()
        self.assertEqual(_main_worktree(self.linked), self.repo)
        self.assertEqual(_main_worktree(sub), self.repo)

    def test_f8_main_worktree_joins_a_relative_common_dir_to_the_payload_cwd(self):
        # Git before --path-format prints a path relative to the directory it ran in.
        real, calls = subprocess.check_output, []
        sub = self.linked / 'sub'
        sub.mkdir()

        def relative(argv, **kwargs):
            calls.append(argv)
            out = real(argv, **kwargs).decode().strip()
            return os.path.relpath(out, argv[2]).encode()

        for cwd in (self.linked, sub):
            with self.subTest(cwd=cwd), mock.patch('orchestra_core.hooks.subprocess.check_output', side_effect=relative):
                self.assertEqual(_main_worktree(cwd), self.repo)
        self.assertFalse(any(arg.startswith('--path-format') for argv in calls for arg in argv))

    def test_a15_bare_common_directory_stays_unarmed(self):
        from orchestra_core.paths import state_location
        bare = self.root / 'bare.git'
        subprocess.run(['git', 'clone', '-q', '--bare', str(self.repo), str(bare)], check=True, capture_output=True)
        git(bare, 'worktree', 'add', '-q', str(self.root / 'bare-wt'), 'main')
        # Even an armed-looking state at the bare directory's parent must never be consulted.
        parent_state = state_location(self.root)
        parent_state.mkdir(parents=True)
        (parent_state / 'state.json').write_text('{}')
        self.assertIsNone(self.bash(self.root / 'bare-wt', 'git push origin main'))
        self.assertIsNone(self.bash(self.root / 'bare-wt', 'git push origin main && git status'))


class HarnessSessionHookTest(unittest.TestCase):
    """B-F5: SessionEnd release policy and the /clear, /resume rebind. The engine clock is injected."""

    def setUp(self):
        from orchestra_core.engine import Engine
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name).resolve()
        self.repo = root / 'repo'
        self.repo.mkdir()
        git(self.repo, 'init', '-q', '-b', 'main')
        git(self.repo, 'config', 'user.name', 'T')
        git(self.repo, 'config', 'user.email', 't@example.invalid')
        (self.repo / 'f').write_text('x')
        git(self.repo, 'add', 'f')
        git(self.repo, 'commit', '-q', '-m', 'f')
        self.now = [5000.0]
        self.engine = Engine(root / 'state', self.repo, clock=lambda: self.now[0])
        self.engine.open_session('main', harness_session='S')

    def session(self):
        return self.engine.status()['session']

    def end(self, session_id, reason, engine=None):
        return handle_event('SessionEnd', {'session_id': session_id, 'reason': reason, 'cwd': str(self.repo)},
                            harness='claude', engine=engine or self.engine)

    def start(self, session_id, source, harness='claude', engine=None):
        return handle_event('SessionStart', {'session_id': session_id, 'source': source, 'cwd': str(self.repo)},
                            harness=harness, engine=engine or self.engine)

    def test_release_reasons_end_the_bound_session(self):
        for reason in ('logout', 'prompt_input_exit', 'other', 'bypass_permissions_disabled', None, 7):
            with self.subTest(reason=reason):
                self.engine.state_path.unlink(missing_ok=True)
                self.engine.open_session('main', harness_session='S')
                payload = {'session_id': 'S', 'cwd': str(self.repo)}
                if reason is not None:
                    payload['reason'] = reason
                self.assertEqual(handle_event('SessionEnd', payload, harness='claude', engine=self.engine).output, {})
                self.assertFalse(self.session()['active'])
                self.assertEqual(self.session()['outcome'], 'ended')

    def test_clear_and_resume_keep_the_run_armed(self):
        for reason in ('clear', 'resume'):
            self.assertEqual(self.end('S', reason).output, {})
            self.assertTrue(self.session()['active'])
            self.assertEqual(self.session()['pending_rebind'], {'from': 'S', 'at': 5000.0})

    def test_other_id_and_unbound_run_are_untouched(self):
        self.end('other', 'prompt_input_exit')
        self.end('other', 'clear')
        self.assertTrue(self.session()['active'])
        self.assertNotIn('pending_rebind', self.session())
        self.engine.interrupt_active()
        self.engine.open_session('main')
        before = self.engine.state_path.read_bytes()
        self.end('S', 'prompt_input_exit')
        self.end('S', 'clear')
        self.assertEqual(self.engine.state_path.read_bytes(), before)

    def test_repeated_session_end_is_idempotent(self):
        self.end('S', 'prompt_input_exit')
        after = self.engine.state_path.read_bytes()
        self.assertEqual(self.end('S', 'prompt_input_exit').output, {})
        self.assertEqual(self.engine.state_path.read_bytes(), after)

    def test_session_end_without_an_engine_or_id_is_a_no_op(self):
        self.assertEqual(handle_event('SessionEnd', {'reason': 'other'}, harness='claude').output, {})
        self.assertEqual(handle_event('SessionEnd', {'reason': 'other'}, harness='claude', engine=self.engine).output, {})
        self.assertTrue(self.session()['active'])

    def test_clear_rebinds_then_exit_of_new_id_releases(self):
        self.end('S', 'clear')
        self.now[0] += 1
        ctx = self.start('S2', 'clear').output['hookSpecificOutput']['additionalContext']
        self.assertIn('--harness-session S2', ctx)
        self.assertEqual(self.session()['harness_session'], 'S2')
        self.assertNotIn('pending_rebind', self.session())
        self.end('S2', 'prompt_input_exit')
        self.assertFalse(self.session()['active'])

    def test_resume_rebinds_then_exit_of_new_id_releases(self):
        self.end('S', 'resume')
        self.start('S2', 'resume')
        self.assertEqual(self.session()['harness_session'], 'S2')
        self.end('S2', 'prompt_input_exit')
        self.assertFalse(self.session()['active'])

    def test_fork_after_resume_rebinds(self):
        self.end('S', 'resume')
        self.start('S2', 'fork')
        self.assertEqual(self.session()['harness_session'], 'S2')

    def test_startup_and_compact_do_not_rebind(self):
        for source in ('startup', 'compact'):
            self.end('S', 'clear')
            ctx = self.start('S2', source).output['hookSpecificOutput']['additionalContext']
            self.assertIn('--harness-session S2', ctx)  # the context line is still the payload id
            self.assertEqual(self.session()['harness_session'], 'S')
            self.assertIn('pending_rebind', self.session())  # left alone by every other path

    def test_worker_session_start_never_rebinds(self):
        self.end('S', 'clear')
        handle_event('SessionStart', {'session_id': 'S2', 'source': 'resume', 'cwd': str(self.repo),
                                      'agent_type': 'orchestra:builder'}, harness='claude', engine=self.engine)
        self.assertEqual(self.session()['harness_session'], 'S')

    def test_stale_and_negative_age_pending_rebind_is_removed_without_binding(self):
        for delta in (60.5, 3600, -5):
            with self.subTest(delta=delta):
                self.now[0] = 5000.0
                self.end('S', 'clear')
                self.now[0] = 5000.0 + delta
                self.start('S2', 'clear')
                self.assertEqual(self.session()['harness_session'], 'S')
                self.assertNotIn('pending_rebind', self.session())

    def test_after_a_rebind_the_old_id_does_not_release(self):
        self.end('S', 'clear')
        self.start('S2', 'clear')
        self.end('S', 'prompt_input_exit')
        self.assertTrue(self.session()['active'])

    def test_second_clear_does_not_rebind_again(self):
        self.end('S', 'clear')
        self.start('S2', 'clear')
        self.start('S3', 'clear')
        self.assertEqual(self.session()['harness_session'], 'S2')

    def test_release_removes_pending_rebind_and_keeps_harness_session(self):
        self.end('S', 'clear')
        self.end('S', 'logout')
        self.assertFalse(self.session()['active'])
        self.assertNotIn('pending_rebind', self.session())
        self.assertEqual(self.session()['harness_session'], 'S')

    def test_rebind_error_still_returns_the_session_start_context(self):
        self.end('S', 'clear')
        self.engine.state_path.write_text('{not json')
        result = self.start('S2', 'clear')
        context = result.output['hookSpecificOutput']['additionalContext']
        self.assertIn('main coordinator', context)
        self.assertIn('--harness-session S2', context)

    def test_interrupt_event_interrupts_an_active_run_through_interrupt_active(self):
        with mock.patch.object(self.engine, 'interrupt_active', wraps=self.engine.interrupt_active) as spy, \
                mock.patch.object(self.engine, 'interrupt', side_effect=AssertionError('lease path used')):
            self.assertEqual(handle_event('Interrupt', {}, harness='claude', engine=self.engine).output, {})
        spy.assert_called_once_with()
        self.assertFalse(self.session()['active'])
        self.assertEqual(handle_event('Interrupt', {}, harness='claude', engine=self.engine).output, {})

    def foreign_policy(self):
        data = json.loads(self.engine.state_path.read_text())
        data['policy'] = '0' * 64
        self.engine.state_path.write_text(json.dumps(data))

    def test_session_end_of_an_ended_run_under_a_changed_policy_is_silent(self):
        self.engine.interrupt('main', json.loads(self.engine.state_path.read_text())['session']['lease'])
        self.foreign_policy()
        result = self.end('S', 'logout')
        self.assertEqual((result.exit_code, result.output), (0, {}))

    def test_session_end_of_an_active_run_under_a_changed_policy_is_still_reported(self):
        self.foreign_policy()
        result = self.end('S', 'logout')
        self.assertIn('could not be recorded', result.output['systemMessage'])

    def test_session_end_error_is_reported_not_raised(self):
        self.engine.state_path.write_text('{not json')
        result = self.end('S', 'logout')
        self.assertEqual(result.exit_code, 0)
        self.assertIn('could not be recorded', result.output['systemMessage'])


class SessionEndBuildErrorTest(unittest.TestCase):
    """R3 F3: an engine that cannot be built at SessionEnd is reported, not silent."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        patcher = mock.patch.dict(os.environ, {'XDG_STATE_HOME': str(self.root / 'xdg')})
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop('ORCHESTRA_STATE_DIR', None)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        git(self.repo, 'init', '-q', '-b', 'main')
        git(self.repo, 'config', 'user.name', 'T')
        git(self.repo, 'config', 'user.email', 't@example.invalid')
        (self.repo / 'f').write_text('x')
        git(self.repo, 'add', 'f')
        git(self.repo, 'commit', '-q', '-m', 'f')

    def session_end(self, session_id='S', reason='prompt_input_exit'):
        payload = {'session_id': session_id, 'reason': reason, 'cwd': str(self.repo)}
        with mock.patch('sys.stdin', io.StringIO(json.dumps(payload))), \
                mock.patch('sys.stdout', new_callable=io.StringIO) as output:
            code = main(['SessionEnd', '--harness', 'claude'])
        return code, json.loads(output.getvalue())

    def test_malformed_policy_names_the_error_and_manual_recovery(self):
        from orchestra_core.paths import state_location
        subprocess.run([sys.executable, str(CLI), '--repo', str(self.repo), 'start', '--harness-session', 'S', '--size', 'medium'],
                       env=os.environ, capture_output=True, text=True, check=True)
        (state_location(self.repo) / 'policy.json').write_text('{not json')
        code, output = self.session_end()
        self.assertEqual(code, 0)
        message = output['systemMessage']
        self.assertIn('could not be recorded', message)
        self.assertIn('Expecting property name', message)
        self.assertIn('--actor A --lease L interrupt', message)

    def test_no_state_file_stays_silent(self):
        self.assertEqual(self.session_end(), (0, {}))

    def test_malformed_policy_on_an_ended_run_stays_silent(self):
        """FX6 (O35): an ended run has nothing to record, even when the engine cannot be built."""
        from orchestra_core.paths import state_location
        out = subprocess.run([sys.executable, str(CLI), '--repo', str(self.repo), 'start', '--harness-session', 'S', '--size', 'medium'],
                             env=os.environ, capture_output=True, text=True, check=True).stdout
        subprocess.run([sys.executable, str(CLI), '--repo', str(self.repo), '--lease', json.loads(out)['lease'],
                        'interrupt'], env=os.environ, capture_output=True, text=True, check=True)
        state = state_location(self.repo)
        self.assertIs(json.loads((state / 'state.json').read_text())['session']['active'], False)
        (state / 'policy.json').write_text('{not json')
        self.assertEqual(self.session_end(), (0, {}))


class RunHookScriptTest(unittest.TestCase):
    def test_syntax(self):
        self.assertEqual(subprocess.run(['bash', '-n', str(RUN_HOOK)]).returncode, 0)
        self.assertEqual(subprocess.run([SH, '-n', str(RUN_HOOK)]).returncode, 0)

    def run_hook(self, *args, trace=False, stdin=''):
        cmd = [SH] + (['-x'] if trace else []) + [str(RUN_HOOK), *args]
        return subprocess.run(cmd, input=stdin, text=True, capture_output=True, timeout=60)

    def test_hook_runs_python_once_without_a_probe(self):
        if not any(shutil.which(name) for name in ['python3.14', 'python3.13', 'python3.12', 'python3.11']):
            self.skipTest('no versioned Python on PATH; the probing fallback is the only path')
        result = self.run_hook('PreToolUse', '--harness', 'claude', trace=True,
                               stdin=json.dumps({'tool_name': 'Read', 'tool_input': {}}))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {})
        self.assertNotIn('sys.version_info', result.stderr)
        launches = [l for l in result.stderr.splitlines() if l.startswith('+ exec ')]
        self.assertEqual(len(launches), 1, result.stderr)
        self.assertTrue(launches[0].startswith('+ exec python3.'), launches)

    def test_cli_first_argument_execs_the_orchestra_cli(self):
        result = self.run_hook('--cli', 'classify', 'git reset --hard')
        self.assertEqual(result.returncode, 0, result.stderr)
        decision = json.loads(result.stdout)
        self.assertEqual(decision['action'], 'deny')
        usage = self.run_hook('--cli', '--help')
        self.assertEqual(usage.returncode, 0)
        self.assertIn('classify', usage.stdout)

    def test_cli_exit_status_is_preserved(self):
        self.assertNotEqual(self.run_hook('--cli', 'no-such-command').returncode, 0)

    def test_script_resolves_its_directory_from_dollar_zero(self):
        result = subprocess.run([SH, 'run-hook.sh', '--cli', 'classify', 'git status'], cwd=RUN_HOOK.parent,
                                text=True, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['action'], 'allow')


class AutonomyHookTest(unittest.TestCase):
    """SPEC 12: the autonomy columns of the PreToolUse mapping, Stop and the SessionStart report."""

    def setUp(self):
        from orchestra_core.engine import AUTONOMY_FIXED, Engine
        from orchestra_core.paths import state_location
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        patcher = mock.patch.dict(os.environ, {'XDG_STATE_HOME': str(self.root / 'xdg')})
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop('ORCHESTRA_STATE_DIR', None)
        self.repo = self.root / 'main'
        self.repo.mkdir()
        git(self.repo, 'init', '-q', '-b', 'main')
        git(self.repo, 'config', 'user.name', 'T')
        git(self.repo, 'config', 'user.email', 't@example.invalid')
        (self.repo / 'f.txt').write_text('x\n')
        git(self.repo, 'add', 'f.txt')
        git(self.repo, 'commit', '-q', '-m', 'f')
        self.linked = self.root / 'linked'
        git(self.repo, 'worktree', 'add', '-q', str(self.linked), '-b', 'side')
        self.state = state_location(self.repo)
        self.now = [1_800_000_000.0]
        self.engine = Engine(self.state, self.repo, clock=lambda: self.now[0])
        self.lease = self.engine.open_session('main')
        self.fixed = AUTONOMY_FIXED

    def ledger(self, passes='3', deadline_in=3600):
        when = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(self.now[0] + deadline_in))
        text = ['goal: g', 'max_passes: ' + passes, 'max_stalls: 2', 'deadline: ' + when, '', '## Completion checks', '',
                'never: ' + sys.executable + ' -c "import sys; sys.exit(1)"', '', '## Approval boundaries', '', *self.fixed]
        (self.state / 'autonomy.md').write_text('\n'.join(text) + '\n')

    def arm(self, **kw):
        self.ledger(**kw)
        self.engine.arm_autonomy()

    def hook(self, cwd, command):
        code, output = run_main({'cwd': str(cwd), 'tool_name': 'Bash', 'tool_input': {'command': command}})
        self.assertEqual(code, 0)
        return output.get('hookSpecificOutput', {}).get('permissionDecision')

    def test_boundary_denied_while_active_and_allowed_while_autonomy_is_off(self):
        for command in ['rm -rf build', 'rmdir empty', 'unlink link', 'git branch -d topic', 'git tag -d v1']:
            with self.subTest(command=command):
                self.assertIsNone(self.hook(self.repo, command))  # armed run, autonomy off
        self.arm()
        for command in ['rm -rf build', 'rmdir empty', 'unlink link', 'git branch -d topic', 'git tag -d v1']:
            with self.subTest(command=command):
                self.assertEqual(self.hook(self.repo, command), 'deny')
        self.assertIsNone(self.hook(self.repo, 'git status'))
        self.engine.disarm_autonomy()
        self.assertIsNone(self.hook(self.repo, 'rm -rf build'))

    def test_denial_names_the_park_command(self):
        self.arm()
        code, output = run_main({'cwd': str(self.repo), 'tool_name': 'Bash', 'tool_input': {'command': 'rm -rf build'}})
        reason = output['hookSpecificOutput']['permissionDecisionReason']
        self.assertIn('park', reason)
        self.assertIn('--reason', reason)

    def test_pretooluse_armed_without_session_under_relaunch(self):
        self.ledger()
        self.engine.arm_autonomy(relaunch=True)
        self.engine.interrupt('main', self.lease)  # between passes: no active session, relaunch autonomy stays armed
        self.assertFalse(self.engine.status()['session']['active'])
        for command in ['git worktree remove x', 'rm -rf build']:
            with self.subTest(command=command):
                code, output = run_main({'cwd': str(self.repo), 'tool_name': 'Bash', 'tool_input': {'command': command}})
                decision = output['hookSpecificOutput']
                self.assertEqual(decision['permissionDecision'], 'deny')
                self.assertIn('Approval boundary under autonomy', decision['permissionDecisionReason'])
        code, output = run_main({'cwd': str(self.repo), 'tool_name': 'Bash', 'tool_input': {'command': 'git push origin side'}})
        self.assertEqual(output['hookSpecificOutput']['permissionDecision'], 'deny')  # no session: no release, fail closed
        self.assertIsNone(self.hook(self.repo, 'git status'))

    def test_pretooluse_without_session_and_without_relaunch_stays_unarmed(self):
        self.ledger()
        self.engine.arm_autonomy()
        self.engine.interrupt('main', self.lease)  # 2.1: a session end clears in-session autonomy
        self.assertIsNone(self.hook(self.repo, 'git worktree remove x'))

    def test_pretooluse_relaunch_armed_with_an_unloadable_state_is_active_without_a_session(self):
        self.ledger()
        self.engine.arm_autonomy(relaunch=True)
        self.engine.interrupt('main', self.lease)
        data = json.loads((self.state / 'state.json').read_text())
        data['policy'] = 'changed'  # the engine cannot load this state any more
        (self.state / 'state.json').write_text(json.dumps(data))
        code, output = run_main({'cwd': str(self.repo), 'tool_name': 'Bash', 'tool_input': {'command': 'git worktree remove x'}})
        self.assertEqual(output['hookSpecificOutput']['permissionDecision'], 'deny')

    def test_stop_without_session_under_relaunch_changes_nothing(self):
        self.ledger()
        self.engine.arm_autonomy(relaunch=True)
        self.engine.interrupt('main', self.lease)
        before = (self.state / 'state.json').read_bytes()
        with mock.patch('sys.stdin', io.StringIO(json.dumps({'cwd': str(self.repo), 'session_id': 'other'}))), \
                mock.patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(main(['Stop']), 0)
        self.assertEqual(json.loads(output.getvalue()), {})
        self.assertEqual(before, (self.state / 'state.json').read_bytes())

    def test_pretooluse_preauthorized_release_reaches_permit_check(self):
        from orchestra_core.engine import Engine
        unit = [sys.executable, '-c', 'print("passed")']
        policy = {'schema_version': 1, 'required_checks': [{'name': 'unit', 'argv': unit}],
                  'release': {'enabled': True, 'authorization': 'user request', 'remote': 'origin', 'target': 'side',
                              'argv': ['git', 'push', 'origin', 'side']}}
        (self.state / 'state.json').unlink()
        (self.state / 'policy.json').write_text(json.dumps(policy))
        self.engine = Engine(self.state, self.repo, policy=policy, clock=lambda: self.now[0])
        self.lease = self.engine.open_session('main')
        categories = ['requirements', 'correctness', 'security', 'tests', 'architecture', 'standards', 'cleanup']
        report = self.root / 'final.json'
        report.write_text(json.dumps(dict(reviewer='reviewer', categories=categories, tasks=[], findings=[], issues=[], final=True,
                                          verdict='CLEAN', artifact=self.engine.artifact(),
                                          summary='Behavior checked against acceptance criteria.')))
        self.engine.record_review('main', self.lease, 'reviewer', report, categories, final=True)
        self.engine.run_gate('main', self.lease, 'unit', unit)
        push = ['git', 'push', 'origin', 'side']
        self.fixed = [('- Release: pre-authorized origin side' if line.startswith('- Release:') else line) for line in self.fixed]
        self.arm()
        self.assertEqual(self.engine.status()['autonomy']['release'], {'remote': 'origin', 'target': 'side'})
        self.assertEqual(self.hook(self.repo, 'git push origin side'), 'deny')  # exact pair, no permit yet: the permit check
        code, output = run_main({'cwd': str(self.repo), 'tool_name': 'Bash', 'tool_input': {'command': 'git push origin side'}})
        self.assertIn('No current explicit release permit', output['hookSpecificOutput']['permissionDecisionReason'])
        self.engine.release_permit('main', self.lease, 'origin', 'side')
        self.assertIsNone(self.hook(self.repo, ' '.join(push)))  # exact pair with a permit: allowed
        for command in ['git push origin other', 'git push origin side && git status', 'rm -rf build']:
            with self.subTest(command=command):
                code, output = run_main({'cwd': str(self.repo), 'tool_name': 'Bash', 'tool_input': {'command': command}})
                decision = output['hookSpecificOutput']
                self.assertEqual(decision['permissionDecision'], 'deny')
                self.assertTrue(decision['permissionDecisionReason'].startswith(('Autonomy is active: ', 'Approval boundary under autonomy')),
                                decision['permissionDecisionReason'])

    def test_release_is_denied_while_active_even_with_a_permit(self):
        from orchestra_core.engine import Engine
        unit = [sys.executable, '-c', 'print("passed")']
        policy = {'schema_version': 1, 'required_checks': [{'name': 'unit', 'argv': unit}],
                  'release': {'enabled': True, 'authorization': 'user request', 'remote': 'origin', 'target': 'side',
                              'argv': ['git', 'push', 'origin', 'side']}}
        (self.state / 'state.json').unlink()  # a fresh run under the release policy the hook loads
        (self.state / 'policy.json').write_text(json.dumps(policy))
        self.engine = Engine(self.state, self.repo, policy=policy, clock=lambda: self.now[0])
        self.lease = self.engine.open_session('main')
        categories = ['requirements', 'correctness', 'security', 'tests', 'architecture', 'standards', 'cleanup']
        report = self.root / 'final.json'
        report.write_text(json.dumps(dict(reviewer='reviewer', categories=categories, tasks=[], findings=[], issues=[], final=True,
                                          verdict='CLEAN', artifact=self.engine.artifact(),
                                          summary='Behavior checked against acceptance criteria.')))
        self.engine.record_review('main', self.lease, 'reviewer', report, categories, final=True)
        self.engine.run_gate('main', self.lease, 'unit', unit)
        self.engine.release_permit('main', self.lease, 'origin', 'side')
        self.assertIsNone(self.hook(self.repo, 'git push origin side'))  # the permit is real and current
        self.arm()
        for command in ['git push origin side', 'git push origin side && git status', 'gh release create v1 --verify-tag']:
            with self.subTest(command=command):
                code, output = run_main({'cwd': str(self.repo), 'tool_name': 'Bash', 'tool_input': {'command': command}})
                decision = output['hookSpecificOutput']
                self.assertEqual(decision['permissionDecision'], 'deny')
                self.assertTrue(decision['permissionDecisionReason'].startswith('Autonomy is active: '),
                                decision['permissionDecisionReason'])

    def break_policy(self):
        """A plugin contract or policy change: the stored policy hash no longer matches, so the engine cannot load."""
        data = json.loads((self.state / 'state.json').read_text())
        data['policy'] = '0' * 64
        (self.state / 'state.json').write_text(json.dumps(data))

    def truncate_state(self):
        text = (self.state / 'state.json').read_text()
        (self.state / 'state.json').write_text(text[:len(text) // 2])

    def stop_main(self, cwd):
        payload = {'cwd': str(cwd), 'session_id': 's-1'}
        with mock.patch('sys.stdin', io.StringIO(json.dumps(payload))), \
                mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(main(['Stop', '--harness', 'claude']), 0)
        return json.loads(out.getvalue())

    def assert_unloadable_active_state_denies(self):
        for cwd in (self.repo, self.linked):
            with self.subTest(cwd=cwd.name):
                self.assertEqual(self.hook(cwd, 'rm -rf build'), 'deny')
                self.assertEqual(self.hook(cwd, 'git push origin side'), 'deny')
                self.assertIsNone(self.hook(cwd, 'git status'))
                self.assertEqual(self.stop_main(cwd), {})
        self.assertEqual(self.hook(self.repo, 'git merge topic'), 'deny')  # main checkout on the default branch
        self.assertIsNone(self.hook(self.linked, 'git merge topic'))  # linked worktree on `side`
        git(self.repo, 'checkout', '-q', '--detach')
        git(self.linked, 'checkout', '-q', 'main')
        self.assertEqual(self.hook(self.linked, 'git merge topic'), 'deny')  # linked worktree on the default branch

    def test_o29_policy_change_while_active_denies_boundaries(self):
        self.arm()
        self.break_policy()
        self.assert_unloadable_active_state_denies()

    def test_o29_truncated_state_denies_boundaries(self):
        self.arm()
        self.truncate_state()
        self.assert_unloadable_active_state_denies()

    def test_o29_policy_change_with_autonomy_inactive_is_armed_autonomy_off(self):
        self.arm()
        self.engine.disarm_autonomy()
        self.break_policy()
        for cwd in (self.repo, self.linked):
            with self.subTest(cwd=cwd.name):
                self.assertIsNone(self.hook(cwd, 'rm -rf build'))
                self.assertEqual(self.hook(cwd, 'git push origin side'), 'deny')  # A1: armed, no permit
                self.assertEqual(self.stop_main(cwd), {})
        self.assertIsNone(self.hook(self.repo, 'git merge topic'))
        never_armed = json.loads((self.state / 'state.json').read_text())
        never_armed.pop('autonomy', None)
        (self.state / 'state.json').write_text(json.dumps(never_armed))
        self.assertIsNone(self.hook(self.repo, 'rm -rf build'))

    def set_raw_session_active(self, value):
        data = json.loads((self.state / 'state.json').read_text())
        data['session']['active'] = value
        (self.state / 'state.json').write_text(json.dumps(data))

    def test_o35_ended_run_under_a_changed_policy_is_unarmed(self):
        self.engine.interrupt('main', self.lease)
        self.break_policy()
        for cwd in (self.repo, self.linked):
            with self.subTest(cwd=cwd.name):
                self.assertIsNone(self.hook(cwd, 'git push origin main'))
                self.assertIsNone(self.hook(cwd, 'rm -rf build'))
                self.assertEqual(self.hook(cwd, 'git reset --hard'), 'deny')  # always-deny is unchanged
                self.assertEqual(self.stop_main(cwd), {})

    def test_o35_active_run_under_a_changed_policy_stays_armed(self):
        self.engine.interrupt('main', self.lease)
        self.break_policy()
        self.set_raw_session_active(True)
        for cwd in (self.repo, self.linked):
            with self.subTest(cwd=cwd.name):
                self.assertEqual(self.hook(cwd, 'git push origin main'), 'deny')
                self.assertEqual(self.hook(cwd, 'git reset --hard'), 'deny')

    def test_o35_unparseable_state_stays_armed(self):
        self.engine.interrupt('main', self.lease)
        self.truncate_state()
        self.assertEqual(self.hook(self.repo, 'git push origin main'), 'deny')

    def test_o29_autonomy_status_error_counts_as_active(self):
        engine = mock.Mock()
        engine.autonomy_active.side_effect = RuntimeError('state changed')
        payload = {'cwd': str(self.repo), 'tool_name': 'Bash', 'tool_input': {'command': 'rm -rf build'}}
        result = handle_event('PreToolUse', payload, harness='claude', engine=engine)
        self.assertEqual(result.output['hookSpecificOutput']['permissionDecision'], 'deny')

    def test_merge_denied_on_the_default_branch_and_allowed_on_another(self):
        self.arm()
        self.assertEqual(self.hook(self.repo, 'git merge topic'), 'deny')  # main is the default branch
        git(self.repo, 'checkout', '-q', '-b', 'work')
        self.assertIsNone(self.hook(self.repo, 'git merge topic'))
        self.assertIsNone(self.hook(self.repo, 'git pull --rebase origin main'))

    def test_merge_allowed_while_autonomy_is_off_on_the_default_branch(self):
        self.assertIsNone(self.hook(self.repo, 'git merge topic'))

    def test_merge_default_branch_follows_origin_head(self):
        git(self.repo, 'update-ref', 'refs/remotes/origin/trunk', 'HEAD')
        git(self.repo, 'symbolic-ref', 'refs/remotes/origin/HEAD', 'refs/remotes/origin/trunk')
        self.arm()
        self.assertIsNone(self.hook(self.repo, 'git merge topic'))  # main is not the default here
        git(self.repo, 'checkout', '-q', '-b', 'trunk')
        self.assertEqual(self.hook(self.repo, 'git merge topic'), 'deny')

    def test_merge_on_a_detached_head_is_denied(self):
        self.arm()
        git(self.repo, 'checkout', '-q', '--detach')
        self.assertEqual(self.hook(self.repo, 'git merge topic'), 'deny')

    def test_a15_push_and_rm_denied_in_a_linked_worktree_of_the_armed_repository(self):
        self.arm()
        for command in ['git push origin side', 'git -C ../linked push origin side', 'rm -rf build', 'rm file.txt']:
            with self.subTest(command=command):
                self.assertEqual(self.hook(self.linked, command), 'deny')
        self.assertIsNone(self.hook(self.linked, 'git status'))

    def test_linked_worktree_merge_reads_the_branch_of_the_payload_cwd(self):
        self.arm()
        # The linked worktree is on `side`; the main worktree has the default branch checked out.
        self.assertIsNone(self.hook(self.linked, 'git merge topic'))
        self.assertEqual(self.hook(self.repo, 'git merge topic'), 'deny')
        # Reverse: the linked worktree holds the default branch while the main worktree is elsewhere.
        git(self.linked, 'checkout', '-q', '--detach')
        git(self.repo, 'checkout', '-q', 'side')
        git(self.linked, 'checkout', '-q', 'main')
        self.assertEqual(self.hook(self.linked, 'git merge topic'), 'deny')
        self.assertIsNone(self.hook(self.repo, 'git merge topic'))

    def stop(self):
        return handle_event('Stop', {'cwd': str(self.repo)}, harness='claude', engine=self.engine).output

    def add_card(self, name):
        self.engine.add_task('main', self.lease, dict(id=name, role='builder', mode='implementation', inputs=['spec'],
                             acceptance=['check'], files=[name], resources=[], dependencies=[]))

    def stop_as(self, cwd, session_id):
        payload = {'cwd': str(cwd)} if session_id is None else {'cwd': str(cwd), 'session_id': session_id}
        with mock.patch('sys.stdin', io.StringIO(json.dumps(payload))), \
                mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(main(['Stop', '--harness', 'claude']), 0)
        return json.loads(out.getvalue())

    def test_o37_stop_from_another_session_neither_continues_nor_spends_a_pass(self):
        data = json.loads((self.state / 'state.json').read_text())
        data['session']['harness_session'] = 'S-main'
        (self.state / 'state.json').write_text(json.dumps(data))
        self.arm(passes='3')
        self.add_card('c1')
        passes = lambda: self.engine.status()['autonomy']['passes']
        self.assertEqual(self.stop_as(self.linked, 's-1'), {})  # another Claude session in a linked worktree
        self.assertEqual(passes(), 0)
        self.assertEqual(self.stop_as(self.linked, 'S-main')['decision'], 'block')
        self.assertEqual(passes(), 1)
        self.assertEqual(self.stop_as(self.repo, None)['decision'], 'block')  # no session id: as before
        self.assertEqual(passes(), 2)

    def test_o37_stop_without_a_bound_session_continues_as_before(self):
        self.arm(passes='3')
        self.add_card('c1')
        self.assertEqual(self.stop_as(self.linked, 's-1')['decision'], 'block')
        self.assertEqual(self.engine.status()['autonomy']['passes'], 1)

    def test_stop_continues_while_active_and_stops_at_the_deadline(self):
        self.arm(passes='1')
        self.add_card('c1')
        first = self.stop()
        self.assertEqual(first['decision'], 'block')
        self.assertIn('Autonomy pass 1', first['reason'])
        self.assertNotIn('Autonomy pass 1 of', first['reason'])
        self.assertEqual(self.stop()['decision'], 'block')  # the old cap of 1 no longer stops the loop
        self.now[0] += 7200
        self.assertEqual(self.stop(), {})
        self.assertEqual(self.engine.status()['autonomy']['last_stop_reason'], 'deadline')

    def test_stop_stops_at_the_deadline(self):
        self.arm()
        self.now[0] += 7200
        self.assertEqual(self.stop(), {})
        self.assertEqual(self.engine.status()['autonomy']['last_stop_reason'], 'deadline')

    def test_stop_without_autonomy_is_empty(self):
        self.assertEqual(self.stop(), {})

    def test_session_start_shows_the_report_with_the_progress_path(self):
        self.arm()
        self.now[0] += 7200
        self.stop()
        payload = {'cwd': str(self.repo), 'session_id': 's-1', 'source': 'startup'}
        with mock.patch('sys.stdin', io.StringIO(json.dumps(payload))), \
                mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            main(['SessionStart', '--harness', 'claude'])
        context = json.loads(out.getvalue())['hookSpecificOutput']['additionalContext']
        self.assertIn('Run brief', context)
        self.assertNotIn('Autonomy report', context)
        self.assertIn('deadline', context)
        self.assertIn(str(self.state / 'progress.md'), context)

    def test_session_start_report_is_capped_at_2000_characters(self):
        engine = mock.Mock()
        engine.status.return_value = {}
        engine.autonomy_report.return_value = {'reason': 'complete', 'text': 'Q' * 5000, 'path': '/p/progress.md'}
        context = handle_event('SessionStart', {'session_id': 's-1', 'source': 'startup'}, harness='claude',
                               engine=engine).output['hookSpecificOutput']['additionalContext']
        self.assertEqual(context.count('Q'), 2000)
        self.assertIn('/p/progress.md', context)

    def test_session_start_without_a_report_adds_nothing(self):
        context = handle_event('SessionStart', {'session_id': 's-1', 'source': 'startup'}, harness='claude',
                               engine=self.engine).output['hookSpecificOutput']['additionalContext']
        self.assertNotIn('Autonomy report', context)
        self.assertNotIn('Run brief', context)

    def test_session_start_worker_gets_no_report(self):
        engine = mock.Mock()
        engine.status.return_value = {}
        engine.autonomy_report.return_value = {'reason': 'complete', 'text': 'T', 'path': '/p'}
        with mock.patch.dict(os.environ, {'ORCHESTRA_ROLE': 'builder'}):
            context = handle_event('SessionStart', {'session_id': 's-1'}, harness='claude',
                                   engine=engine).output['hookSpecificOutput']['additionalContext']
        self.assertNotIn('Autonomy report', context)
        self.assertNotIn('Run brief', context)


class RunBriefHookTest(unittest.TestCase):
    """SPEC 5.9 and 5.16: the run brief at SessionStart, the missing-cwd and busy-lock behavior of the hooks."""

    setUp = AutonomyHookTest.setUp
    ledger = AutonomyHookTest.ledger
    arm = AutonomyHookTest.arm
    hook = AutonomyHookTest.hook
    stop_main = AutonomyHookTest.stop_main

    def session_context(self):
        payload = {'cwd': str(self.repo), 'session_id': 's-9', 'source': 'startup'}
        with mock.patch('sys.stdin', io.StringIO(json.dumps(payload))), \
                mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            main(['SessionStart', '--harness', 'claude'])
        return json.loads(out.getvalue())['hookSpecificOutput']['additionalContext']

    def hold_lock(self):
        from orchestra_core import portable as fcntl
        self.engine.status()
        handle = open(self.state / 'state.lock', 'a+')
        fcntl.flock(handle, fcntl.LOCK_EX)
        self.addCleanup(handle.close)
        return handle

    def release_lock(self, handle):
        from orchestra_core import portable as fcntl
        fcntl.flock(handle, fcntl.LOCK_UN)

    def agent_main(self, kind='general-purpose'):
        code, output = run_main({'cwd': str(self.repo), 'tool_name': 'Agent',
                                 'tool_input': {'prompt': 'x', 'subagent_type': kind}})
        self.assertEqual(code, 0)
        return output.get('hookSpecificOutput', {}).get('permissionDecisionReason')

    def test_agent_guard_denies_while_an_active_run_is_busy(self):
        self.hold_lock()
        self.assertEqual(self.agent_main(), hooks_module.AGENT_GUARD)
        self.assertIsNone(self.agent_main('orchestra:builder'))

    def test_agent_guard_denies_while_an_active_run_cannot_load(self):
        data = json.loads((self.state / 'state.json').read_text())
        data['version'] = 99
        (self.state / 'state.json').write_text(json.dumps(data))
        self.assertEqual(self.agent_main(), hooks_module.AGENT_GUARD)
        data['session']['active'] = False
        (self.state / 'state.json').write_text(json.dumps(data))
        self.assertIsNone(self.agent_main())  # an ended run is outside a run

    def test_session_start_shows_newest_brief_without_autonomy(self):
        self.engine.interrupt('main', self.lease)
        context = self.session_context()
        self.assertIn('Run brief (interrupted): ', context)
        self.assertIn('## Run brief', context)
        self.assertIn(str(self.state / 'progress.md'), context)

    def test_session_start_excerpt_contains_needs_you(self):
        self.engine.add_task('main', self.lease, dict(id='p', role='builder', mode='implementation', inputs=['spec'],
                             acceptance=['check'], files=['p'], resources=[], dependencies=[]))
        self.engine.park('main', self.lease, 'p', 'needs a push')
        self.engine.interrupt('main', self.lease)
        context = self.session_context()
        self.assertIn('Needs you', context)
        self.assertLess(context.index('Needs you'), context.index('p: needs a push') + 1)

    def test_session_start_falls_back_to_2_1_autonomy_report(self):
        self.arm()
        self.stop_main(self.repo)
        data = json.loads((self.state / 'state.json').read_text())
        self.assertIn('report', data['autonomy'])
        del data['last_brief']
        (self.state / 'state.json').write_text(json.dumps(data))
        context = self.session_context()
        self.assertIn('Autonomy report (no-ready-card): ## Run brief', context)  # the hook runs on the real clock
        self.assertNotIn('Run brief (', context)

    def test_pretooluse_missing_cwd_denies_delegated_class_with_reason(self):
        gone = self.root / 'gone'
        for command in ['git push origin side', 'rm -rf build']:
            with self.subTest(command=command):
                code, output = run_main({'cwd': str(gone), 'tool_name': 'Bash', 'tool_input': {'command': command}})
                self.assertEqual(code, 0)
                decision = output['hookSpecificOutput']
                self.assertEqual(decision['permissionDecision'], 'deny')
                self.assertEqual(decision['permissionDecisionReason'],
                                 'Session directory no longer exists: cd to an existing directory, then retry')

    def test_pretooluse_missing_cwd_allows_nothing_new(self):
        gone = self.root / 'gone'
        self.assertEqual(self.hook(gone, 'git status'), None)  # an allowed class stays allowed
        self.assertEqual(self.hook(gone, 'git reset --hard'), 'deny')  # a plain deny stays denied
        self.assertEqual(self.hook(self.repo, 'git push origin side'), 'deny')  # existing cwd: unchanged

    def test_hook_state_read_fails_closed_after_lock_wait(self):
        self.arm()
        self.hold_lock()
        started = time.monotonic()
        code, output = run_main({'cwd': str(self.repo), 'tool_name': 'Bash', 'tool_input': {'command': 'git push origin side'}})
        self.assertLess(time.monotonic() - started, 6)
        self.assertEqual(output['hookSpecificOutput']['permissionDecision'], 'deny')
        self.assertEqual(output['hookSpecificOutput']['permissionDecisionReason'], 'Orchestra state is busy; retry')

    def test_hook_busy_lock_keeps_raw_fallback_for_other_classes(self):
        self.arm()
        self.hold_lock()
        self.assertIsNone(self.hook(self.repo, 'git status'))
        self.assertEqual(self.hook(self.repo, 'git reset --hard'), 'deny')
        self.assertEqual(self.hook(self.repo, 'rm -rf build'), 'deny')  # raw armed state still guards the boundary

    def test_ended_run_busy_lock_does_not_deny_non_delegated(self):
        from orchestra_core.engine import Engine, StateBusy
        self.engine.interrupt('main', self.lease)  # the run's session has ended
        # The first read (status) succeeds; the second read (autonomy_active) meets a busy lock.
        with mock.patch.object(Engine, 'autonomy_active', side_effect=StateBusy('Orchestra state is busy; retry')) as second:
            self.assertIsNone(self.hook(self.repo, 'git status'))
            self.assertIsNone(self.hook(self.repo, 'git commit -m done'))
            self.assertEqual(self.hook(self.repo, 'git reset --hard'), 'deny')  # a plain deny keeps its verdict
        self.assertTrue(second.called)

    def test_hook_stop_allows_stop_and_writes_state_busy_brief_on_lock_timeout(self):
        self.arm()
        self.hold_lock()
        progress = self.state / 'progress.md'
        before = progress.read_text() if progress.exists() else ''
        with mock.patch.object(hooks_module, 'STOP_LOCK_BUDGET', 3.0):
            started = time.monotonic()
            self.assertEqual(self.stop_main(self.repo), {})
            self.assertLess(time.monotonic() - started, 9)
        added = progress.read_text()[len(before):]
        self.assertIn('## Run brief', added)
        self.assertIn('state busy', added)
        self.assertTrue(json.loads((self.state / 'state.json').read_text())['autonomy']['active'])

    def test_hook_stop_busy_unarmed_writes_no_brief(self):
        self.hold_lock()
        progress = self.state / 'progress.md'
        before = progress.read_bytes() if progress.exists() else None
        with mock.patch.object(hooks_module, 'STOP_LOCK_BUDGET', 3.0):
            self.assertEqual(self.stop_main(self.repo), {})
        self.assertEqual(before, progress.read_bytes() if progress.exists() else None)

    def test_hook_stop_runs_when_lock_frees_within_budget(self):
        self.arm()
        self.engine.add_task('main', self.lease, dict(id='c1', role='builder', mode='implementation', inputs=['spec'],
                             acceptance=['check'], files=['c1'], resources=[], dependencies=[]))
        handle = self.hold_lock()
        timer = threading.Timer(2.5, self.release_lock, [handle])
        timer.start()
        self.addCleanup(timer.cancel)
        with mock.patch.object(hooks_module, 'STOP_LOCK_BUDGET', 8.0):
            output = self.stop_main(self.repo)
        self.assertEqual(output['decision'], 'block')
        self.assertEqual(json.loads((self.state / 'state.json').read_text())['autonomy']['passes'], 1)

    def run_hook_from_deleted_cwd(self, payload):
        """Run the hook process with a cwd that is removed before Python starts (the H1 removed-worktree case)."""
        gone = self.root / 'removed-worktree'
        gone.mkdir()
        script = PLUGIN / 'scripts/orchestra_hook.py'
        shell = 'cd "$1" && rmdir "$1" && exec "$2" "$3" PreToolUse --harness claude'
        return subprocess.run([SH, '-c', shell, 'sh', str(gone), sys.executable, str(script)],
                              input=json.dumps(payload(gone)), text=True, capture_output=True, timeout=60)

    @unittest.skipIf(os.name == 'nt', 'Windows cannot remove a process working directory')
    def test_pretooluse_deleted_process_cwd_denies_delegated(self):
        payloads = {'payload cwd removed': lambda gone, c: {'cwd': str(gone), 'tool_name': 'Bash', 'tool_input': {'command': c}},
                    'no payload cwd': lambda gone, c: {'tool_name': 'Bash', 'tool_input': {'command': c}}}
        for label, make in payloads.items():
            for command in ['git push origin side', 'rm -rf build']:
                with self.subTest(label=label, command=command):
                    result = self.run_hook_from_deleted_cwd(lambda gone: make(gone, command))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    decision = json.loads(result.stdout)['hookSpecificOutput']
                    self.assertEqual(decision['permissionDecision'], 'deny')
                    self.assertEqual(decision['permissionDecisionReason'],
                                     'Session directory no longer exists: cd to an existing directory, then retry')
            with self.subTest(label=label, command='git status'):
                result = self.run_hook_from_deleted_cwd(lambda gone: make(gone, 'git status'))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {})
        with self.subTest(label='no payload cwd', tool='Edit relative path'):
            result = self.run_hook_from_deleted_cwd(
                lambda gone: {'tool_name': 'Edit', 'tool_input': {'file_path': 'notes.txt', 'old_string': 'a', 'new_string': 'b'}})
            self.assertEqual(result.returncode, 0, result.stderr)
            decision = json.loads(result.stdout)['hookSpecificOutput']
            self.assertEqual(decision['permissionDecision'], 'deny')
            self.assertEqual(decision['permissionDecisionReason'],
                             'Session directory no longer exists: cd to an existing directory, then retry')

    def hold_lock_in_process(self, seconds):
        """Hold the state lock exclusively from another process for `seconds`."""
        self.engine.status()
        code = ('import sys, time\nsys.path.insert(0, %r)\nfrom orchestra_core import portable as fcntl\n'
                'f = open(sys.argv[1], "a+")\nfcntl.flock(f, fcntl.LOCK_EX)\n'
                'print("held", flush=True)\ntime.sleep(float(sys.argv[2]))\n') % str(PLUGIN / 'scripts')
        proc = subprocess.Popen([sys.executable, '-c', code, str(self.state / 'state.lock'), str(seconds)],
                                stdout=subprocess.PIPE, text=True)
        self.addCleanup(proc.stdout.close)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        self.assertEqual(proc.stdout.readline().strip(), 'held')
        return proc

    def add_permit(self):
        data = json.loads((self.state / 'state.json').read_text())
        data['permits'] = [dict(id='p', action='release', remote='r', target='t', argv=[], artifact={}, lease=self.lease)]
        (self.state / 'state.json').write_text(json.dumps(data))

    def hook_event(self, event, payload):
        with mock.patch('sys.stdin', io.StringIO(json.dumps(payload))), \
                mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            code = main([event, '--harness', 'claude'])
        return code, json.loads(out.getvalue())

    def test_interrupt_recorded_when_lock_busy_past_hook_wait(self):
        self.add_permit()
        self.hold_lock_in_process(5.0)
        code, output = self.hook_event('Interrupt', {'cwd': str(self.repo), 'session_id': 's-9'})
        self.assertEqual((code, output), (0, {}))
        data = json.loads((self.state / 'state.json').read_text())
        self.assertIs(data['session']['active'], False)
        self.assertEqual(data['permits'], [])
        self.assertEqual(data['last_brief']['reason'], 'interrupted')

    def test_session_end_recorded_when_lock_busy_past_hook_wait(self):
        self.engine.interrupt('main', self.lease)
        self.lease = self.engine.open_session('main', harness_session='S')
        self.add_permit()
        self.hold_lock_in_process(5.0)
        code, output = self.hook_event('SessionEnd', {'cwd': str(self.repo), 'session_id': 'S', 'reason': 'other'})
        self.assertEqual((code, output), (0, {}))
        data = json.loads((self.state / 'state.json').read_text())
        self.assertIs(data['session']['active'], False)
        self.assertEqual(data['session']['outcome'], 'ended')
        self.assertEqual(data['permits'], [])
        self.assertEqual(data['last_brief']['reason'], 'ended')


class RunEngine:
    """Fake engine adapter: an active run, optional gate receipt ids, optional failing status."""
    def __init__(self, state_path, active=True, gate_ids=None, broken=False):
        self.state_path, self.active, self.broken = state_path, active, broken
        if gate_ids is not None:
            self.current_gate_ids = lambda: list(gate_ids)

    def status(self):
        if self.broken:
            raise RuntimeError('state unreadable')
        return {'session': {'active': self.active} if self.active is not None else None}


class PlanV24GuardTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.state = self.dir / 'state.json'

    def engine(self, **kw):
        return RunEngine(self.state, **kw)

    def agent(self, subagent_type, tool='Agent', engine=None, **extra):
        data = {'prompt': 'x'}
        if subagent_type is not None:
            data['subagent_type'] = subagent_type
        payload = {'tool_name': tool, 'tool_input': data, 'cwd': str(self.dir), **extra}
        return handle_event('PreToolUse', payload, harness='claude', engine=engine)

    def review_call(self, text, agent_type, engine=None):
        payload = {'tool_name': 'Bash', 'tool_input': {'command': text}, 'cwd': str(self.dir)}
        if agent_type is not None:
            payload.update(agent_id='a1', agent_type=agent_type)
        return handle_event('PreToolUse', payload, harness='claude', engine=engine)

    def test_non_orchestra_agent_denied_during_run(self):
        for tool in ('Agent', 'Task'):
            for kind in ('general-purpose', 'Explore', 'Plan', 'claude', '', None, 7, 'orchestrator'):
                with self.subTest(tool=tool, kind=kind):
                    result = self.agent(kind, tool, self.engine())
                    self.assertEqual(decision_of(result), 'deny')
                    self.assertEqual(result.output['hookSpecificOutput']['permissionDecisionReason'],
                                     'Orchestra run active: use an orchestra:* agent (investigator-code for search, builder for edits)')

    def test_orchestra_agent_allowed_during_run(self):
        self.assertEqual(self.agent('orchestra:builder', engine=self.engine()).output, {})

    def test_non_orchestra_agent_allowed_without_active_run(self):
        self.assertEqual(self.agent('general-purpose').output, {})
        self.assertEqual(self.agent('general-purpose', engine=self.engine(active=False)).output, {})
        self.assertEqual(self.agent('general-purpose', engine=self.engine(active=None)).output, {})

    def test_agent_guard_fails_closed_on_engine_error_only_for_an_active_raw_session(self):
        broken = self.engine(broken=True)
        self.state.write_text(json.dumps({'session': {'active': True}}))
        self.assertEqual(decision_of(self.agent('general-purpose', engine=broken)), 'deny')
        self.state.write_text('{not json')
        self.assertEqual(decision_of(self.agent('general-purpose', engine=broken)), 'deny')
        self.state.write_text(json.dumps({'session': {'active': False}}))
        self.assertEqual(self.agent('general-purpose', engine=broken).output, {})
        self.assertEqual(decision_of(self.agent('general-purpose', engine=mock.Mock())), 'deny')

    def tool_in_subagent(self, agent_type, tool='Bash', engine=None):
        data = {'command': 'git add src/a.ts docs/b.md'} if tool == 'Bash' else {'file_path': str(self.dir / 'f.txt'), 'content': 'x'}
        payload = {'tool_name': tool, 'tool_input': data, 'cwd': str(self.dir), 'agent_id': 'a1'}
        if agent_type is not None:
            payload['agent_type'] = agent_type
        return handle_event('PreToolUse', payload, harness='claude', engine=engine)

    def test_non_orchestra_subagent_tools_denied_during_run(self):
        # A Workflow agent with no agentType arrives as 'workflow-subagent' (live probe, Claude Code 2.1.292)
        for kind in ('workflow-subagent', 'general-purpose', 'Explore', '', None):
            for tool in ('Bash', 'Write'):
                with self.subTest(kind=kind, tool=tool):
                    result = self.tool_in_subagent(kind, tool, self.engine())
                    self.assertEqual(decision_of(result), 'deny')
                    self.assertEqual(result.output['hookSpecificOutput']['permissionDecisionReason'],
                                     hooks_module.SUBAGENT_GUARD)

    def test_non_orchestra_subagent_denied_when_run_cannot_load(self):
        self.state.write_text(json.dumps({'session': {'active': True}}))
        self.assertEqual(decision_of(self.tool_in_subagent('workflow-subagent', engine=self.engine(broken=True))), 'deny')

    def test_orchestra_subagent_and_no_run_unaffected(self):
        self.assertEqual(self.tool_in_subagent('orchestra:builder', engine=self.engine()).output, {})
        self.assertEqual(self.tool_in_subagent('workflow-subagent').output, {})
        self.assertEqual(self.tool_in_subagent('workflow-subagent', engine=self.engine(active=False)).output, {})

    def test_non_orchestra_subagent_start_is_told_to_stop_during_run(self):
        payload = {'agent_id': 'a1', 'agent_type': 'workflow-subagent'}
        result = handle_event('SubagentStart', payload, harness='claude', engine=self.engine())
        self.assertEqual(result.output['hookSpecificOutput']['additionalContext'], hooks_module.SUBAGENT_GUARD)
        self.assertEqual(handle_event('SubagentStart', payload, harness='claude', engine=None).output, {})
        self.assertEqual(handle_event('SubagentStart', payload, harness='claude', engine=self.engine(active=False)).output, {})

    def test_subagent_agent_call_still_hits_workers_do_not_delegate(self):
        result = self.agent('orchestra:builder', engine=self.engine(), agent_id='a1', agent_type='orchestra:builder')
        self.assertIn('Workers do not delegate', result.output['hookSpecificOutput']['permissionDecisionReason'])

    def test_reviewers_cannot_rerun_suites_while_gate_receipts_exist(self):
        engine = self.engine(gate_ids=['gate-1', 'gate-2'])
        for kind in ('orchestra:code-reviewer', 'orchestra:critic'):
            for text in ('python3 -m unittest discover', 'cd x && pytest -q', 'npm test'):
                with self.subTest(kind=kind, text=text):
                    result = self.review_call(text, kind, engine)
                    self.assertEqual(decision_of(result), 'deny')
                    self.assertEqual(result.output['hookSpecificOutput']['permissionDecisionReason'],
                                     'Cite gate receipt gate-1, gate-2; reviewers do not rerun suites')

    def test_reviewer_test_block_covers_the_size_variants(self):
        engine = self.engine(gate_ids=['gate-1'])
        for kind in ('orchestra:code-reviewer-medium',):
            with self.subTest(kind=kind):
                result = self.review_call('python3 -m unittest discover', kind, engine)
                self.assertEqual(decision_of(result), 'deny')
                self.assertEqual(result.output['hookSpecificOutput']['permissionDecisionReason'],
                                 'Cite gate receipt gate-1; reviewers do not rerun suites')

    def test_suite_allowed_without_receipts_engine_or_method(self):
        for engine in (self.engine(gate_ids=[]), None, self.engine()):
            with self.subTest(engine=engine):
                self.assertEqual(self.review_call('pytest', 'orchestra:critic', engine).output, {})

    def test_other_agents_and_main_session_may_run_suites(self):
        engine = self.engine(gate_ids=['gate-1'])
        self.assertEqual(self.review_call('pytest', 'orchestra:builder', engine).output, {})
        self.assertEqual(self.review_call('pytest', None, engine).output, {})
        self.assertEqual(self.review_call('pytest', 'orchestra:codex-reviewer', engine).output, {})

    def test_targeted_probe_allowed_for_reviewers(self):
        engine = self.engine(gate_ids=['gate-1'])
        for text in ('python3 -m unittest tests.test_x.Class.test_y', 'pytest tests/test_x.py::test_y'):
            self.assertEqual(self.review_call(text, 'orchestra:code-reviewer', engine).output, {}, text)

    def test_failing_gate_listing_never_blocks_a_reviewer(self):
        engine = self.engine()
        engine.current_gate_ids = mock.Mock(side_effect=RuntimeError('x'))
        self.assertEqual(self.review_call('pytest', 'orchestra:critic', engine).output, {})


if __name__ == '__main__':
    unittest.main()
