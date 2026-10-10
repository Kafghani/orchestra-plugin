# Changelog

Release 2.0.0 is described in docs/RELEASE-NOTES-2.0.0.md.

## 2.5.1 — 2026-10-10

- **Windows fork — Portability:** `orchestra_core/portable.py` replaces `fcntl.flock` (LockFileEx), `os.killpg` (`taskkill /T`) and directory `fsync` on Windows; POSIX behavior is unchanged.
- **Windows fork — Hooks:** `run-hook.sh` forces `PYTHONUTF8=1` and finds `python`, `py` and the standard python.org install folders (the Microsoft Store stub shadows `python`).
- **Windows fork — Ledger:** `parse_ledger` accepts CRLF line endings; before, a CRLF ledger failed with "deadline must be ISO 8601".
- **Windows fork — Guards:** executable names are normalized (`git.exe`, `GIT.EXE`, `C:\...\git.exe`) in `guards.py` and `guard.ts`, so Windows spellings of denied commands are denied too. Six corpus cases cover it.
- **Windows fork — Manifest:** `hooks/mods.json` carries an empty `hooks` object so Claude Code 2.1.224, which requires the key, loads the plugin.
- **Windows fork — Tests:** the suite runs on Windows; the deleted-working-directory and relaunch-signal tests are skipped there. Run with `PYTHONUTF8=1`.
- **Engine:** a run state whose session carries `size` never loads under the 2.3 policy hash. Before, `binds()` refused only a session with `items`. The two task-size checks share one constant, `CARD_SIZES`.
- **Examples:** `examples/global-CLAUDE.md` (a user-level `~/.claude/CLAUDE.md` that routes through Orchestra) and `examples/project-AGENTS.md` (a project charter whose standing orders Orchestra pastes into every brief).

## 2.5.0 — 2026-10-09

Route by diff size instead of item count. The design is `docs/DESIGN-v2.5.md` (owner decisions D1 to D5), the contract is `docs/PLAN-v2.5.md` section 2.

- **Size tiers (D1):** `start --size tiny|medium [--asks N]` is required for a new run. Tiny is up to 50 changed lines (inline edit, no alignment; a tiny builder card needs `dispatch --helper REASON`), medium up to 400 (grill inline, then every unit inline in sequence; the medium benchmark showed a worker's fixed cost exceeds a medium unit's inline time). Large runs 2+ units through Workflow builders, and the coordinator starts its own inline card in the same turn. `--asks` counts separately stated asks; the tier is the largest ask and the budget is the guide times the count.
- **Large only by escalation:** `route --size large --reason TEXT`, or `start --size large --owner-request` when the owner asks for a map. A designer-planner plan card needs a large run or an owner request.
- **Size check (D2):** the new read-only `prepr` command compares the diff with the budget and prints a warning; it never blocks.
- **Reviewer by summed diff (D3):** `prepr` names the pre-PR reviewer: Sonnet 5.5 (`code-reviewer-medium`) up to 400 changed lines, one card with `Lens: combined`; Opus 5.5 with one card per lens above 400.
- **Wayfinder (D4, D5):** `references/wayfinder.md` maps large work as decision tickets in `docs/maps/<name>.md`; research tickets run together as investigator cards. Derived from mattpocock/skills at 49dd158d1076 (third pin, credited).
- **Engine gaps:** `gate --timeout SECONDS` overrides the policy timeout for one run. A reported card takes a replacement report from the same worker until accept or a review covers it, so a wrong report no longer needs park and unpark. A builder report needs a nonempty `ARTIFACT:` line, so a report cannot be accepted with no commit named.
- **Upgrade:** a 2.4 run loads under 2.5 and keeps item routing; `start --items` is refused (README, Upgrade from 2.4 to 2.5).

## 2.4.0 — 2026-10-08

Inline-first routing, builder self-review and one review before the PR. The decisions are `docs/PLAN-v2.4.md` section 1 (S1–S11), the contract is section 2.

- **Model matrix (S1, S2):** Haiku 5.5 high for mechanical and cleanup builders, operator and code discovery; Opus 5.5 only for critic (high), final reviewer and builder repair (medium).
- **Routing (S3, S11):** `start --items N` is required for a new run; 1 to 5 items run inline (`dispatch --helper REASON` for a helper builder), 6 or more go through a designer-planner plan card and Workflow builders. `route` changes the route mid-run.
- **Self-review (S6):** a builder report carries one `SELF_REVIEW:` JSON line with its checks and criteria; the engine accepts a builder card on it while the artifact is current.
- **One review before the PR (S4, S5, S7):** checkpoint review, waves, gates between waves, `supersede` and the `code-reviewer-checkpoint` agent are removed. Only the pre-PR review and one fix re-review are recorded; a chain still blocked after that is held. Lenses come from the diff: security on `sensitive_paths`, standards above `standards_min_lines`.
- **Guards (S9, S10):** during a run the main session may start only `orchestra:*` agents (denied also when the run state cannot be loaded), and shell, edit and agent calls from any other agent, including agents a Workflow starts, are denied (file reads are not guarded). Reviewers and critics cite a current gate receipt instead of rerunning a test suite.
- **Upgrade:** a 2.3 run loads under 2.4 with 2.3 routing; its gate and review receipts go stale (README, Upgrade from 2.3 to 2.4).

## 2.3.0 — 2026-10-06

Four small items folded from mattpocock/skills at 2b47ffcf2385 (second pin; credited in `plugins/orchestra/THIRD-PARTY-NOTICES`).

- **Strategic track:** the coordinator works a tactical track (finish the task) and a strategic track (change the environment so the next task goes better: a lint rule, a constrained API, a standards file or a check, not more instructions). `coordination.md`, section Two tracks.
- **No workarounds:** a deviation from project convention is fixed, as its own card, before feature work builds on it.
- **Bug-lane retro:** after an accepted repair, name the missing check or seam that would have caught the bug and route adding it.
- **Handoff directory:** `handoff.md` names the temporary directory: `$TMPDIR`, else `/tmp` (`%TEMP%` on Windows).

## 2.2.0 — 2026-10-05

The full change set is `docs/SPEC-v2.2.md` section 5; each item below names its section.

- **Wave review and repair-diff check (5.1):** one checkpoint review per wave over its reported tickets; a repair is checked against its own diff before the chain tip is accepted (`repair_check`, `supersede`, wave labels in `status`).
- **Repair ladder ending in hold (5.2, 5.3):** a builder gets one repair; a chain still blocked after it is held (`hold`), its work stays in place, the held log records it and the run continues. Held dependencies count as satisfied.
- **Gates between waves (5.4, 5.11):** gate receipts are recorded once and reused; a repeated gate needs `gate --again`; boundary gate argv is refused.
- **Final phase (5.5):** three parallel lenses (correctness and security on Opus 5.5 high, standards on the new Sonnet 5.5 medium `code-reviewer-standards` variant). Final receipts attribute findings to chain tips and must address every held tip. The final repair loop has no round cap.
- **Materiality (5.6):** review reports separate blocking `findings` from `issues`; work with no real impact, or under about 20% impact on otherwise-correct work, is a note, never a failure.
- **Out-of-scope triage and findings ledger (5.7, 5.12):** out-of-scope defects never change a verdict; they are triaged inline, as a card or in the brief.
- **Autonomy without caps (5.8):** the deadline is the only limit; `max_passes` and `max_stalls` from 2.1 ledgers are recorded but not enforced. Stalls are detected by signature. The status band reads "pass N". A ledger `Release:` line pre-authorizes one exact remote and target pair.
- **Run brief (5.9):** every end path appends one `## Run brief` to `progress.md`; `brief` prints it.
- **Relaunch harness (5.10):** `orchestra.py relaunch --permission-mode MODE [--model ID] [--launcher ARGV...]` runs fresh-context passes until `complete`, `deadline` or a stop, with `settle` before each pass and a pass session nonce. A signal disarms autonomy without taking the state lock in the handler.
- **Briefs carry exact keep and remove lists (5.13).**
- **Guard (5.14, 5.15, 5.16):** forced deletion of a branch that is provably merged into the default branch is allowed (local and remote; the remote push URL must equal its fetch URL; default refs and the branch name are matched exactly, case included). Raw ref deletion through `git update-ref` is denied. Abbreviated long options are read as git reads them; `commit --amend` is denied. Hook state reads wait at most 2 s; a busy lock or a removed session directory denies only the delegated classes, with a reason. The mod's fail-closed message names its failure class, and `delegate` spawns from the plugin root. The chained-command failure reproduced at the mod seam (missing session directory); the fix ships here.
- **Engine (5.17):** read-only reviews no longer collide with the cards they review.
- **Mixed versions on one active run (section 8):** a 2.1 engine reading 2.2 state rejects any `held` card and an armed autonomy without `max_passes`, and the 2.1 hooks then fail closed for that run. End every 2.1 session before the first `hold` or before arming autonomy under 2.2.

## 2.1.0 — 2026-10-05

- Claude-native only. Removed the Codex package (`plugins/orchestra-codex`), `.agents`, the Codex manifest and hook file, the generated worker profiles, `install-profiles` and `uninstall-profiles`, and every Codex path in the engine, hooks and generator. `config/models.json` keeps only the claude profile. Claude roles, models and efforts are unchanged; `agents/*.md` are byte-identical to 2.0.1.
- Stricter Git guard, in both the Python guard and the TypeScript mod, kept in parity by the shared corpus: every `git stash` form is denied (including `list` and `show`); wholesale `git add` is denied (`-A`, `-u`, `--all`, `--update`, `--no-ignore-removal`, short clusters with `A` or `u`, and the pathspecs `.`, `./`, `..`, `../`, `:/`, `:/.` and `*`); `git commit -a`, `--all` and clusters with `a` are denied. Commit messages that merely mention these words stay allowed.
- Docs and skill references rewritten for Claude only. Historical records are unchanged.

## 2.0.1 — 2026-10-04

- Claude `PreToolUse` matcher now includes `Agent` and `Task` (`Bash|Edit|Write|MultiEdit|Agent|Task`), so workers cannot delegate in Claude Code. This supersedes the 2.0.0 note that the matcher covered only `Bash|Edit|Write|MultiEdit`.
- Test: `_MOD_TOOLS` in `orchestra_core/hooks.py` must equal `GUARDED` in `hooks/mod/orchestra.ts`, so the two lists cannot drift apart.
