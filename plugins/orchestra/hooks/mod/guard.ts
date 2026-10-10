// TypeScript port of the bounded shell guard in scripts/orchestra_core/guards.py (SPEC 10.3, A5, A8).
//
// The rules table (config/guard-rules.json) and the corpus (config/guard-corpus.json) are shared with
// Python; the corpus is the parity contract. This file holds ALL classifier logic: the guard digest
// covers guard-rules.json, guards.py, hooks.py and this file, so a change here invalidates the marker.
//
// Pure code only: the engine's validator never follows `$` across an import. Not an interpreter, alias
// or hostile-worker sandbox. Known limit: edit protection compares lexical paths (symlinks are not
// resolved here; Python resolves them).

export class ValueError extends Error {}

export type Decision = {
  action: string;
  reason: string;
  category: string;
  remote: string | null;
  target: string | null;
  argv: string[];
  source: string | null;
  boundary: string | null;
  kind: string | null; // category merged-delete only: 'local' or 'remote' (SPEC 5.14).
  branch: string | null; // category merged-delete only: the one branch the command deletes.
};

type Rules = {
  shells: string[];
  shell_value_flags: string[];
  wrappers: Record<string, string[]>;
  tools: { shell: string[]; edit: string[] };
  runners: {
    attached_value_flags: Record<string, string[]>;
    watch_exec_flags: string[];
    flock_command_flags: string[];
    find_exec_actions: string[];
  };
  git: Record<string, string[]>;
  release: {
    gh: string[][];
    az_requires: string[];
    az_pr_update: { prefix: string[]; word: string };
    package_tools: string[];
    package_verb: string;
    deploy_tools: string[];
    deploy_words: string[];
  };
  boundary: { delete_commands: string[]; find_delete_flag: string; gh: string[][] };
  protected: { harness_dirs: string[]; files: string[]; agents_prefixes: string[]; component: string; state_root_exceptions: string[] };
};

const MULTI = 'releasemulti';

let SHELLS = new Set<string>();
let SHELL_VALUE_FLAGS = new Set<string>();
let WRAPPER_VALUES = new Map<string, Set<string>>();
let GIT: Record<string, Set<string>> = {};
let LONG_GUARDED: Record<string, string[]> = {};
let LONG_VALUE: Record<string, Set<string>> = {};
let RELEASE: Rules['release'];
let BOUNDARY: Rules['boundary'];
let ATTACHED = new Map<string, Set<string>>();
let EXEC_FLAGS = new Set<string>();
let COMMAND_FLAGS = new Set<string>();
let FIND_EXEC = new Set<string>();
let PROTECTED: Rules['protected'];
let SHELL_TOOLS: string[] = [];
let EDIT_TOOLS: string[] = [];

function strings(value: unknown, what: string): string[] {
  if (!Array.isArray(value) || value.some((x) => (x as unknown) !== String(x) || (typeof x) !== 'string')) throw new ValueError('Invalid guard rules: ' + what);
  return value as string[];
}

/** Install the rules table from the JSON text of config/guard-rules.json. Throws when it is malformed. */
export function loadRules(json: string): void {
  const raw = JSON.parse(json) as Partial<Rules>;
  const need = <T>(value: T | undefined, what: string): T => {
    if (value === undefined || value === null) throw new ValueError('Invalid guard rules: ' + what);
    return value;
  };
  const wrappers = need(raw.wrappers, 'wrappers');
  const runners = need(raw.runners, 'runners');
  const git = need(raw.git, 'git');
  const release = need(raw.release, 'release');
  const boundary = need(raw.boundary, 'boundary');
  const prot = need(raw.protected, 'protected');
  const tools = need(raw.tools, 'tools');
  const shells = new Set(strings(raw.shells, 'shells'));
  const shellFlags = new Set(strings(raw.shell_value_flags, 'shell_value_flags'));
  const wrapperMap = new Map<string, Set<string>>();
  for (const key of Object.keys(wrappers)) wrapperMap.set(key, new Set(strings(wrappers[key], 'wrappers.' + key)));
  const attached = new Map<string, Set<string>>();
  for (const key of Object.keys(need(runners.attached_value_flags, 'runners.attached'))) attached.set(key, new Set(strings(runners.attached_value_flags[key], 'attached')));
  const gitSets: Record<string, Set<string>> = {};
  for (const key of Object.keys(git)) gitSets[key] = new Set(strings(git[key], 'git.' + key));
  for (const key of ['global_value_options', 'clean_value_options', 'push_value_options', 'commit_value_options', 'wholesale_add_flags', 'wholesale_add_pathspecs', 'push_multi_flags', 'switch_force_flags', 'worktree_delete', 'boundary_merge_verbs', 'commit_guarded_flags']) need(gitSets[key], 'git.' + key);
  // SPEC 5.15: per verb, the guarded long options, most restrictive first. An exemption (clean --dry-run, restore --staged) is absent: it counts only in full.
  const longGuarded: Record<string, string[]> = {
    add: git.wholesale_add_flags!,
    reset: ['--hard'],
    clean: ['--force'],
    branch: ['--delete', '--force'],
    checkout: ['--force'],
    switch: git.switch_force_flags!,
    restore: ['--force', '--worktree'],
    push: ['--force', '--force-with-lease', '--force-if-includes', '--mirror', ...git.push_multi_flags!],
    commit: ['--all', ...git.commit_guarded_flags!],
    tag: ['--delete'],
  };
  strings(release.az_requires, 'release.az_requires');
  strings(release.package_tools, 'release.package_tools');
  strings(release.deploy_tools, 'release.deploy_tools');
  strings(release.deploy_words, 'release.deploy_words');
  strings(release.az_pr_update.prefix, 'release.az_pr_update');
  strings(boundary.delete_commands, 'boundary.delete_commands');
  strings(prot.harness_dirs, 'protected.harness_dirs');
  strings(prot.files, 'protected.files');
  strings(prot.agents_prefixes, 'protected.agents_prefixes');
  strings(prot.state_root_exceptions, 'protected.state_root_exceptions');
  const shellTools = strings(tools.shell, 'tools.shell');
  const editTools = strings(tools.edit, 'tools.edit');
  const execFlags = new Set(strings(runners.watch_exec_flags, 'runners.watch_exec_flags'));
  const commandFlags = new Set(strings(runners.flock_command_flags, 'runners.flock_command_flags'));
  const findExec = new Set(strings(runners.find_exec_actions, 'runners.find_exec_actions'));
  SHELLS = shells;
  SHELL_VALUE_FLAGS = shellFlags;
  WRAPPER_VALUES = wrapperMap;
  ATTACHED = attached;
  GIT = gitSets;
  LONG_GUARDED = longGuarded;
  LONG_VALUE = { clean: gitSets.clean_value_options!, push: gitSets.push_value_options!, commit: gitSets.commit_value_options! };
  RELEASE = release;
  BOUNDARY = boundary;
  PROTECTED = prot;
  SHELL_TOOLS = shellTools;
  EDIT_TOOLS = editTools;
  EXEC_FLAGS = execFlags;
  COMMAND_FLAGS = commandFlags;
  FIND_EXEC = findExec;
}

export function shellTools(): string[] {
  return SHELL_TOOLS;
}

export function editTools(): string[] {
  return EDIT_TOOLS;
}

// ---------------------------------------------------------------------------------------------
// Python string semantics the classifier depends on.

const PY_WS = '\\t-\\r\\x1c-\\x20\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000';
const STRIP_RE = new RegExp('^[' + PY_WS + ']+|[' + PY_WS + ']+$', 'g');
const WS_OR_END_RE = new RegExp('^(?:[' + PY_WS + ']|$)');
const DIGITS_RE = /^[\p{Nd}²³¹⁰⁴-⁹₀-₉①-⑨⑴-⑼⒈-⒐⓪⓵-⓽⓿❶-❾➀-➈➊-➒]+$/u;

function strip(text: string): string {
  return text.replace(STRIP_RE, '');
}

function isDigit(text: string): boolean {
  return DIGITS_RE.test(text);
}

function posixName(path: string): string {
  const parts = path.replace(/\\/g, '/').split('/').filter((p) => p !== '' && p !== '.');
  const name = parts.length ? parts[parts.length - 1]! : '';
  // Windows spellings (`C:\...\git.exe`, `GIT.EXE`) judge like the bare lowercase name; keep in step with guards.py _exe_name.
  const bare = name.replace(/\.(?:exe|cmd|bat|com)$/i, '');
  return bare !== name ? bare.toLowerCase() : name;
}

function quote(text: string): string {
  if (text === '') return "''";
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(text)) return text;
  return "'" + text.split("'").join('\'"\'"\'') + "'";
}

/** Python's shlex.split: posix mode, whitespace_split, `#` comments only when asked. */
export function shlexSplit(s: string, comments: boolean): string[] {
  const out: string[] = [];
  const n = s.length;
  let i = 0;
  const WS = ' \t\r\n';
  for (;;) {
    let state: string = ' ';
    let token = '';
    let quoted = false;
    let escapedState = '';
    for (;;) {
      const ch = i < n ? s[i++]! : '';
      if (state === ' ') {
        if (ch === '') break;
        if (WS.includes(ch)) {
          if (token !== '' || quoted) break;
          continue;
        }
        if (comments && ch === '#') {
          const end = s.indexOf('\n', i);
          i = end < 0 ? n : end + 1;
          continue;
        }
        if (ch === '\\') {
          escapedState = 'a';
          state = ch;
        } else if (ch === '"' || ch === "'") {
          state = ch;
        } else {
          token = ch;
          state = 'a';
        }
      } else if (state === '"' || state === "'") {
        quoted = true;
        if (ch === '') throw new ValueError('No closing quotation');
        if (ch === state) state = 'a';
        else if (ch === '\\' && state === '"') {
          escapedState = state;
          state = ch;
        } else token += ch;
      } else if (state === '\\') {
        if (ch === '') throw new ValueError('No escaped character');
        // Inside double quotes a backslash before `$`, a backtick, `"` or a backslash is removed, and a
        // backslash-newline pair is deleted, as in bash (O34); before any other character it stays.
        if (escapedState === '"' && ch === '\n') {
          state = escapedState;
          continue;
        }
        if (escapedState === '"' && !'$`"\\'.includes(ch)) token += state;
        token += ch;
        state = escapedState;
      } else {
        if (ch === '') break;
        if (WS.includes(ch)) {
          state = ' ';
          if (token !== '' || quoted) break;
          continue;
        }
        if (ch === '"' || ch === "'") state = ch; // A mid-word `#` is literal (SPEC A5, O27 and O33).
        else if (ch === '\\') {
          escapedState = 'a';
          state = ch;
        } else token += ch;
      }
    }
    if (!quoted && token === '') return out;
    out.push(token);
  }
}

// ---------------------------------------------------------------------------------------------

function dec(action = 'allow', reason = '', category = '', extra: Partial<Decision> = {}): Decision {
  return { action, reason, category, remote: null, target: null, argv: [], source: null, boundary: null, kind: null, branch: null, ...extra };
}

function denyOf(reason: string, category = 'destructiveGit'): Decision {
  return dec('deny', reason, category);
}

/** The SPEC 5.1 class: allow, deny, release, release-multi or boundary. */
export function klassOf(d: Decision): string {
  if (d.boundary) return 'boundary';
  if (d.category === MULTI) return 'release-multi';
  return d.action;
}

type Piece = [string, string];

function split(command: string): Piece[] {
  // Split operators only outside quotes; quoted messages remain ordinary arguments.
  const out: Piece[] = [];
  let start = 0;
  let q: string | null = null;
  let escaped = false;
  for (let i = 0; i < command.length; i++) {
    const char = command[i]!;
    if (escaped) {
      escaped = false;
    } else if (char === '\\' && q !== "'") {
      escaped = true;
    } else if (q) {
      if (char === q) q = null;
    } else if (char === '"' || char === "'") {
      q = char;
    } else if (char === '&' && ((i > 0 && '<>'.includes(command[i - 1]!)) || command.slice(i + 1, i + 2) === '>')) {
      continue;
    } else if (char === '|' && i > 0 && command[i - 1] === '>') {
      continue;
    } else if (';|&()\n'.includes(char)) {
      out.push([command.slice(start, i), char]);
      start = i + 1;
    }
  }
  out.push([command.slice(start), '']);
  return out;
}

function segments(command: string): string[] {
  return split(command).map((p) => p[0]);
}

function pipelines(command: string): string[][] {
  const parts = split(command);
  const out: string[][] = [];
  let current: string[] = [];
  let k = 0;
  while (k < parts.length) {
    const [segment, op] = parts[k]!;
    if (strip(segment)) current.push(segment);
    let join = false;
    if (op === '|' && k + 1 < parts.length) {
      const [following, followingOp] = parts[k + 1]!;
      if (strip(following)) join = true;
      else if (followingOp === '&' || followingOp === '\n') {
        join = true;
        k += 1;
      }
    }
    if (!join && current.length) {
      out.push(current);
      current = [];
    }
    k += 1;
  }
  if (current.length) out.push(current);
  return out;
}

const MARK = '';
const MARK_RE = /<<[0-9]+/g;
const REDIRECT_RE = /^(?:(?:[0-9]*|\{[A-Za-z_][A-Za-z0-9_]*\})(?:<<<|>&|<&|>>|>\||<>|>|<)|&>>?)([^\n]*)$/;
const RMARK = ''; // Private-use mark markRedirects puts before each unquoted redirection operator.
const REDIRECT_WORD_RE = /^(?:[0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\})?(?:<<<|<<-?|<>|<&|<|>>|>&|>\||>|&>>?)/;
const REDIRECT_OP_RE = /<<<|<<-?|<>|<&|<|>>|>&|>\||>|&>>?/y;
const FD_WORD_RE = /^(?:[0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\})$/;
const SHLEX_BLANK = ' \t\r\n';
const HEREDOC_RE = /<<(-?)[ \t]*("[^"\n]*"|'[^'\n]*'|\\?[A-Za-z_0-9][A-Za-z_0-9.\-]*)/y;

/** HEREDOC_RE matched at text[i], or null. */
function heredocAt(text: string, i: number): RegExpExecArray | null {
  HEREDOC_RE.lastIndex = i;
  return HEREDOC_RE.exec(text);
}
const ASSIGNMENT_RE = /^[A-Za-z_][A-Za-z0-9_]*=[^\n]*$/;

type Doc = [string, boolean];

const WORD_START = ' \t\n;&|()<>'; // A `#` right after one of these (or at the start) begins a comment.
const COMMENT_BLANK = /['"\\]/g;
const KEYWORD_STOP = ' \t\n;&|()<>"\'\\$`#'; // Characters that cannot begin a bare word (case-keyword tracking, O27).
const BARE_WORD_RE = /[^ \t\n;&|()<>"'\\$`]*/y;
const WORD_GLUE = new Set(['"', "'", '\\', '$', '`']); // A bare word glued to one of these is not a keyword.

/** True when the character at i follows an odd run of backslashes: it is escaped, so it is no word start. */
function backslashed(text: string, i: number): boolean {
  let j = i;
  while (j > 0 && text[j - 1] === '\\') j -= 1;
  return (i - j) % 2 === 1;
}

function stripHeredocs(command: string): [string, Doc[]] {
  const out: string[] = [];
  const docs: Doc[] = [];
  let pending: [string, boolean, boolean][] = [];
  let q: string | null = null;
  let escaped = false;
  let i = 0;
  const n = command.length;
  let tick = false; // Inside a backtick substitution.
  const parens: [string, number][] = []; // Open `(` as [kind, index].
  let noStart = -1; // The index where a `#` cannot start a word.
  const cases: [string, number][] = []; // Open `case` as [state, parens.length] (SPEC A5, O27).
  let start = true; // At a command position.
  const caseTop = (): [string, number] | null => {
    const top = cases[cases.length - 1];
    return top !== undefined && top[1] === parens.length ? top : null;
  };
  while (i < n) {
    const char = command[i]!;
    if (escaped) {
      escaped = false;
      // SPEC A5 (O27): a character after an unescaped backslash is not a word start. A backslash-newline
      // pair is deleted, so the character after it is a word start exactly when the backslash was one.
      const glued = char !== '\n' || i - 1 === noStart || (i > 1 && !WORD_START.includes(command[i - 2]!));
      noStart = glued ? i + 1 : -1;
      start = start && !glued;
    } else if (char === '\\' && q !== "'") {
      escaped = true;
    } else if (q) {
      if (char === q) q = null;
    } else if (char === '"' || char === "'") {
      q = char;
      start = false;
    } else if (char === '(') {
      const top = caseTop();
      if (!(top && top[0] === 'pattern')) {
        // In a case pattern the opening parenthesis is optional.
        const prev = i > 0 ? command[i - 1]! : '';
        const last = parens[parens.length - 1];
        const sub = i > 0 && ('$<>='.includes(prev) || (prev === '(' && last !== undefined && last[0] === 'sub' && last[1] === i - 1));
        parens.push([sub ? 'sub' : 'plain', i]); // `=(` opens an array assignment, inside a word.
      }
      start = true;
    } else if (char === ')') {
      const top = caseTop();
      if (top && top[0] === 'pattern') {
        top[0] = 'body'; // The `)` of a case pattern closes no group, so it cannot pop an enclosing `$(`.
      } else {
        const popped = parens.pop();
        if (popped && popped[0] === 'sub') noStart = i + 1; // The `)` of `$(`, `$((`, `<(` or `a=(` ends part of a word, not a command.
      }
      start = true;
    } else if (char === '`') {
      tick = !tick;
      start = tick;
    } else if (char === ';' || char === '&' || char === '|') {
      const top = caseTop();
      if (top && top[0] === 'body' && (command.startsWith(';;', i) || command.startsWith(';&', i))) top[0] = 'pattern';
      start = true;
    } else if (char === '#' && i !== noStart && (i === 0 || WORD_START.includes(command[i - 1]!) || (tick && command[i - 1] === '`'))) {
      // SPEC A5 (O27): a comment runs to the newline. Its quotes and backslashes are literal, so they
      // are blanked: no later scanner can read them as opening a quote or escaping the newline.
      // Inside a backtick substitution it ends at the closing backtick, which stays visible.
      const found = command.indexOf('\n', i);
      let end = found < 0 ? n : found;
      if (tick) {
        let stop = i;
        while (stop < end && (command[stop] !== '`' || backslashed(command, stop))) stop += 1;
        end = stop;
      }
      out.push(command.slice(i, end).replace(COMMENT_BLANK, ' '));
      i = end;
      continue;
    } else if (char === '<' && command.startsWith('<<', i) && !command.startsWith('<<<', i) && (i === 0 || command[i - 1] !== '<')) {
      HEREDOC_RE.lastIndex = i;
      const match = HEREDOC_RE.exec(command);
      // An all-digit word is shell arithmetic (1 << 2), not a heredoc.
      if (match && !isDigit(match[2]!)) {
        let word = match[2]!;
        const quoted = '\'"\\'.includes(word[0]!);
        word = '\'"'.includes(word[0]!) ? word.slice(1, -1) : word.startsWith('\\') ? word.slice(1) : word;
        pending.push([word, match[1] === '-', quoted]);
        out.push('<<' + MARK + String(docs.length + pending.length - 1) + MARK);
        i = match.index + match[0].length;
        continue;
      }
    } else if (!KEYWORD_STOP.includes(char) && i !== noStart && (i === 0 || WORD_START.includes(command[i - 1]!))) {
      BARE_WORD_RE.lastIndex = i;
      BARE_WORD_RE.exec(command);
      const end = BARE_WORD_RE.lastIndex;
      const word = WORD_GLUE.has(command.slice(end, end + 1)) ? '' : command.slice(i, end);
      const top = caseTop();
      if (word === 'in' && top && top[0] === 'head') top[0] = 'pattern';
      else if (word === 'case' && start) cases.push(['head', parens.length]);
      else if (word === 'esac' && start && top && top[0] !== 'head') cases.pop();
      start = CASE_PREV.has(word);
      out.push(command.slice(i, end));
      i = end;
      continue;
    } else if (char === '\n') {
      out.push(char);
      i += 1;
      start = true;
      for (const [word, stripTabs, quoted] of pending) {
        const body: string[] = [];
        let found = false;
        while (i < n) {
          const end = command.indexOf('\n', i);
          const line = command.slice(i, end >= 0 ? end : n);
          i = end >= 0 ? end + 1 : n;
          if ((stripTabs ? line.replace(/^\t+/, '') : line) === word) {
            found = true;
            break;
          }
          body.push(line);
        }
        if (!found) throw new ValueError('Heredoc has no terminator');
        docs.push([body.join('\n'), quoted]);
      }
      pending = [];
      continue;
    } else if (char !== ' ' && char !== '\t') {
      start = false;
    }
    out.push(char);
    i += 1;
  }
  if (pending.length) throw new ValueError('Heredoc has no terminator');
  return [out.join(''), docs];
}

type Found = { exec: boolean; command: string | null };

function eatOptions(wrapper: string, wordsIn: string[]): [string[], Found] {
  let words = wordsIn;
  const found: Found = { exec: false, command: null };
  const values = WRAPPER_VALUES.get(wrapper)!;
  const attached = ATTACHED.get(wrapper) ?? new Set<string>();
  while (words.length && (words[0]!.startsWith('-') || ASSIGNMENT_RE.test(words[0]!))) {
    const option = words.shift()!;
    if (option === '--') break;
    let value: string | null = null;
    let valueOption = option;
    if (option.startsWith('--') && option.includes('=')) {
      const at = option.indexOf('=');
      valueOption = option.slice(0, at);
      value = option.slice(at + 1);
    } else if (option.startsWith('-') && !option.startsWith('--')) {
      // A value-taking short flag ends the cluster; its suffix is its value.
      for (let i = 1; i < option.length; i++) {
        const char = option[i]!;
        if (attached.has('-' + char)) break;
        if (values.has('-' + char)) {
          valueOption = '-' + char;
          value = option.slice(i + 1) || null;
          break;
        }
        if (wrapper === 'watch' && EXEC_FLAGS.has('-' + char)) found.exec = true;
      }
    }
    if (wrapper === 'watch' && EXEC_FLAGS.has(option)) found.exec = true;
    if (values.has(valueOption)) {
      if (value === null) {
        if (!words.length) throw new ValueError('Missing wrapper option value');
        value = words.shift()!;
      }
      if (wrapper === 'env' && (valueOption === '-S' || valueOption === '--split-string')) {
        words = shlexSplit(value, false).concat(words);
        break;
      }
      if (wrapper === 'flock' && COMMAND_FLAGS.has(valueOption)) found.command = value;
    }
  }
  return [words, found];
}

const RESERVED = new Set(['{', '}', '!', 'if', 'then', 'elif', 'else', 'fi', 'while', 'until', 'do', 'done', 'esac']);

function unwrap(wordsIn: string[]): string[] {
  let words = wordsIn;
  while (words.length) {
    const name = posixName(words[0]!);
    const redirect = REDIRECT_RE.exec(words[0]!);
    if (words[0] === 'case') return [];
    if (words[0] === 'function' && words.length > 1) {
      // `function NAME [()] {`: the name is not a command (SPEC A5, O20).
      words = words.slice(2);
      if (words.length && words[0] === '()') words = words.slice(1);
    } else if (words[0] === 'coproc') {
      // `coproc [NAME] {` or `coproc COMMAND` (SPEC A5, O20).
      words = words.slice(1);
      if (words.length > 1 && words[1] === '{') words = words.slice(1);
    } else if (RESERVED.has(words[0]!)) {
      words = words.slice(1);
    } else if (redirect) {
      words = redirect[1] ? words.slice(1) : words.slice(2);
    } else if (ASSIGNMENT_RE.test(words[0]!)) {
      words = words.slice(1);
    } else if (WRAPPER_VALUES.has(name)) {
      const wrapper = name;
      let found: Found;
      [words, found] = eatOptions(wrapper, words.slice(1));
      if (wrapper === 'timeout' && words.length) {
        words.shift();
      } else if (wrapper === 'watch' && !found.exec && words.length) {
        words = ['sh', '-c', words.join(' ')];
      } else if (wrapper === 'flock') {
        if (found.command === null && words.length) [words, found] = eatOptions(wrapper, words.slice(1));
        if (found.command !== null) words = ['sh', '-c', found.command];
      }
    } else {
      return words;
    }
  }
  return words;
}

function shellPayloadRest(words: string[]): [string, string[]] | null {
  let i = 1;
  while (i < words.length) {
    const token = words[i]!;
    if (token === '--' || !(token.startsWith('-') || token.startsWith('+'))) return null;
    if (SHELL_VALUE_FLAGS.has(token)) {
      i += 2;
      continue;
    }
    if (/^-[A-Za-z]+$/.test(token) && token.slice(1).includes('c')) {
      return i + 1 < words.length ? [words[i + 1]!, words.slice(i + 2)] : ['', []];
    }
    i += 1;
  }
  return null;
}

function shellPayload(words: string[]): string | null {
  const found = shellPayloadRest(words);
  return found ? found[0] : null;
}

function boundaryOf(kind: string, reason: string): Decision {
  return dec('allow', reason, 'boundary', { boundary: kind });
}

/** The guarded long option of `verb` that `token` abbreviates (its part before `=` is a non-empty strict prefix of it; the first match wins), else null. */
export function longPrefix(verb: string, token: string, guarded: string[]): string | null {
  const name = token.split('=')[0]!;
  if (!Object.prototype.hasOwnProperty.call(LONG_GUARDED, verb) || name.length < 3 || !name.startsWith('--')) return null;
  return guarded.find((option) => name.length < option.length && option.startsWith(name)) ?? null;
}

/** Words a value option takes: 2 for a detached value, 1 for an abbreviated long option with its value attached, else 0. */
function valueWidth(token: string, valueOptions: Set<string>): number {
  if (valueOptions.has(token)) return 2;
  const name = token.split('=')[0]!;
  if (name.length > 2 && name.startsWith('--') && [...valueOptions].some((x) => name.length < x.length && x.startsWith(name))) return token.includes('=') ? 1 : 2;
  return 0;
}

/** The options of a guarded verb with value options and their values dropped and abbreviated guarded options spelled in full. */
function readLongOptions(verb: string, options: string[]): string[] {
  const read: string[] = [];
  const valueOptions = LONG_VALUE[verb] ?? new Set<string>();
  let i = 0;
  while (i < options.length) {
    const full = longPrefix(verb, options[i]!, LONG_GUARDED[verb]!);
    const width = full ? 0 : valueWidth(options[i]!, valueOptions);
    if (width) {
      i += width;
      continue;
    }
    read.push(full ?? options[i]!);
    i += 1;
  }
  return read;
}

const MERGED = 'merged-delete';
const BRANCH_NAME = /^[A-Za-z0-9_][A-Za-z0-9._/+-]*$/;
const REMOTE_NAME = /^[A-Za-z0-9_][A-Za-z0-9._-]*$/;
const PLAIN_REASON = 'Branch deletion must run plainly in the session repository';
const SEPARATE_REASON = 'Execute branch deletions separately';

/** SPEC 5.14 item 1: the exact merged-delete shapes, else null. `options` is what precedes `--` with abbreviated
 * long options spelled in full (5.15). A shape has one branch positional and no other option. */
function mergedDelete(verb: string, options: string[], allFlags: string[], short: string, words: string[], redirected: boolean, raw: string[]): Decision | null {
  if (raw.length !== options.length) return null; // A value option and its value were read away: not a bare delete.
  const positional = options.filter((x) => !x.startsWith('-'));
  const shorts = new Set(short);
  const flags = new Set(allFlags.filter((x) => x.startsWith('--')));
  let remote: string | null;
  let branch: string;
  let kind: string;
  if (verb === 'branch') {
    if (![...flags].every((x) => x === '--delete' || x === '--force') || ![...shorts].every((x) => 'Ddf'.includes(x)) || positional.length !== 1) return null;
    if (!((shorts.has('D') || shorts.has('d') || flags.has('--delete')) && (shorts.has('D') || shorts.has('f') || flags.has('--force')))) return null;
    remote = null;
    branch = positional[0]!;
    kind = 'local';
  } else if (verb === 'push') {
    const longOnly = flags.size === 1 && flags.has('--delete');
    const shortOnly = flags.size === 0 && shorts.size === 1 && shorts.has('d');
    if (!(longOnly || shortOnly) || [...shorts].some((x) => x !== 'd') || positional.length !== 2) return null;
    remote = positional[0]!;
    branch = positional[1]!;
    kind = 'remote';
    if (!REMOTE_NAME.test(remote)) return null;
  } else return null;
  if (!BRANCH_NAME.test(branch)) return null;
  if (redirected) return denyOf(PLAIN_REASON); // A git global option precedes the verb.
  return dec('allow', 'Deletion is a boundary action', MERGED, { remote, argv: words.slice(), boundary: 'delete', kind, branch });
}

/** `git update-ref` that can delete: -d (alone or in a cluster), a long option that abbreviates --delete or --stdin (its input can delete), or an all-zero new value. The value of -m is a message. Doubt reads as a delete. */
function rawRefDelete(args: string[]): boolean {
  for (let i = 0; i < args.length; i++) {
    const x = args[i]!;
    if (x === '-m') i++;
    else if (x.startsWith('--')) {
      const name = x.split('=')[0]!;
      if (name.length > 2 && ('--delete'.startsWith(name) || '--stdin'.startsWith(name))) return true;
    } else if (x.startsWith('-') && !x.startsWith('-m') && x.slice(1).includes('d')) return true;
    else if (/^(?:0{40}|0{64})$/.test(x)) return true;
  }
  return false;
}

function git(words: string[]): Decision {
  let args = words.slice(1);
  let changedRepo = false;
  const plain = !(args.length && args[0]!.startsWith('-')); // Any global option can redirect a merged-delete (R2): fail closed.
  while (args.length && args[0]!.startsWith('-')) {
    const opt = args.shift()!;
    if (GIT.global_value_options!.has(opt)) {
      if (!args.length) return denyOf('Malformed Git global option', 'malformed');
      args.shift();
    }
    if (opt.startsWith('-C') || opt.startsWith('--git-dir') || opt.startsWith('--work-tree')) changedRepo = true;
  }
  if (!args.length) return dec();
  const verb = args[0]!;
  args = args.slice(1);
  let options = args.includes('--') ? args.slice(0, args.indexOf('--')) : args;
  if (Object.prototype.hasOwnProperty.call(LONG_GUARDED, verb)) options = readLongOptions(verb, options);
  const flags = options.filter((x) => x.startsWith('-'));
  const short = flags.filter((x) => !x.startsWith('--')).map((x) => x.slice(1)).join('');
  const hasFlag = (name: string) => flags.includes(name);
  if (verb === 'stash') {
    return denyOf('Git stash shares state across worktrees', 'stash');
  }
  if (verb === 'update-ref' && rawRefDelete(args)) return denyOf('Raw ref deletion is not allowed; use git branch -d');
  if (verb === 'reset' && flags.some((x) => x === '--hard' || x.startsWith('--hard='))) return denyOf('Hard reset discards work');
  if (verb === 'clean' && (short.includes('f') || hasFlag('--force')) && !(short.includes('n') || hasFlag('--dry-run'))) return denyOf('Forced clean discards files');
  if (verb === 'branch' && (short.includes('D') || ((short.includes('d') || hasFlag('--delete')) && (short.includes('f') || hasFlag('--force'))))) {
    const merged = !args.includes('--') ? mergedDelete(verb, options, flags, short, words, !plain, args) : null;
    return merged ?? denyOf('Forced branch deletion discards refs');
  }
  const wholesale = args.includes('.') || args.includes(':/');
  if (verb === 'checkout' && (wholesale || hasFlag('--force') || short.includes('f'))) return denyOf('Wholesale restore discards work');
  if (verb === 'switch' && (short.includes('f') || [...GIT.switch_force_flags!].some((x) => hasFlag(x)))) return denyOf('Wholesale restore discards work');
  if (verb === 'restore') {
    const stagedOnly = (hasFlag('--staged') || short.includes('S')) && !(hasFlag('--worktree') || short.includes('W'));
    if (hasFlag('--force') || (wholesale && !stagedOnly)) return denyOf('Wholesale restore discards work');
  }
  if (verb === 'add' && ([...GIT.wholesale_add_flags!].some((x) => hasFlag(x)) || short.includes('A') || short.includes('u') || args.some((x) => GIT.wholesale_add_pathspecs!.has(x)))) {
    return denyOf('Stage explicit paths only', 'wholesaleStage');
  }
  if (verb === 'commit') {
    // A message beginning with a dash is still a message.
    const opts = options.filter((x) => !(x.startsWith('--message=') || x.startsWith('--file=') || x.startsWith('-m')));
    if (opts.includes('--all') || opts.some((x) => x.startsWith('-') && !x.startsWith('--') && x.slice(1).includes('a'))) {
      return denyOf('Commit explicit staged paths only', 'wholesaleStage');
    }
    if (opts.some((x) => GIT.commit_guarded_flags!.has(x))) return denyOf('Amend rewrites history');
  }
  if (verb === 'push') {
    if (flags.some((x) => x.startsWith('--force') || x === '--mirror') || short.includes('f') || args.some((x) => x.startsWith('+'))) return denyOf('Force push rewrites remote history');
    const dryRun = hasFlag('--dry-run') || short.includes('n');
    const positional = options.filter((x) => !x.startsWith('-'));
    if ((hasFlag('--delete') || short.includes('d')) && !dryRun && !args.includes('--')) {
      const merged = mergedDelete(verb, options, flags, short, words, !plain, args);
      if (merged) return merged;
    }
    if (positional.length > 2 || [...GIT.push_multi_flags!].some((x) => hasFlag(x)) || short.includes('d')) return denyOf('Push needs one explicit remote and refspec', 'release');
    let remote: string | null = positional[0] ?? null;
    let target: string | null = positional[1] ?? null;
    let source: string | null = target ? target.split(':', 2)[0]! : null;
    if (target) {
      if (target.startsWith(':') || target.includes('*') || target.split(':').length - 1 > 1) return denyOf('Push needs one non-deleting refspec', 'release');
      const last = target.split(':').pop()!;
      target = last.startsWith('refs/heads/') ? last.slice('refs/heads/'.length) : last;
    }
    if (changedRepo) {
      remote = null;
      target = null;
      source = null;
    }
    if (dryRun) return dec('allow', 'Dry-run push does not release', 'gitpush', { remote, target, argv: words.slice(), source });
    return dec('release', 'Push needs an exact current release permit', 'gitpush', { remote, target, argv: words.slice(), source });
  }
  if (
    verb === 'rm' ||
    (verb === 'branch' && (short.includes('d') || hasFlag('--delete'))) ||
    (verb === 'tag' && (short.includes('d') || hasFlag('--delete'))) ||
    (verb === 'worktree' && args.length > 0 && GIT.worktree_delete!.has(args[0]!))
  ) {
    return boundaryOf('delete', 'Deletion is a boundary action');
  }
  if (GIT.boundary_merge_verbs!.has(verb)) return boundaryOf('merge', 'Local merge is a boundary action');
  return dec();
}

function sameWords(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

function isRelease(name: string, words: string[]): boolean {
  const pair = words.slice(1, 3);
  return (
    (name === 'gh' && RELEASE.gh.some((p) => sameWords(p, pair))) ||
    (name === 'az' &&
      (RELEASE.az_requires.every((x) => words.includes(x)) ||
        (sameWords(words.slice(1, 4), RELEASE.az_pr_update.prefix) && words.includes(RELEASE.az_pr_update.word)))) ||
    (RELEASE.package_tools.includes(name) && words.slice(1).includes(RELEASE.package_verb)) ||
    (RELEASE.deploy_tools.includes(name) && RELEASE.deploy_words.some((x) => words.slice(1).includes(x)))
  );
}

function findExec(words: string[], depth: number): Decision[] {
  const decisions: Decision[] = [];
  let i = 1;
  while (i < words.length) {
    if (FIND_EXEC.has(words[i]!)) {
      let j = i + 1;
      let command: string[] = [];
      while (j < words.length && !(words[j] === ';' || (words[j] === '+' && words[j - 1] === '{}'))) {
        command.push(words[j]!);
        j += 1;
      }
      command = unwrap(command);
      if (command.length) decisions.push(classifySegment(command, depth));
      i = j;
    }
    i += 1;
  }
  return decisions;
}

function firstBySeverity(decisions: Decision[], base: Decision): Decision {
  const tests: ((d: Decision) => boolean)[] = [(d) => d.action === 'deny' && d.category !== MULTI, (d) => d.action === 'release', (d) => !!d.boundary];
  for (const test of tests) for (const d of decisions) if (test(d)) return d;
  return base;
}

function classifySegment(words: string[], depth: number): Decision {
  const name = posixName(words[0]!);
  if (SHELLS.has(name)) {
    const found = shellPayloadRest(words);
    if (found === null) return dec();
    const [payload, rest] = found;
    const decision = classifyCommand(payload, depth + 1);
    if (hardDeny(decision)) return decision;
    // Rule (6b): substitutions in the payload and the arguments after it.
    return scanSubstitutions(payload, depth) ?? scanPieces(rest, depth) ?? decision;
  }
  if (name === 'eval') {
    const text = words.slice(1).join(' ');
    const decision = classifyCommand(text, depth + 1);
    if (hardDeny(decision)) return decision;
    return scanSubstitutions(text, depth) ?? decision;
  }
  if (name === 'git') return git(words);
  if (isRelease(name, words)) return dec('release', 'Provider release needs structured authorization', 'providerrelease', { argv: words.slice() });
  let base = dec();
  const pair = words.slice(1, 3);
  if (BOUNDARY.delete_commands.includes(name) || (name === 'find' && words.slice(1).includes(BOUNDARY.find_delete_flag)) || (name === 'gh' && BOUNDARY.gh.some((p) => sameWords(p, pair)))) {
    base = boundaryOf('delete', 'Deletion is a boundary action');
  }
  if (name === 'find') return firstBySeverity(findExec(words, depth), base);
  return base;
}

function hardDeny(d: Decision): boolean {
  return d.action === 'deny' && d.category !== 'malformed' && d.category !== MULTI;
}

function scanLines(body: string, depth: number, keepRelease = false): Decision {
  let release = dec();
  for (const line of body.split('\\\n').join('').split('\n')) {
    if (!strip(line)) continue;
    const decision = classifyCommand(line, depth + 1);
    if (hardDeny(decision)) return decision;
    if (keepRelease && decision.action === 'release' && release.action === 'allow') release = decision;
  }
  return release;
}

function substitutions(body: string): string[] {
  const found: string[] = [];
  let i = 0;
  const n = body.length;
  while (i < n) {
    const char = body[i]!;
    if (char === '\\') {
      i += 2;
    } else if (body.startsWith('$((', i)) {
      i += 3;
    } else if (body.startsWith('$(', i)) {
      let depth = 1;
      let j = i + 2;
      while (j < n && depth) {
        if (body[j] === '\\') j += 1;
        else if (body[j] === '(') depth += 1;
        else if (body[j] === ')') depth -= 1;
        j += 1;
      }
      const content = body.slice(i + 2, depth === 0 ? j - 1 : j);
      found.push(content);
      found.push(...substitutions(content));
      i = j;
    } else if (char === '`') {
      let j = i + 1;
      while (j < n && body[j] !== '`') j += body[j] === '\\' ? 2 : 1;
      const content = body.slice(i + 1, j);
      found.push(content);
      found.push(...substitutions(content));
      i = j + 1;
    } else {
      i += 1;
    }
  }
  return found;
}

/**
 * SPEC A5 (O31): put a blank and RMARK before each redirection operator outside quotes (before its
 * descriptor prefix when a number or `{name}` is the whole word before it), so shlex starts a word there
 * that reads as a redirection. A `#` starts a comment only at the start of a word (O33); a `${...}`
 * expansion is copied whole, nested braces included. Mirrors guards._mark_redirects.
 */
function markRedirects(segment: string): string {
  if (!segment.includes('<') && !segment.includes('>')) return segment;
  if (segment.includes(RMARK)) throw new ValueError('Reserved character in command');
  const out: string[] = [];
  let q: string | null = null;
  let i = 0;
  const n = segment.length;
  let start = 0; // Where the current word starts in out.
  let bare = true; // Whether the current word holds only bare characters.
  let here = 0; // 2 right after a `<<<`, 1 inside its operand word: a here-string operand is not word-split.
  let blank = true; // The previous character is a blank (or there is none): a `#` here starts a comment.
  while (i < n) {
    const char = segment[i]!;
    const atBlank = blank;
    blank = false;
    if (q) {
      if (char === q) {
        q = null;
      } else if (char === '\\' && q === '"') {
        out.push(segment.slice(i, i + 2));
        i += 2;
        continue;
      }
    } else if (SHLEX_BLANK.includes(char)) {
      out.push(char);
      i += 1;
      start = out.length;
      bare = true;
      blank = true;
      here = here === 2 ? 2 : 0;
      continue;
    } else if (char === '"' || char === "'") {
      q = char;
      bare = false;
    } else if (char === '\\') {
      out.push(segment.slice(i, i + 2));
      i += 2;
      bare = false;
      here = here ? 1 : 0;
      continue;
    } else if (char === '#' && atBlank) {
      const found = segment.indexOf('\n', i);
      const end = found < 0 ? n : found;
      out.push(segment.slice(i, end));
      i = end;
      continue;
    } else if (segment.startsWith('${', i)) {
      const end = braceEnd(segment, i);
      out.push(here ? escapeBlanks(segment.slice(i, end)) : segment.slice(i, end));
      here = here ? 1 : 0;
      i = end;
      bare = false;
      continue;
    } else if (char === '<' || char === '>' || char === '&') {
      REDIRECT_OP_RE.lastIndex = i;
      const match = REDIRECT_OP_RE.exec(segment);
      if (match) {
        if (bare && FD_WORD_RE.test(out.slice(start).join(''))) out.splice(start, 0, ' ' + RMARK);
        else out.push(' ' + RMARK);
        out.push(match[0]);
        i += match[0].length;
        if (i < n && !SHLEX_BLANK.includes(segment[i]!)) out.push(RMARK); // A second mark right after the operator says its operand is glued.
        start = out.length;
        bare = false; // A glued operand is never a descriptor prefix.
        here = match[0] === '<<<' ? 2 : 0;
        continue;
      }
    }
    here = here ? 1 : 0;
    out.push(char);
    i += 1;
  }
  return out.join('');
}

/** Index just past the `}` closing the `${` at text[i], counting nested `${`; text.length when never closed. Mirrors guards._brace_end. */
function braceEnd(text: string, i: number): number {
  let depth = 0;
  const n = text.length;
  while (i < n) {
    if (text.startsWith('${', i)) {
      depth += 1;
      i += 2;
      continue;
    }
    if (text[i] === '}') {
      depth -= 1;
      if (!depth) return i + 1;
    }
    i += 1;
  }
  return n;
}

/** Escape the blanks of text that stand outside quotes, so shlex keeps it one word. */
function escapeBlanks(text: string): string {
  const out: string[] = [];
  let q: string | null = null;
  for (const char of text) {
    if (q) {
      if (char === q) q = null;
    } else if (char === '"' || char === "'") {
      q = char;
    } else if (SHLEX_BLANK.includes(char)) {
      out.push('\\');
    }
    out.push(char);
  }
  return out.join('');
}

/**
 * SPEC A5 (O31): the shlex words of a segment (comments dropped) as [all words, the words without
 * redirections, the here-string operands]. Mirrors guards._words.
 */
function splitWords(segment: string): [string[], string[], string[]] {
  const original: string[] = [];
  const kept: string[] = [];
  const operands: string[] = [];
  let skip: string | null = null;
  const markedText = markRedirects(segment);
  const words = shlexSplit(markedText, true);
  if (!markedText.includes(RMARK)) return [words, words.slice(), []];
  for (const word of words) {
    const marked = word.startsWith(RMARK);
    const plain = word.split(RMARK).join('');
    original.push(plain);
    if (skip) {
      if (skip === '<<<') operands.push(plain);
      skip = null;
      continue;
    }
    const match = marked ? REDIRECT_WORD_RE.exec(plain) : null; // A heredoc operator is a redirection too (O33).
    if (!match) {
      kept.push(plain);
      continue;
    }
    const here = match[0].endsWith('<<<') ? '<<<' : '>';
    if (word.startsWith(RMARK, 1 + match[0].length)) {
      // Glued operand (even an empty one, as in `<<<""`).
      if (here === '<<<') operands.push(plain.slice(match[0].length));
    } else {
      skip = here;
    }
  }
  return [original, kept, operands];
}

/** The command words of a segment: redirections dropped, wrappers unwrapped. Here-string operands are added to operands when given. */
function commandWords(segment: string, operands: string[] | null = null): string[] {
  if (!segment.includes('<') && !segment.includes('>')) return unwrap(shlexSplit(segment, true));
  const [, words, here] = splitWords(segment);
  if (operands !== null) operands.push(...here);
  return unwrap(words);
}

function consumerMode(segment: string, allowEval = true): string | null {
  const kept = commandWords(segment);
  if (!kept.length) return null;
  if (SHELLS.has(posixName(kept[0]!))) return shellPayload(kept) !== null ? 'c' : 'script';
  if (kept[0] === '.' || kept[0] === 'source' || (allowEval && kept[0] === 'eval')) return 'script';
  return null;
}

function bodyDecision(body: string, modes: Set<string | null>, depth: number): Decision {
  if (!strip(body)) return dec();
  let decision = classifyCommand(body, depth + 1);
  if (!modes.has('script') && decision.category === 'malformed') decision = scanLines(body, depth, true);
  return decision;
}

const ANSI: Record<string, string> = { a: '\x07', b: '\b', e: '\x1b', E: '\x1b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v', '\\': '\\', "'": "'", '"': '"', '?': '?' };
const ANSI_NUMERIC: [string, RegExp, number][] = [
  ['x', /[0-9A-Fa-f]{1,2}/y, 16],
  ['u', /[0-9A-Fa-f]{1,4}/y, 16],
  ['U', /[0-9A-Fa-f]{1,8}/y, 16],
];
const ANSI_OCTAL = /[0-7]{1,3}/y;

function matchAt(re: RegExp, text: string, pos: number): string | null {
  re.lastIndex = pos;
  const m = re.exec(text);
  return m ? m[0] : null;
}

function ansiEscape(text: string, i: number): [string, number] {
  const char = text[i + 1]!;
  if (Object.prototype.hasOwnProperty.call(ANSI, char)) return [ANSI[char]!, i + 2];
  try {
    for (const [letter, pattern, base] of ANSI_NUMERIC) {
      const m = char === letter ? matchAt(pattern, text, i + 2) : null;
      if (m) return [String.fromCodePoint(parseInt(m, base)), i + 2 + m.length];
    }
    const m = matchAt(ANSI_OCTAL, text, i + 1);
    if (m) return [String.fromCodePoint(parseInt(m, 8)), i + 1 + m.length];
  } catch {
    // Out of range for a code point: the escape stays literal.
  }
  return ['\\' + char, i + 2];
}

function dollarDecode(text: string): string {
  if (!text.includes("$'")) return text;
  const out: string[] = [];
  let q: string | null = null;
  let escaped = false;
  let i = 0;
  const n = text.length;
  while (i < n) {
    const char = text[i]!;
    if (escaped) {
      escaped = false;
    } else if (char === '\\' && q !== "'") {
      escaped = true;
    } else if (q) {
      if (char === q) q = null;
    } else if (char === '"' || char === "'") {
      q = char;
    } else if (char === '$' && text.startsWith("$'", i)) {
      let j = i + 2;
      const buf: string[] = [];
      while (j < n && text[j] !== "'") {
        if (text[j] === '\\' && j + 1 < n) {
          const [decoded, next] = ansiEscape(text, j);
          buf.push(decoded);
          j = next;
        } else {
          buf.push(text[j]!);
          j += 1;
        }
      }
      if (j >= n) {
        out.push(text.slice(i));
        break;
      }
      out.push(quote(buf.join('')));
      i = j + 1;
      continue;
    }
    out.push(char);
    i += 1;
  }
  return out.join('');
}

function readBalanced(text: string, i: number): number {
  const end = balancedEnd(text, i);
  return end < 0 ? text.length : end;
}

const CASE_PREV = new Set(['if', 'then', 'elif', 'else', 'while', 'until', 'do', '!', '{', 'time']);
const WORD_STOP = ' \t\n;&|()<>"\'\\$`';

/**
 * Index just past the bodies of the heredocs in pending, which start at text[i]. A body that never ends is
 * not skipped (the operator may not have been a heredoc, as in `$((1 << 2))`).
 */
function skipHeredocBodies(text: string, i: number, pending: [boolean, string][]): number {
  let j = i;
  const n = text.length;
  for (const [dash, delimiter] of pending) {
    for (;;) {
      if (j >= n) return i;
      const end = text.indexOf('\n', j);
      const line = text.slice(j, end < 0 ? n : end);
      j = end < 0 ? n : end + 1;
      if ((dash ? line.replace(/^\t+/, '') : line) === delimiter) break;
    }
  }
  return j;
}

function balancedEnd(text: string, start0: number): number {
  let i = start0;
  let depth = 1;
  let q: string | null = null;
  const n = text.length;
  const cases: { state: string; depth: number }[] = [];
  let pending: [boolean, string][] = []; // Heredoc (dash, delimiter) pairs whose bodies start after the next newline (SPEC A5, O20).
  let start = true;
  while (i < n) {
    const char = text[i]!;
    if (char === '\\' && q !== "'") {
      i += 2;
      start = false;
      continue;
    }
    if (q) {
      if (char === q) q = null;
      i += 1;
      continue;
    }
    const last = cases[cases.length - 1];
    const top = last && last.depth === depth ? last : null;
    if (char === '"' || char === "'") {
      q = char;
      start = false;
    } else if (text.startsWith("$'", i)) {
      i += 2;
      while (i < n && text[i] !== "'") i += text[i] === '\\' ? 2 : 1;
      start = false;
    } else if (char === '#' && (i === 0 || ' \t\n;&|()'.includes(text[i - 1]!))) {
      const end = text.indexOf('\n', i);
      i = end < 0 ? n : end;
      continue;
    } else if (char === ' ' || char === '\t') {
      // Blanks neither start nor end a command position.
    } else if (char === '(') {
      if (!(top && top.state === 'pattern')) depth += 1;
      start = true;
    } else if (char === ')') {
      if (top && top.state === 'pattern') {
        top.state = 'body';
      } else {
        depth -= 1;
        if (depth === 0) return i + 1;
      }
      start = true;
    } else if (char === '<' && text.startsWith('<<', i) && !text.startsWith('<<<', i) && (i === 0 || text[i - 1] !== '<') && heredocAt(text, i) !== null) {
      const found = heredocAt(text, i)!;
      pending.push([found[1] !== '', found[2]!.replace(/^["'\\]+|["'\\]+$/g, '')]);
      i = found.index + found[0].length;
      start = false;
      continue;
    } else if (';&|\n'.includes(char)) {
      const two = text.slice(i, i + 2);
      if (top && top.state === 'body' && (two === ';;' || two === ';&')) {
        top.state = 'pattern';
        i += 1;
      } else if (char === '\n' && pending.length) {
        i = skipHeredocBodies(text, i + 1, pending);
        pending = [];
        start = true;
        continue;
      }
      start = true;
    } else if (!'$`<>'.includes(char)) {
      let end = i;
      while (end < n && !WORD_STOP.includes(text[end]!)) end += 1;
      const after = text.slice(end, end + 1);
      const word = after !== '"' && after !== "'" && after !== '\\' && after !== '$' && after !== '`' ? text.slice(i, end) : '';
      if (word === 'in' && top && top.state === 'head') top.state = 'pattern';
      else if (word === 'case' && start) cases.push({ state: 'head', depth });
      else if (word === 'esac' && start && top && top.state !== 'head') cases.pop();
      start = CASE_PREV.has(word);
      i = end;
      continue;
    } else {
      start = false;
    }
    i += 1;
  }
  return -1;
}

function skipDouble(text: string, start: number): number {
  let i = start;
  const n = text.length;
  while (i < n) {
    if (text[i] === '\\') i += 2;
    else if (text[i] === '"') return i + 1;
    else if (text.startsWith('$(', i)) i = readBalanced(text, i + 2);
    else if (text[i] === '`') {
      const close = text.indexOf('`', i + 1);
      i = close < 0 ? n : close + 1;
    } else i += 1;
  }
  return n;
}

function readWord(text: string, start: number): number {
  let i = start;
  const n = text.length;
  while (i < n) {
    const char = text[i]!;
    if (' \t\n;|&<>()'.includes(char)) break;
    if (char === '\\') i += 2;
    else if (char === "'") {
      const close = text.indexOf("'", i + 1);
      i = close < 0 ? n : close + 1;
    } else if (char === '"') i = skipDouble(text, i + 1);
    else if (text.startsWith('$(', i)) i = readBalanced(text, i + 2);
    else if (char === '`') {
      const close = text.indexOf('`', i + 1);
      i = close < 0 ? n : close + 1;
    } else i += 1;
  }
  return Math.min(i, n);
}

type Ops = [[string, string][], [string, string][]];

function scanOps(text: string): Ops {
  const herestrings: [string, string][] = [];
  const procsubs: [string, string][] = [];
  let pending: [string, string, number][] = [];
  const parens: ([number, [string, string, number][]] | null)[] = [];
  let start = 0;
  let q: string | null = null;
  let escaped = false;
  const n = text.length;
  for (let i = 0; i < n; i++) {
    const char = text[i]!;
    if (escaped) {
      escaped = false;
    } else if (char === '\\' && q !== "'") {
      escaped = true;
    } else if (q) {
      if (char === q) q = null;
    } else if (char === '"' || char === "'") {
      q = char;
    } else if (char === '<' && text.startsWith('<<<', i) && (i === 0 || text[i - 1] !== '<')) {
      let j = i + 3;
      while (j < n && ' \t'.includes(text[j]!)) j += 1;
      const end = readWord(text, j);
      pending.push([text.slice(start, i), text.slice(j, end), end]);
    } else if (char === '<' && text.startsWith('<(', i) && (i === 0 || !'<>'.includes(text[i - 1]!))) {
      const close = readBalanced(text, i + 2);
      const inner = text.slice(close - 1, close) === ')' ? text.slice(i + 2, close - 1) : text.slice(i + 2, close);
      procsubs.push([text.slice(start, i), inner]);
    } else if (char === '&' && ((i > 0 && '<>'.includes(text[i - 1]!)) || text.slice(i + 1, i + 2) === '>')) {
      continue;
    } else if (char === '|' && i > 0 && text[i - 1] === '>') {
      continue;
    } else if (char === '(' && i > 0 && text[i - 1] === '$' && !backslashed(text, i - 1)) {
      // O34: a `$(` substitution does not cut the command around it; its inner text is a command of its own.
      parens.push([start, pending]);
      pending = [];
      start = i + 1;
    } else if (';|&()\n'.includes(char)) {
      for (const [before, word, end] of pending) herestrings.push([before + ' ' + (i >= end ? text.slice(end, i) : ''), word]);
      pending = [];
      start = i + 1;
      if (char === '(') parens.push(null);
      else if (char === ')' && parens.length) {
        const outer = parens.pop();
        if (outer) [start, pending] = outer;
      }
    }
  }
  for (const [before, word, end] of pending) herestrings.push([before + ' ' + text.slice(end), word]);
  return [herestrings, procsubs];
}

function isArithmetic(text: string, i: number): boolean {
  if (!text.startsWith('$((', i)) return false;
  const inner = balancedEnd(text, i + 3);
  return inner < 0 || text.slice(inner, inner + 1) === ')';
}

function rawSubstitutions(text: string, ticks: [boolean, number, boolean][] | null = null): [string[], boolean] {
  const found: string[] = [];
  let closed = true;
  let i = 0;
  const n = text.length;
  let inQuote = false;

  const command = (at: number): number => {
    if (ticks !== null) ticks.push([text[at] === '`', at, inQuote]);
    if (text[at] === '`') {
      let j = at + 1;
      while (j < n && text[j] !== '`') j += text[j] === '\\' ? 2 : 1;
      closed = closed && j < n;
      found.push(text.slice(at + 1, Math.min(j, n)).replace(/\\([`\\$])/g, '$1'));
      return j + 1;
    }
    const end = balancedEnd(text, at + 2);
    closed = closed && end >= 0;
    found.push(text.slice(at + 2, end < 0 ? n : end - 1));
    return end < 0 ? n : end;
  };

  while (i < n) {
    const char = text[i]!;
    if (char === '\\') {
      i += 2;
    } else if (inQuote) {
      if (char === '"') {
        inQuote = false;
        i += 1;
      } else if (char === '`' || (text.startsWith('$(', i) && !isArithmetic(text, i))) {
        i = command(i);
      } else {
        i += 1;
      }
    } else if (char === "'") {
      const close = text.indexOf("'", i + 1);
      i = close < 0 ? n : close + 1;
    } else if (char === '"') {
      inQuote = true;
      i += 1;
    } else if (isArithmetic(text, i)) {
      i += 3;
    } else if (char === '`' || text.startsWith('$(', i)) {
      i = command(i);
    } else {
      i += 1;
    }
  }
  return [found, closed];
}

function rawCommands(text: string): string[][] {
  const commands: string[][] = [];
  let words: string[] = [];
  let i = 0;
  const n = text.length;
  while (i < n) {
    const char = text[i]!;
    if (char === ' ' || char === '\t') {
      i += 1;
    } else if (char === '#') {
      const end = text.indexOf('\n', i);
      i = end < 0 ? n : end;
    } else if (';|&()\n'.includes(char)) {
      const glued = (char === '&' && ((i > 0 && '<>'.includes(text[i - 1]!)) || text.slice(i + 1, i + 2) === '>')) || (char === '|' && i > 0 && text[i - 1] === '>');
      if (!glued) {
        commands.push(words);
        words = [];
      }
      i += 1;
    } else if (char === '<' || char === '>') {
      let end = i;
      while (end < n && (text[end] === '<' || text[end] === '>')) end += 1;
      words.push(text.slice(i, end));
      i = end;
    } else {
      let end = Math.max(readWord(text, i), i + 1);
      const next = text.slice(end, end + 1);
      if ((isDigit(text.slice(i, end)) || FD_WORD_RE.test(text.slice(i, end))) && (next === '<' || next === '>')) {
        while (end < n && (text[end] === '<' || text[end] === '>')) end += 1;
      }
      words.push(text.slice(i, end));
      i = end;
    }
  }
  commands.push(words);
  return commands.filter((c) => c.length);
}

function rawScan(text: string, depth: number): Decision | null {
  if (depth > 8) return null;
  for (const raws of rawCommands(text)) {
    const values: string[] = [];
    for (const raw of raws) {
      let parts: string[];
      try {
        parts = shlexSplit(raw, false);
      } catch (e) {
        if (!(e instanceof ValueError)) throw e;
        parts = [];
      }
      values.push(parts.length === 1 ? parts[0]! : raw);
    }
    const kept: string[] = [];
    let skip = false;
    raws.forEach((raw, k) => {
      // SPEC A5 (O31): unquoted redirections and their operands.
      const redirect = skip ? null : REDIRECT_RE.exec(raw);
      if (!skip && !redirect) kept.push(values[k]!);
      skip = !!redirect && !redirect[1];
    });
    let words: string[];
    try {
      words = unwrap(kept);
    } catch (e) {
      if (!(e instanceof ValueError)) throw e;
      continue;
    }
    if (!words.length) continue;
    const name = posixName(words[0]!);
    if (!(name === 'eval' || (SHELLS.has(name) && shellPayloadRest(words) !== null))) continue;
    for (const raw of raws) {
      const [contents, closed] = rawSubstitutions(raw);
      if (!closed) return denyOf('Unbalanced command substitution', 'malformed');
      for (const content of contents) {
        const hit = scanText(content, depth + 1, true);
        if (hit) return hit;
      }
    }
  }
  return null;
}

/**
 * SPEC A5 (O25): rewrite each closed, unquoted backtick substitution (never inside quotes) as the `$(...)`
 * form of the same content, so it keeps the same class in the same position. Inside double quotes a
 * backtick stays one (backtickScan classifies it, with its escaped inner backticks unescaped). Inside
 * backticks the shell reads backslash-backtick, backslash-backslash and backslash-dollar as the plain
 * character, so an escaped backtick there is a nested substitution, rewritten in turn. A top-level
 * escaped backtick stays a literal.
 */
function tickToDollar(text: string): string {
  const out: string[] = [];
  let i = 0;
  const n = text.length;
  let quote = false;
  while (i < n) {
    const char = text[i]!;
    if (char === '\\') {
      out.push(text.slice(i, i + 2));
      i += 2;
    } else if (char === '`' && !quote) {
      let j = i + 1;
      while (j < n && text[j] !== '`') j += text[j] === '\\' ? 2 : 1;
      if (j >= n) { // Never closed: leave it for the malformed checks.
        out.push(text.slice(i));
        break;
      }
      const content = text.slice(i + 1, j).replace(/\\([`\\$])/g, '$1');
      out.push('$(' + tickToDollar(content) + ')');
      i = j + 1;
    } else if (char === "'" && !quote) {
      const close = text.indexOf("'", i + 1);
      const end = close < 0 ? n : close + 1;
      out.push(text.slice(i, end));
      i = end;
    } else {
      if (char === '"') quote = !quote;
      out.push(char);
      i += 1;
    }
  }
  return out.join('');
}

const ASSIGN_PREFIX_RE = /^[A-Za-z_][A-Za-z0-9_]*\+?=/;
const SKIP_WORDS = 32; // Words of one segment kept to find its command name; a longer all-skip prefix counts as command position.

/**
 * True when a leading word is skipped before the command name (SPEC A5): reserved words, `time`,
 * `function`/`coproc` headers, `case`, redirects, assignments and the wrappers table.
 */
function skips(word: string): boolean {
  return word === 'function' || !unwrap([word]).length;
}

const HERE_OPERATOR_RE = /^[0-9]*<<<?$/;

type CommandGroup = ['proc' | 'group', string[], boolean, boolean];

/**
 * SPEC A5 (O20, O23, O28): for each index in ats (ascending, each the start of a substitution), true when
 * the substitution is at command position: after a separator or group opener, with only the words the
 * command-name rule skips since (see skips; wrapper options and values included). One forward,
 * quote-aware pass: separators inside quotes or after a backslash do not count, and a literal `{` or `)`
 * argument is not a separator. A case pattern is not a command position; the body of a case arm is.
 */
function commandPositions(text: string, ats: number[]): boolean[] {
  const result: boolean[] = [];
  const limit = ats.length;
  const n = text.length;
  let seg: string[] = [];
  let settled = false; // Whether the segment's command name came.
  let overflow = false; // Too many words.
  const stack: CommandGroup[] = []; // Open `(` groups.
  const cases: string[] = []; // Open `case` states ('head', 'pattern', 'body').
  let t = 0;
  let i = 0;
  let noStart = -1; // The index just after the `)` of a `<(` or `>(`, where a `#` is no word start.

  const here = (): boolean => {
    if (cases.length && cases[cases.length - 1] !== 'body') return false;
    if (settled) return false;
    if (overflow) return true;
    try {
      return !unwrap(seg.slice()).length;
    } catch (e) {
      if (e instanceof ValueError) return false;
      throw e;
    }
  };

  const word = (bare: string): void => {
    const atCommand = here();
    if (bare === 'case' && atCommand) cases.push('head');
    else if (bare === 'in' && cases.length && cases[cases.length - 1] === 'head') cases[cases.length - 1] = 'pattern';
    else if (bare === 'esac' && cases.length && ['body', 'pattern'].includes(cases[cases.length - 1]!) && !seg.length && !settled) cases.pop();
    if (settled || overflow) return;
    if (!seg.length && !skips(bare)) settled = true;
    else if (seg.length < SKIP_WORDS) seg.push(bare);
    else overflow = true;
  };

  const reset = (): void => {
    seg = [];
    settled = false;
    overflow = false;
  };

  while (i < n && t < limit) {
    const char = text[i]!;
    if (char === ' ' || char === '\t') {
      i += 1;
      continue;
    }
    let token = 'word';
    let end = i + 1;
    if (char === '#' && i !== noStart && (i === 0 || (WORD_START.includes(text[i - 1]!) && !backslashed(text, i)))) {
      const found = text.indexOf('\n', i);
      end = found < 0 ? n : found;
      token = 'comment';
    } else if (char === '\n') {
      token = 'sep';
    } else if (char === ';') {
      token = 'sep';
      if (text.startsWith(';;&', i)) end = i + 3;
      else if (text.slice(i, i + 2) === ';;' || text.slice(i, i + 2) === ';&') end = i + 2;
      if (cases.length && cases[cases.length - 1] === 'body' && end > i + 1) cases[cases.length - 1] = 'pattern';
    } else if (char === '|') {
      token = 'pipe';
    } else if (char === '&' && text.slice(i + 1, i + 2) !== '>') {
      token = 'sep';
    } else if ((char === '<' || char === '>') && text.startsWith('(', i + 1)) {
      token = 'skip'; // `<(` or `>(`: the `(` after it opens the process substitution.
    } else if (char === '<' || char === '>' || char === '&') {
      while (end < n && (text[end] === '<' || text[end] === '>')) end += 1;
      if ((text.slice(end, end + 1) === '&' && '<>'.includes(text[end - 1]!)) || (text.slice(end, end + 1) === '|' && text[end - 1] === '>')) end += 1;
      token = 'redirect';
    } else if (char === '(') {
      token = 'open';
    } else if (char === ')') {
      token = 'close';
    } else {
      end = Math.max(readWord(text, i), i + 1);
      const after = text.slice(end, end + 2);
      if ((isDigit(text.slice(i, end)) || FD_WORD_RE.test(text.slice(i, end))) && (text.slice(end, end + 1) === '<' || text.slice(end, end + 1) === '>') && after !== '<(' && after !== '>(') {
        while (end < n && (text[end] === '<' || text[end] === '>')) end += 1;
        if (text.slice(end, end + 1) === '&' || (text.slice(end, end + 1) === '|' && text[end - 1] === '>')) end += 1;
        token = 'redirect';
      }
    }
    if (token === 'redirect' && end < n && !' \t\n;&|()<>'.includes(text[end]!) && HERE_OPERATOR_RE.test(text.slice(i, end))) {
      end = Math.max(readWord(text, end), end); // SPEC A5 (O28): `<<<x` and `<<EOF` glue their operand, as the command-name rule reads them.
    }
    while (t < limit && ats[t]! < end) {
      if (ats[t]! <= i) {
        result.push(here());
      } else if (token === 'word') {
        const match = ASSIGN_PREFIX_RE.exec(text.slice(i)); // A substitution inside a `NAME=` word keeps the position before it.
        result.push(match && ats[t]! >= i + match[0].length ? here() : false);
      } else {
        result.push(here());
      }
      t += 1;
    }
    const raw = text.slice(i, end);
    if (token === 'sep' || (token === 'pipe' && !(cases.length && cases[cases.length - 1] === 'pattern'))) {
      reset();
    } else if (token === 'open') {
      if (!(cases.length && cases[cases.length - 1] === 'pattern')) {
        stack.push([i > 0 && '<>'.includes(text[i - 1]!) ? 'proc' : 'group', seg, settled, overflow]);
        reset();
      }
    } else if (token === 'close') {
      if (cases.length && cases[cases.length - 1] === 'pattern') {
        cases[cases.length - 1] = 'body';
        reset();
      } else if (stack.length) {
        const [kind, savedSeg, savedSettled, savedOverflow] = stack.pop()!;
        seg = savedSeg;
        settled = savedSettled;
        overflow = savedOverflow;
        if (kind === 'proc') {
          noStart = end;
          word('<()');
        } else {
          seg = [];
          settled = true;
          overflow = false;
        }
      } else {
        reset();
      }
    } else if (token === 'word' || token === 'redirect') {
      let parts: string[];
      try {
        parts = shlexSplit(raw, false);
      } catch (e) {
        if (!(e instanceof ValueError)) throw e;
        parts = [];
      }
      word(parts.length === 1 ? parts[0]! : raw);
    }
    i = end;
  }
  while (t < limit) {
    result.push(here());
    t += 1;
  }
  return result;
}

/**
 * SPEC A5 (O20, O23): a backtick substitution anywhere in the text is a command, as `$(...)` is. The
 * `$(...)` ones are classified by the segment split, except at command position, where (like a
 * backtick there) the substitution's output runs, so its text is producer text.
 */
function backtickScan(text: string, depth: number): Decision | null {
  if (depth > 8) return null;
  const ticks: [boolean, number, boolean][] = []; // One [is a backtick, start index, inside double quotes] per substitution.
  const [found] = rawSubstitutions(text, ticks);
  const positions = commandPositions(text, ticks.map((tick) => tick[1]));
  for (let k = 0; k < found.length && k < ticks.length; k++) {
    const content = found[k]!;
    const [tick] = ticks[k]!;
    let hit: Decision | null;
    if (positions[k]) hit = scanText(content, depth + 1, true); // At command position its output runs.
    else if (!tick) hit = backtickScan(content, depth + 1);
    else hit = classifyCommand(content, depth + 1);
    if (hit && hardDeny(hit)) return hit;
  }
  return null;
}

/**
 * SPEC A5 (O26): a `$(...)` inside a double-quoted word keeps the full class of its content, as the
 * unquoted one does (the segment split cuts that one out; here the quoted word stays whole). Returns the
 * decision of each such substitution, found at any depth of unquoted substitutions. A double-quoted
 * backtick is unchanged: backtickScan classifies it. Nesting above depth 8 throws ValueError, which
 * classifyCommand turns into the malformed deny (accepted limit).
 */
function quotedSubstitutions(text: string, depth: number): Decision[] {
  if (!text.includes('$(') || !text.includes('"')) return [];
  if (depth > 8) throw new ValueError('Quoted substitution nested too deep'); // Fail-safe: a malformed deny, never an empty result.
  const ticks: [boolean, number, boolean][] = [];
  const found: Decision[] = [];
  const contents = rawSubstitutions(text, ticks)[0];
  for (let k = 0; k < contents.length && k < ticks.length; k++) {
    const [tick, , quoted] = ticks[k]!;
    if (tick) continue;
    if (quoted) found.push(classifyCommand(contents[k]!, depth + 1));
    else found.push(...quotedSubstitutions(contents[k]!, depth + 1));
  }
  return found;
}

/** True when the segment is blank or only redirections (`2>/dev/null`, `>&1`, `</dev/stdin`). */
function onlyRedirects(segment: string): boolean {
  let words: string[];
  try {
    words = shlexSplit(segment, false);
  } catch {
    return false;
  }
  let i = 0;
  while (i < words.length) {
    const redirect = REDIRECT_RE.exec(words[i]!);
    if (!redirect) return false;
    i += redirect[1] ? 1 : 2;
  }
  return i <= words.length;
}

function pipeJoins(parts: Piece[], k: number): boolean {
  const following = k + 1 < parts.length ? parts[k + 1]! : null;
  return following !== null && !!(strip(following[0]) || following[1] === '&' || following[1] === '\n' || following[1] === '(');
}

function chains(text: string): string[][] {
  const parts = split(text);
  const out: string[][] = [];
  let cur: string[] = [];
  const frames: { members: string[]; seen: number; feeder: string[] | null }[] = [];
  let carry = false;
  let pipeBefore = false;
  let flushes = 0;

  const flush = () => {
    if (cur.length) {
      for (let f = frames.length - 1; f >= 0; f--) {
        const frame = frames[f]!;
        if (frame.feeder && frame.feeder.length && flushes !== frame.seen) {
          cur = frame.feeder.concat(cur);
          break;
        }
      }
      out.push(cur);
      flushes += 1;
    }
    cur = [];
  };

  // A part holding only redirects and a continuing `|` comes right after parts[k] (O20).
  const pipeFollows = (k: number): boolean => k + 1 < parts.length && onlyRedirects(parts[k + 1]![0]) && parts[k + 1]![1] === '|' && pipeJoins(parts, k + 1);

  for (let k = 0; k < parts.length; k++) {
    const [seg, op] = parts[k]!;
    let s = strip(seg);
    if (carry && !s && (op === '&' || op === '\n')) {
      carry = false;
      continue;
    }
    carry = false;
    if (k && parts[k - 1]![1] === ')' && s && pipeFollows(k - 1)) s = ''; // The redirects of a group that a pipe follows are not a command.
    if (/^\{/.test(s) && WS_OR_END_RE.test(s.slice(1))) {
      s = strip(s.slice(1));
      frames.push({ members: [], seen: flushes, feeder: pipeBefore ? cur.slice() : null });
    }
    const closes = s === '}';
    if (closes) s = '';
    if (s) {
      cur.push(s);
      for (const frame of frames) frame.members.push(s);
    }
    if (closes && frames.length) {
      const frame = frames.pop()!;
      if (flushes !== frame.seen) cur = (frame.feeder ?? []).concat(frame.members);
    }
    if (op === '(') {
      if (!pipeBefore) flush();
      frames.push({ members: [], seen: flushes, feeder: pipeBefore ? cur.slice() : null });
    } else if (op === ')') {
      if (frames.length) {
        const frame = frames.pop()!;
        if (flushes !== frame.seen && pipeFollows(k)) cur = (frame.feeder ?? []).concat(frame.members);
        else if (frame.feeder && frame.feeder.length && flushes !== frame.seen && cur.length) cur = frame.feeder.concat(cur);
      }
      if (!pipeFollows(k)) flush();
    } else if (op === '|' && pipeJoins(parts, k)) {
      carry = !strip(parts[k + 1]![0]) && (parts[k + 1]![1] === '&' || parts[k + 1]![1] === '\n');
      pipeBefore = true;
      continue;
    } else {
      flush();
    }
    pipeBefore = op !== '(' ? false : pipeBefore;
  }
  flush();
  return out;
}

function scanSubstitutions(text: string, depth: number): Decision | null {
  if (depth > 8) return null;
  for (const content of substitutions(text)) {
    const hit = scanText(content, depth + 1, true);
    if (hit) return hit;
  }
  return null;
}

function scanPieces(args: string[], depth: number): Decision | null {
  if (depth > 8 || !args.length) return null;
  for (const word of args) {
    const hit = scanSubstitutions(word, depth);
    if (hit) return hit;
  }
  for (const text of [...args, args.join(' ')]) {
    for (const piece of text.split(/\n|\\n|;/)) {
      if (strip(piece)) {
        const decision = classifyCommand(strip(piece), depth + 1);
        if (hardDeny(decision)) return decision;
      }
    }
  }
  return null;
}

function scanText(textIn: string, depth: number, asCommand = false): Decision | null {
  if (depth > 8) return null;
  const text = dollarDecode(textIn);
  if (asCommand) {
    const decision = classifyCommand(text, depth + 1);
    if (hardDeny(decision)) return decision;
  }
  for (const content of rawSubstitutions(text)[0]) {
    const hit = scanText(content, depth + 1, true);
    if (hit) return hit;
  }
  for (const segment of segments(text)) {
    let words: string[];
    const operands: string[] = [];
    try {
      words = commandWords(segment, operands);
    } catch (e) {
      if (!(e instanceof ValueError)) throw e;
      continue;
    }
    const hit = scanPieces(words.slice(1).concat(operands), depth);
    if (hit) return hit;
  }
  return null;
}

type Item = [Decision, string[], boolean];

function streamItems(text: string, ops: Ops, depth: number): Item[] {
  const items: Item[] = [];
  const [herestrings, procsubs] = ops;

  const consumer = (commandText: string, allowEval: boolean): [string | null, string[]] => {
    try {
      return [consumerMode(commandText, allowEval), commandWords(commandText)];
    } catch (e) {
      if (!(e instanceof ValueError)) throw e;
      return [null, []];
    }
  };

  for (const [commandText, word] of herestrings) {
    const [mode, argv] = consumer(commandText, false);
    if (mode === null) continue;
    let value: string;
    try {
      value = shlexSplit(word, false).join(' ');
    } catch (e) {
      if (!(e instanceof ValueError)) throw e;
      continue;
    }
    items.push([bodyDecision(value, new Set([mode]), depth), argv, false]);
    const hit = scanSubstitutions(value, depth);
    if (hit) items.push([hit, argv, false]);
  }
  for (const [before, inner] of procsubs) {
    const [mode, argv] = consumer(before, false);
    if (mode !== null) {
      const hit = scanText(inner, depth, true);
      if (hit) items.push([hit, argv, false]);
    }
  }
  for (const chain of chains(text)) {
    for (let index = 0; index < chain.length; index++) {
      const [mode, argv] = consumer(chain[index]!, true);
      if (mode === null) continue;
      for (const producer of chain.slice(0, index)) {
        const hit = scanText(producer, depth);
        if (hit) items.push([hit, argv, false]);
      }
      break;
    }
  }
  return items;
}

function heredocItems(docs: Doc[], pipes: string[][], depth: number): Item[] {
  const items: Item[] = [];
  docs.forEach(([body, quoted], index) => {
    const marker = '<<' + MARK + String(index) + MARK;
    let modes = new Set<string | null>();
    let argv: string[] = [];
    for (const pipeline of pipes) {
      const where = pipeline.findIndex((segment) => segment.includes(marker));
      if (where >= 0) {
        argv = shlexSplit(pipeline[where]!, true).map((word) => word.replace(MARK_RE, '<<HEREDOC'));
        modes = new Set(pipeline.slice(where).map((segment) => consumerMode(segment)));
        break;
      }
    }
    if (modes.has('script') || modes.has('c')) items.push([bodyDecision(body, modes, depth), argv, false]);
    if (!quoted) {
      // Rule (4): every class but malformed is kept and counts as a segment, as for O26.
      for (const content of substitutions(body)) {
        const decision = classifyCommand(content, depth + 1);
        if (klassOf(decision) !== 'allow' && decision.category !== 'malformed') items.push([decision, argv, true]);
      }
    }
    const decision = scanLines(body, depth);
    if (decision.action === 'deny') items.push([decision, argv, false]);
  });
  return items;
}

function codePointLength(text: string): number {
  if (text.length <= 131072) return text.length;
  let n = 0;
  for (const _ of text) n += 1;
  return n;
}

const SMARK = '\ue002'; // Private-use delimiter for the placeholder that stands in for an unquoted `$(...)` (O33).
const SUB_RE = /\ue002([0-9]+)\ue002/g;
const PURE_SUB_RE = /^(?:\ue002[0-9]+\ue002)+$/; // A word made only of substitutions.
const FOLD_LEVELS = 16; // Substitution nesting levels folded (O33); a substitution nested deeper denies (O34).
const SUFFIX_CAP = 32; // Command readings after pure-substitution words in one segment (FX4); more denies.
const READING_BUDGET = 1024; // Extra readings (O33 removed, wrapper twin, FX4 suffix) per call, nested shells included (FX6).
let budgetLeft = READING_BUDGET;
const RANK: Record<string, number> = { deny: 4, 'release-multi': 3, release: 2, boundary: 1 };

/** The stricter of two verdicts (O34); first on a tie. Mirrors guards._stricter. */
function stricter(first: Decision, second: Decision): Decision {
  return (RANK[klassOf(second)] ?? 0) > (RANK[klassOf(first)] ?? 0) ? second : first;
}

/**
 * One extra reading of a segment (FX6). It spends the per-call budget; past it the command denies as malformed.
 * A reading the words cannot form (a wrapper option left without its value) is dropped, as the shell could not
 * run that expansion: it is no reason to deny the command. Mirrors guards._extra.
 */
function extra(build: () => string[]): string[] {
  budgetLeft -= 1;
  if (budgetLeft < 0) throw new ValueError('Too many command readings');
  try {
    return build();
  } catch (e) {
    if (!(e instanceof ValueError)) throw e;
    return [];
  }
}

/** FX4: the words after a pure-substitution word, read as the command. Mirrors guards._suffix_reading. */
function suffixReading(full: string[], kept: string[], pure: boolean[]): string[] {
  const rest = unwrap(full);
  return pure.includes(true) ? removedReading(full, kept, rest) : rest;
}

/** O33 and O34: the words with pure-substitution words removed, then unwrapped. Mirrors guards._removed_reading. */
function removedReading(full: string[], kept: string[], whole: string[]): string[] {
  const words = unwrap(full.filter((_w, k) => !PURE_SUB_RE.test(kept[k]!)));
  if (!words.length || !whole.length || whole[0] !== words[0]) return words;
  if (words[0] === 'eval' || !SHELLS.has(posixName(words[0]!))) return words[0] === 'eval' ? whole : words;
  const offset = full.length - whole.length;
  if (whole.some((word, k) => full[offset + k] !== word)) return whole; // Rewritten by a runner (watch, flock -c).
  const out = [whole[0]!];
  let payload = false;
  for (let k = 1; k < whole.length; k++) {
    const word = whole[k]!;
    if (payload || !PURE_SUB_RE.test(kept[offset + k]!)) out.push(word);
    payload = payload || (/^-[A-Za-z]+$/.test(word) && word.slice(1).includes('c'));
  }
  return out;
}

/**
 * SPEC A5 (O33): text with each unquoted `$(...)` (backticks are rewritten to it first; `$((...))` included)
 * replaced by a numbered placeholder, so a substitution never cuts its simple command. The inner texts are
 * appended to subs. An unclosed `$(` and the text after it are left as they are. Mirrors guards._fold.
 */
function fold(text: string, subs: string[]): string {
  const out: string[] = [];
  let q: string | null = null;
  let i = 0;
  const n = text.length;
  while (i < n) {
    const char = text[i]!;
    if (char === '\\' && q !== "'") {
      out.push(text.slice(i, i + 2));
      i += 2;
      continue;
    }
    if (q) {
      if (char === q) q = null;
    } else if (char === '"' || char === "'") {
      q = char;
    } else if (text.startsWith('$(', i)) {
      const end = balancedEnd(text, i + 2);
      if (end < 0) {
        out.push(text.slice(i));
        break;
      }
      out.push(SMARK + String(subs.length) + SMARK);
      subs.push(text.slice(i + 2, end - 1));
      i = end;
      continue;
    }
    out.push(char);
    i += 1;
  }
  return out.join('');
}

/** The segments of text with its substitutions folded (O33), each followed by the segments of the substitutions it holds. Mirrors guards._folded_segments. */
function foldedSegments(text: string, subs: string[], level = 0): string[] {
  if (level >= FOLD_LEVELS) {
    if (fold(text, []) !== text) throw new ValueError('Substitution nesting too deep'); // O34: fail closed.
    return segments(text);
  }
  const result: string[] = [];
  for (const segment of segments(fold(text, subs))) {
    result.push(segment);
    for (const match of segment.matchAll(SUB_RE)) result.push(...foldedSegments(subs[Number(match[1])]!, subs, level + 1));
  }
  return result;
}

/** Classify a shell command (SPEC A5). Mirrors guards.classify_command. */
export function classifyCommand(command: string, depth = 0): Decision {
  if (depth) return classifyInner(command, depth);
  budgetLeft = READING_BUDGET;
  const decision = classifyInner(command, 0);
  return budgetLeft < 0 ? denyOf('Malformed shell quoting', 'malformed') : decision;
}

function classifyInner(command: string, depth: number): Decision {
  if (budgetLeft < 0) return denyOf('Malformed shell quoting', 'malformed'); // The reading budget is spent (FX6).
  if (!(typeof command === 'string') || !strip(command) || codePointLength(command) > 131072 || depth > 8) return denyOf('Invalid or excessively nested command', 'malformed');
  if (command.includes(RMARK) || command.includes(SMARK)) return denyOf('Malformed shell quoting', 'malformed'); // Reserved placeholder characters (R2k minor 4).
  const items: Item[] = [];
  try {
    const [stripped, docs] = stripHeredocs(command);
    const text = tickToDollar(dollarDecode(stripped));
    const subs: string[] = [];
    const parsed = foldedSegments(text, subs).map((segment) => splitWords(segment));
    const render = (word: string): string => word.replace(MARK_RE, '<<HEREDOC').replace(SUB_RE, (_m, k: string) => '$(' + subs[Number(k)]! + ')');
    for (const [rawOriginal, kept] of parsed) {
      const heredoc = rawOriginal.some((word) => word.includes(MARK));
      const original = rawOriginal.map(render);
      const full = kept.map(render);
      const whole = unwrap(full); // Redirections removed (O31, heredocs included).
      const readings = [whole];
      const pure = kept.map((raw) => PURE_SUB_RE.test(raw));
      if (pure.includes(true)) {
        // A pure-substitution word may expand to nothing (O33): classified removed and kept, stricter wins (O34).
        readings.unshift(extra(() => removedReading(full, kept, whole)));
        if (full.slice(0, pure.indexOf(true)).some((word) => WRAPPER_VALUES.has(posixName(word)))) {
          // After a wrapper it may also fill an option value and the next slot (two words).
          readings.push(extra(() => unwrap(full.flatMap((word, k) => (pure[k] ? [word, word] : [word])))));
          // Or fill an option value while a later one expands to nothing (FX4): the words after
          // each pure-substitution word are also read as the command. A suffix that starts with
          // another pure substitution or an option names no new command; past the cap it denies.
          const heads = pure.flatMap((sub, k) => (sub && k + 1 < pure.length && !pure[k + 1] && !full[k + 1]!.startsWith('-') ? [k] : []));
          if (heads.length > SUFFIX_CAP) throw new ValueError('Too many substitution words');
          for (const k of heads) readings.push(extra(() => suffixReading(full.slice(k + 1), kept.slice(k + 1), pure.slice(k + 1))));
        }
      }
      let decision: Decision | null = null;
      for (const words of readings) {
        if (!words.length) continue;
        const found = words[0] === 'eval' && heredoc ? denyOf('Malformed heredoc', 'malformed') : classifySegment(words, depth); // R2b F3 fail-safe.
        decision = decision === null ? found : stricter(decision, found);
      }
      if (decision !== null) items.push([decision, original, true]);
    }
    items.push(...heredocItems(docs, pipelines(text), depth));
    items.push(...streamItems(text, scanOps(text), depth));
    const rawHit = rawScan(text, depth) ?? backtickScan(text, depth);
    if (rawHit) items.push([rawHit, [], false]);
    for (const decision of quotedSubstitutions(text, depth)) items.push([decision, [], true]);
  } catch (e) {
    if (!(e instanceof ValueError)) throw e;
    return denyOf(e.message.startsWith('Heredoc') ? 'Malformed heredoc' : 'Malformed shell quoting', 'malformed');
  }
  for (const [decision] of items) if (decision.action === 'deny' && decision.category !== MULTI) return decision;
  const total = items.filter((item) => item[2]).length;
  const releases = items.filter((item) => item[0].action === 'release');
  if (items.some((item) => item[0].category === MULTI) || releases.length > 1 || (releases.length && total > 1)) return denyOf('Execute release actions separately', MULTI);
  if (releases.length) return { ...releases[0]![0], argv: releases[0]![1].slice() };
  const merged = items.find((item) => item[0].category === MERGED);
  if (merged) {
    // SPEC 5.14 item 2: a merged-delete stands alone and runs plainly, or the whole command denies.
    const subst = (word: string) => word.includes('$(') || word.includes('`');
    const words = merged[1];
    if (items.length > 1) return denyOf(items.some((item) => item[1].some(subst)) ? PLAIN_REASON : SEPARATE_REASON);
    if (!(words[0] === 'git' && !words.some(subst))) return denyOf(PLAIN_REASON);
  }
  for (const kind of ['delete', 'merge']) for (const [decision] of items) if (decision.boundary === kind) return decision;
  let result = dec();
  for (const [decision, original] of items) if (decision.category) result = { ...decision, argv: original.slice() };
  return result;
}

// ---------------------------------------------------------------------------------------------
// Edit protection (hooks.py _protected, A8 and A12). Lexical paths: symlinks are not resolved.

export type EditEnv = { stateDir: string | null | undefined; xdg: string | undefined; home: string | undefined };

function expandUser(path: string, home: string | undefined): string {
  if (home && (path === '~' || path.startsWith('~/'))) return home + path.slice(1);
  return path;
}

function resolveParts(base: string, path: string): string[] {
  const joined = path.startsWith('/') ? path : base + '/' + path;
  const parts: string[] = [];
  for (const part of joined.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') parts.pop();
    else parts.push(part);
  }
  return parts;
}

function startsWithParts(parts: string[], prefix: string[]): boolean {
  return prefix.length <= parts.length && prefix.every((x, i) => parts[i] === x);
}

/** True when an Edit, Write or MultiEdit of `path` (relative to `cwd`) must be denied. */
export function editDenied(path: string | undefined, cwd: string, env: EditEnv): boolean {
  if (!(typeof path === 'string') || path === '') return true;
  const resolved = resolveParts(cwd, path);
  const stateRoot = (root: string[]): boolean | null => {
    if (!startsWithParts(resolved, root)) return null;
    // Coordinator-authored notes at the state root stay writable (A8).
    return !(resolved.length === root.length + 1 && PROTECTED.state_root_exceptions.includes(resolved[resolved.length - 1]!));
  };
  if (env.stateDir) {
    const verdict = stateRoot(resolveParts('/', expandUser(env.stateDir, env.home)));
    if (verdict !== null) return verdict;
  }
  const bases: string[] = [];
  if (env.xdg) bases.push(expandUser(env.xdg, env.home));
  else if (env.home) bases.push(env.home + '/.local/state');
  for (const base of bases) {
    const orchestra = resolveParts('/', base).concat('orchestra');
    if (startsWithParts(resolved, orchestra.concat('mods'))) return true;
    // Without ORCHESTRA_STATE_DIR the run state directory is <base>/orchestra/<24 hex>: protect any such directory.
    if (startsWithParts(resolved, orchestra) && resolved.length > orchestra.length && /^[0-9a-f]{24}$/.test(resolved[orchestra.length]!)) {
      const verdict = stateRoot(orchestra.concat(resolved[orchestra.length]!));
      if (verdict !== null && verdict) return true;
    }
  }
  if (resolved.includes(PROTECTED.component)) return true;
  // Every harness directory in the path counts, not only the first (B-F4).
  for (let i = 0; i < resolved.length; i++) {
    if (!PROTECTED.harness_dirs.includes(resolved[i]!)) continue;
    const tail = resolved.slice(i + 1);
    if (tail.length && (PROTECTED.files.includes(tail[0]!) || (tail[0] === 'agents' && tail.slice(1).some((x) => PROTECTED.agents_prefixes.some((p) => x.startsWith(p)))))) return true;
  }
  return false;
}
