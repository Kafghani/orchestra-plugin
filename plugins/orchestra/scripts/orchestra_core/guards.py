"""Bounded shell guard. Not an interpreter, alias or hostile-worker sandbox.

The rules table (config/guard-rules.json) and the corpus (config/guard-corpus.json)
are shared with the TypeScript mod; the corpus is the parity contract.
"""
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex

RULES_PATH = Path(__file__).resolve().parents[2] / 'config/guard-rules.json'
RULES = {key: value for key, value in json.loads(RULES_PATH.read_text(encoding='utf-8')).items()
         if not key.startswith('_')}  # Underscore keys (_doc) are documentation only.
GUARD_DIGEST_FILES = ('config/guard-rules.json', 'scripts/orchestra_core/guards.py',
                      'scripts/orchestra_core/hooks.py', 'hooks/mod/guard.ts')
_WINDOWS_EXECUTABLE = re.compile(r'\.(?:exe|cmd|bat|com)$', re.I)


def _exe_name(word):
    """Command name of an executable word: directory-less, and on Windows spellings (`C:\\...\\git.exe`,
    `GIT.EXE`) the bare lowercase name, so `git.exe reset --hard` is judged exactly like `git reset --hard`."""
    name = PurePosixPath(word.replace('\\', '/')).name
    stripped = _WINDOWS_EXECUTABLE.sub('', name)
    return stripped.lower() if stripped != name else name


_SHELLS = frozenset(RULES['shells'])
_SHELL_VALUE_FLAGS = frozenset(RULES['shell_value_flags'])
_WRAPPER_VALUES = {name: set(values) for name, values in RULES['wrappers'].items()}
_GIT = {key: (set(value) if isinstance(value, list) else value) for key, value in RULES['git'].items()}
# SPEC 5.15: per verb, the guarded long options, most restrictive first. A strict prefix of one reads as that
# option; an exemption (clean --dry-run, restore --staged) is deliberately absent and counts only in full.
_LONG_GUARDED = {
    'add': tuple(RULES['git']['wholesale_add_flags']),
    'reset': ('--hard',),
    'clean': ('--force',),
    'branch': ('--delete', '--force'),
    'checkout': ('--force',),
    'switch': tuple(RULES['git']['switch_force_flags']),
    'restore': ('--force', '--worktree'),  # --worktree negates the --staged exemption
    'push': ('--force', '--force-with-lease', '--force-if-includes', '--mirror') + tuple(RULES['git']['push_multi_flags']),
    'commit': ('--all',) + tuple(RULES['git']['commit_guarded_flags']),
    'tag': ('--delete',),
}
_LONG_VALUE = {'clean': _GIT['clean_value_options'], 'push': _GIT['push_value_options'],
               'commit': _GIT['commit_value_options']}
_RELEASE = RULES['release']
_BOUNDARY = RULES['boundary']
_RUNNERS = RULES['runners']
_ATTACHED = {name: set(values) for name, values in _RUNNERS['attached_value_flags'].items()}
_EXEC_FLAGS = set(_RUNNERS['watch_exec_flags'])
_COMMAND_FLAGS = set(_RUNNERS['flock_command_flags'])
_FIND_EXEC = set(_RUNNERS['find_exec_actions'])
_MULTI = 'releasemulti'  # Decision.category of a release-class segment inside a multi-segment command.


def guard_digest(root=None):
    """SHA-256 over the plugin-root guard files (SPEC 10.3). Per file: relative path, NUL, decimal
    byte length, NUL, bytes. A missing file counts as zero bytes. Computed at runtime, never stored."""
    root = Path(root) if root is not None else Path(__file__).resolve().parents[2]
    digest = hashlib.sha256()
    for rel in GUARD_DIGEST_FILES:
        try:
            data = (root / rel).read_bytes()
        except OSError:
            data = b''
        digest.update(rel.encode() + b'\0' + str(len(data)).encode() + b'\0' + data)
    return digest.hexdigest()


@dataclass(frozen=True)
class Decision:
    action: str = 'allow'
    reason: str = ''
    category: str = ''
    remote: str | None = None
    target: str | None = None
    argv: tuple[str, ...] = ()
    source: str | None = None
    boundary: str | None = None  # 'delete' or 'merge' for class boundary; action stays allow.
    kind: str | None = None  # category merged-delete only: 'local' or 'remote' (SPEC 5.14).
    branch: str | None = None  # category merged-delete only: the one branch the command deletes.

    @property
    def klass(self):
        """The SPEC 5.1 class: allow, deny, release, release-multi or boundary."""
        if self.boundary:
            return 'boundary'
        if self.category == _MULTI:
            return 'release-multi'
        return self.action


def _deny(reason, category='destructiveGit'):
    return Decision('deny', reason, category)


def _split(command):
    # Split operators only outside quotes; quoted messages remain ordinary arguments.
    # Yields (segment, operator that ended it); the last segment has operator ''.
    start, quote, escaped = 0, None, False
    for i, char in enumerate(command):
        if escaped:
            escaped = False
        elif char == '\\' and quote != "'":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == '&' and ((i and command[i - 1] in '<>') or command[i + 1:i + 2] == '>'):
            continue  # Descriptor duplication and Bash's combined redirect are not control operators.
        elif char == '|' and i and command[i - 1] == '>':
            continue
        elif char in ';|&()\n':
            yield command[start:i], char
            start = i + 1
    yield command[start:], ''


def _segments(command):
    for segment, _ in _split(command):
        yield segment


def _pipelines(command):
    """Group non-empty segments joined by a single `|` (or `|&`, or a pipe before a newline)."""
    parts = list(_split(command))
    pipelines, current, k = [], [], 0
    while k < len(parts):
        segment, op = parts[k]
        if segment.strip():
            current.append(segment)
        join = False
        if op == '|' and k + 1 < len(parts):
            following, following_op = parts[k + 1]
            if following.strip():
                join = True
            elif following_op in {'&', '\n'}:
                join = True
                k += 1
        if not join and current:
            pipelines.append(current)
            current = []
        k += 1
    if current:
        pipelines.append(current)
    return pipelines


_WORD_START = ' \t\n;&|()<>'  # A `#` right after one of these (or at the start) begins a comment.
_COMMENT_BLANK = re.compile(r'[\'"\\]')
_KEYWORD_STOP = ' \t\n;&|()<>"\'\\$`#'  # Characters that cannot begin a bare word (case-keyword tracking, O27).
_BARE_WORD = re.compile(r'[^ \t\n;&|()<>"\'\\$`]*')
_WORD_GLUE = frozenset(['"', "'", '\\', '$', '`'])  # A bare word glued to one of these is not a keyword.
_MARK = '\ue000'  # Private-use delimiter for the placeholder that stands in for a heredoc operator.
_MARK_RE = re.compile('<<' + _MARK + r'\d+' + _MARK)
_REDIRECT = re.compile(r'(?:(?:[0-9]*|\{[A-Za-z_][A-Za-z0-9_]*\})(?:<<<|>&|<&|>>|>\||<>|>|<)|&>>?)(.*)')
_RMARK = '\ue001'  # Private-use mark _mark_redirects puts before each unquoted redirection operator.
_REDIRECT_WORD = re.compile(r'(?:[0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\})?(?:<<<|<<-?|<>|<&|<|>>|>&|>\||>|&>>?)')
_REDIRECT_OP = re.compile(r'<<<|<<-?|<>|<&|<|>>|>&|>\||>|&>>?')
_FD_WORD = re.compile(r'[0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\}')
_SHLEX_BLANK = ' \t\r\n'
_SMARK = ''  # Private-use delimiter for the placeholder that stands in for an unquoted `$(...)` (O33).
_SUB_RE = re.compile(_SMARK + r'(\d+)' + _SMARK)
_PURE_SUB = re.compile('(?:' + _SMARK + r'\d+' + _SMARK + ')+')  # A word made only of substitutions.
_HEREDOC = re.compile(r'<<(-?)[ \t]*("[^"\n]*"|\'[^\'\n]*\'|\\?[A-Za-z_0-9][A-Za-z_0-9.\-]*)')


def _shlex_words(text):
    """shlex.split(text, comments=True), except that a `#` begins a comment only at the start of a word:
    a mid-word `#` is literal (SPEC A5, O27 and O33). Word-start comments are cut here and shlex reads
    the rest with comments off."""
    if '#' not in text:
        return _plain_split(text)
    out, quote, start, i, last, n = [], None, True, 0, 0, len(text)
    while i < n:
        char = text[i]
        if char == '\\' and quote != "'":
            i += 2
            start = False
            continue
        if quote:
            quote = None if char == quote else quote
        elif char in "\"'":
            quote = char
        elif char == '#' and start:
            end = text.find('\n', i)
            end = n if end < 0 else end
            out.append(text[last:i])  # A comment: its quotes are literal and it is dropped.
            i = last = end
            continue
        start = not quote and char in _SHLEX_BLANK
        i += 1
    out.append(text[last:])
    return _plain_split(''.join(out))


_PLAIN_WORD = re.compile(r'(?:\\[\s\S]|[^ \t\r\n\\])+')
_PLAIN_ESCAPE = re.compile(r'\\([\s\S])')


_DQ_SPAN = re.compile(r"""\\[\s\S]|'[^']*'?|"(?:[^"\\]|\\[\s\S])*"?""")


def _dq_unescape(match):
    """Inside double quotes a backslash before `$`, a backtick or a newline is removed, as in bash (O34);
    shlex already removes it before `"` and a backslash, and keeps it before any other character."""
    span = match.group()
    if span[0] != '"':
        return span
    return _PLAIN_ESCAPE.sub(lambda m: m.group(1) if m.group(1) in '$`' else '' if m.group(1) == '\n' else m.group(), span)


def _plain_split(text):
    """shlex.split(text) without comments, except for the bash double-quote backslash rule (O34);
    quote-free text takes an equivalent regex path (speed only)."""
    if '"' in text or "'" in text or text.endswith('\\') and _PLAIN_WORD.sub('', text).endswith('\\'):
        if '"' in text and ('\\$' in text or '\\`' in text or '\\\n' in text):
            text = _DQ_SPAN.sub(_dq_unescape, text)
        return shlex.split(text)
    return [_PLAIN_ESCAPE.sub(r'\1', word) for word in _PLAIN_WORD.findall(text)]


def _strip_heredocs(command):
    """Remove heredoc bodies before segmentation. Returns (text, [(body, quoted_delimiter)]).
    Each operator becomes a numbered placeholder so the pipeline that consumes it can be found."""
    out, docs, pending = [], [], []
    quote, escaped, i, n = None, False, 0, len(command)
    tick = False  # Inside a backtick substitution.
    parens, no_start = [], -1  # Open `(` as (kind, index); the index where a `#` cannot start a word.
    cases, start = [], True  # Open `case` as [state, len(parens)]; at a command position (SPEC A5, O27).
    while i < n:
        char = command[i]
        if escaped:
            escaped = False
            # SPEC A5 (O27): a character after an unescaped backslash is not a word start. A backslash-newline
            # pair is deleted, so the character after it is a word start exactly when the backslash was one.
            glued = char != '\n' or i - 1 == no_start or (i > 1 and command[i - 2] not in _WORD_START)
            no_start = i + 1 if glued else -1
            start = start and not glued
        elif char == '\\' and quote != "'":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote, start = char, False
        elif char == '(':
            top = cases[-1] if cases and cases[-1][1] == len(parens) else None
            if not (top and top[0] == 'pattern'):  # In a case pattern the opening parenthesis is optional.
                sub = i and (command[i - 1] in '$<>=' or (command[i - 1] == '(' and parens and parens[-1] == ('sub', i - 1)))
                parens.append(('sub' if sub else 'plain', i))  # `=(` opens an array assignment, inside a word.
            start = True
        elif char == ')':
            top = cases[-1] if cases and cases[-1][1] == len(parens) else None
            if top and top[0] == 'pattern':
                top[0] = 'body'  # The `)` of a case pattern closes no group, so it cannot pop an enclosing `$(`.
            elif parens and parens.pop()[0] == 'sub':
                no_start = i + 1  # The `)` of `$(`, `$((`, `<(` or `a=(` ends part of a word, not a command.
            start = True
        elif char == '`':
            tick = not tick
            start = tick
        elif char in ';&|':
            top = cases[-1] if cases and cases[-1][1] == len(parens) else None
            if top and top[0] == 'body' and command.startswith((';;', ';&'), i):
                top[0] = 'pattern'
            start = True
        elif char == '#' and i != no_start and (i == 0 or command[i - 1] in _WORD_START or (tick and command[i - 1] == '`')):
            # SPEC A5 (O27): a comment runs to the newline. Its quotes and backslashes are literal, so they
            # are blanked: no later scanner can read them as opening a quote or escaping the newline.
            # Inside a backtick substitution it ends at the closing backtick, which stays visible.
            end = command.find('\n', i)
            end = n if end < 0 else end
            if tick:
                stop = i
                while stop < end and (command[stop] != '`' or _backslashed(command, stop)):
                    stop += 1
                end = stop
            out.append(_COMMENT_BLANK.sub(' ', command[i:end]))
            i = end
            continue
        elif char == '<' and command.startswith('<<', i) and not command.startswith('<<<', i) and (i == 0 or command[i - 1] != '<'):
            match = _HEREDOC.match(command, i)
            # An all-digit word is shell arithmetic (1 << 2), not a heredoc.
            if match and not match.group(2).isdigit():
                word = match.group(2)
                quoted = word[0] in '\'"\\'
                word = word[1:-1] if word[0] in '\'"' else word.removeprefix('\\')
                pending.append((word, match.group(1) == '-', quoted))
                out.append('<<' + _MARK + str(len(docs) + len(pending) - 1) + _MARK)
                i = match.end()
                continue
        elif char not in _KEYWORD_STOP and i != no_start and (i == 0 or command[i - 1] in _WORD_START):
            end = _BARE_WORD.match(command, i).end()
            word = command[i:end] if command[end:end + 1] not in _WORD_GLUE else ''
            top = cases[-1] if cases and cases[-1][1] == len(parens) else None
            if word == 'in' and top and top[0] == 'head':
                top[0] = 'pattern'
            elif word == 'case' and start:
                cases.append(['head', len(parens)])
            elif word == 'esac' and start and top and top[0] != 'head':
                cases.pop()
            start = word in _CASE_PREV
            out.append(command[i:end])
            i = end
            continue
        elif char == '\n':
            out.append(char)
            i += 1
            start = True
            for word, strip, quoted in pending:
                body, found = [], False
                while i < n:
                    end = command.find('\n', i)
                    line = command[i:end if end >= 0 else n]
                    i = end + 1 if end >= 0 else n
                    if (line.lstrip('\t') if strip else line) == word:
                        found = True
                        break
                    body.append(line)
                if not found:
                    raise ValueError('Heredoc has no terminator')
                docs.append(('\n'.join(body), quoted))
            pending = []
            continue
        elif char not in ' \t':
            start = False
        out.append(char)
        i += 1
    if pending:
        raise ValueError('Heredoc has no terminator')
    return ''.join(out), docs


_ASSIGNMENT = re.compile(r'[A-Za-z_][A-Za-z0-9_]*=.*')


def _eat_options(wrapper, words):
    """Consume a wrapper's leading options. Returns (remaining words, found) where found says whether
    a watch exec flag was seen and holds the flock shell string, if any."""
    found = {'exec': False, 'command': None}
    values, attached = _WRAPPER_VALUES[wrapper], _ATTACHED.get(wrapper, ())
    while words and (words[0].startswith('-') or _ASSIGNMENT.fullmatch(words[0])):
        option = words.pop(0)
        if option == '--':
            break
        value = None
        value_option = option
        if option.startswith('--') and '=' in option:
            value_option, value = option.split('=', 1)
        elif option.startswith('-') and not option.startswith('--'):
            # A value-taking short flag ends the cluster; its suffix is its value.
            for i, char in enumerate(option[1:], 1):
                if '-' + char in attached:
                    break  # Its value, if any, is attached and ends the cluster.
                if '-' + char in values:
                    value_option = '-' + char
                    value = option[i + 1:] or None
                    break
                if wrapper == 'watch' and '-' + char in _EXEC_FLAGS:
                    found['exec'] = True
        if wrapper == 'watch' and option in _EXEC_FLAGS:
            found['exec'] = True
        if value_option in values:
            if value is None:
                if not words:
                    raise ValueError('Missing wrapper option value')
                value = words.pop(0)
            if wrapper == 'env' and value_option in {'-S', '--split-string'}:
                words = _plain_split(value) + words
                break
            if wrapper == 'flock' and value_option in _COMMAND_FLAGS:
                found['command'] = value
    return words, found


_RESERVED = frozenset(['{', '}', '!', 'if', 'then', 'elif', 'else', 'fi', 'while', 'until', 'do', 'done', 'esac'])


def _unwrap(words):
    while words:
        name = _exe_name(words[0])
        redirect = _REDIRECT.fullmatch(words[0])
        if words[0] == 'case':
            return []  # A case header (`case WORD in`) runs nothing; its patterns are not commands.
        if words[0] == 'function' and len(words) > 1:
            words = words[2:]  # `function NAME [()] {`: the name is not a command (SPEC A5, O20).
            if words and words[0] == '()':
                words = words[1:]
        elif words[0] == 'coproc':
            words = words[1:]  # `coproc [NAME] {` or `coproc COMMAND` (SPEC A5, O20).
            if len(words) > 1 and words[1] == '{':
                words = words[1:]
        elif words[0] in _RESERVED:
            words = words[1:]  # SPEC A5 (O17): reserved words and group openers precede the real command.
        elif redirect:
            words = words[1:] if redirect.group(1) else words[2:]
        elif _ASSIGNMENT.fullmatch(words[0]):
            words = words[1:]
        elif name in _WRAPPER_VALUES:
            wrapper = name
            words, found = _eat_options(wrapper, words[1:])
            if wrapper == 'timeout' and words:
                words.pop(0)
            elif wrapper == 'watch' and not found['exec'] and words:
                words = ['sh', '-c', ' '.join(words)]  # Without -x, watch runs its words as a shell string.
            elif wrapper == 'flock':
                if found['command'] is None and words:
                    words, found = _eat_options(wrapper, words[1:])  # The lock file, then later options.
                if found['command'] is not None:
                    words = ['sh', '-c', found['command']]
        else:
            return words
    return words


def _shell_payload_rest(words):
    """Return (the literal -c argument, the words after it), ignoring long flags and option values."""
    i = 1
    while i < len(words):
        token = words[i]
        if token == '--' or not token.startswith(('-', '+')):
            return None
        if token in _SHELL_VALUE_FLAGS:
            i += 2
            continue
        if re.fullmatch(r'-[A-Za-z]+', token) and 'c' in token[1:]:
            return (words[i + 1], words[i + 2:]) if i + 1 < len(words) else ('', [])
        i += 1
    return None


def _shell_payload(words):
    found = _shell_payload_rest(words)
    return found[0] if found else None


def _boundary(kind, reason):
    return Decision('allow', reason, 'boundary', boundary=kind)


_MERGED = 'merged-delete'
_BRANCH_NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9._/+-]*')
_REMOTE_NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9._-]*')
_PLAIN_REASON = 'Branch deletion must run plainly in the session repository'
_SEPARATE_REASON = 'Execute branch deletions separately'


def _merged_delete(verb, options, flags, short, words, redirected, raw):
    """SPEC 5.14 item 1: the exact merged-delete shapes, else None. `options` is what precedes `--`
    with abbreviated long options spelled in full (5.15). A shape has one branch positional and no other option."""
    if len(raw) != len(options):
        return None  # A value option and its value were read away: not a bare delete.
    positional = [x for x in options if not x.startswith('-')]
    shorts = set(short)
    flags = {x for x in flags if x.startswith('--')}
    if verb == 'branch':
        if not (flags <= {'--delete', '--force'} and shorts <= {'D', 'd', 'f'} and len(positional) == 1):
            return None
        if not (('D' in shorts or 'd' in shorts or '--delete' in flags) and
                ('D' in shorts or 'f' in shorts or '--force' in flags)):
            return None
        remote, branch, kind = None, positional[0], 'local'
    elif verb == 'push':
        if not (flags == {'--delete'} or (not flags and shorts == {'d'})) or shorts - {'d'} or len(positional) != 2:
            return None
        remote, branch, kind = positional[0], positional[1], 'remote'
        if not _REMOTE_NAME.fullmatch(remote):
            return None
    else:
        return None
    if not _BRANCH_NAME.fullmatch(branch):
        return None
    if redirected:  # A git global option precedes the verb.
        return _deny(_PLAIN_REASON)
    return Decision('allow', 'Deletion is a boundary action', _MERGED, remote, None, tuple(words),
                    boundary='delete', kind=kind, branch=branch)


def _long_prefix(verb, token, guarded):
    """The guarded long option of `verb` that `token` abbreviates (its part before `=` is a non-empty strict
    prefix of it; the first match wins, so list guarded options most restrictive first), else None."""
    name = token.split('=', 1)[0]
    if verb not in _LONG_GUARDED or len(name) < 3 or not name.startswith('--'):
        return None
    return next((option for option in guarded if len(name) < len(option) and option.startswith(name)), None)


def _value_width(token, value_options):
    """Words a value option takes: 2 for a detached value, 1 for an abbreviated long option with its value attached."""
    if token in value_options:
        return 2
    name = token.split('=', 1)[0]
    if len(name) > 2 and name.startswith('--') and any(len(name) < len(x) and x.startswith(name) for x in value_options):
        return 1 if '=' in token else 2
    return 0


def _read_long_options(verb, options):
    """The options of a guarded verb with value options and their values dropped and abbreviated guarded options spelled in full."""
    read, i = [], 0
    value_options = _LONG_VALUE.get(verb, ())
    while i < len(options):
        full = _long_prefix(verb, options[i], _LONG_GUARDED[verb])
        width = 0 if full else _value_width(options[i], value_options)
        if width:
            i += width
            continue
        read.append(full or options[i])
        i += 1
    return read


def _raw_ref_delete(args):
    """`git update-ref` that can delete: -d (alone or in a cluster), a long option that abbreviates --delete or
    --stdin (its input can delete), or an all-zero new value. The value of -m is a message. Doubt reads as a delete."""
    i = 0
    while i < len(args):
        x = args[i]
        i += 1
        if x == '-m':
            i += 1
        elif x.startswith('--'):
            name = x.split('=', 1)[0]
            if len(name) > 2 and ('--delete'.startswith(name) or '--stdin'.startswith(name)):
                return True
        elif x.startswith('-') and not x.startswith('-m') and 'd' in x[1:]:
            return True
        elif re.fullmatch(r'0{40}|0{64}', x):
            return True
    return False


def _git(words):
    args = words[1:]
    changed_repo = False
    plain = not (args and args[0].startswith('-'))  # Any global option can redirect a merged-delete (R2): fail closed.
    while args and args[0].startswith('-'):
        opt = args.pop(0)
        if opt in _GIT['global_value_options']:
            if not args:
                return _deny('Malformed Git global option', 'malformed')
            args.pop(0)
        if opt.startswith('-C') or opt.startswith(('--git-dir', '--work-tree')):
            changed_repo = True
    if not args:
        return Decision()
    verb, args = args[0], args[1:]
    options = args[:args.index('--')] if '--' in args else args
    if verb in _LONG_GUARDED:
        options = _read_long_options(verb, options)
    flags = [x for x in options if x.startswith('-')]
    short = ''.join(x[1:] for x in flags if not x.startswith('--'))
    if verb == 'stash':
        return _deny('Git stash shares state across worktrees', 'stash')
    if verb == 'update-ref' and _raw_ref_delete(args):
        return _deny('Raw ref deletion is not allowed; use git branch -d')
    if verb == 'reset' and any(x == '--hard' or x.startswith('--hard=') for x in flags):
        return _deny('Hard reset discards work')
    if verb == 'clean' and ('f' in short or '--force' in flags) and not ('n' in short or '--dry-run' in flags):
        return _deny('Forced clean discards files')
    if verb == 'branch' and ('D' in short or (('d' in short or '--delete' in flags) and ('f' in short or '--force' in flags))):
        merged = '--' not in args and _merged_delete(verb, options, flags, short, words, not plain, args)
        if merged:
            return merged
        return _deny('Forced branch deletion discards refs')
    wholesale = '.' in args or ':/' in args
    if verb == 'checkout' and (wholesale or '--force' in flags or 'f' in short):
        return _deny('Wholesale restore discards work')
    if verb == 'switch' and ('f' in short or any(x in flags for x in _GIT['switch_force_flags'])):
        return _deny('Wholesale restore discards work')
    if verb == 'restore':
        staged_only = ('--staged' in flags or 'S' in short) and not ('--worktree' in flags or 'W' in short)
        if '--force' in flags or (wholesale and not staged_only):
            return _deny('Wholesale restore discards work')
    if verb == 'add' and (any(x in flags for x in _GIT['wholesale_add_flags']) or 'A' in short or 'u' in short or
                          any(x in _GIT['wholesale_add_pathspecs'] for x in args)):
        return _deny('Stage explicit paths only', 'wholesaleStage')
    if verb == 'commit':
        # A message beginning with a dash is still a message.
        opts = [x for x in options if not (x.startswith(('--message=', '--file=')) or x.startswith('-m'))]
        if '--all' in opts or any(x.startswith('-') and not x.startswith('--') and 'a' in x[1:] for x in opts):
            return _deny('Commit explicit staged paths only', 'wholesaleStage')
        if any(x in _GIT['commit_guarded_flags'] for x in opts):
            return _deny('Amend rewrites history')
    if verb == 'push':
        if any(x.startswith('--force') or x == '--mirror' for x in flags) or 'f' in short or any(x.startswith('+') for x in args):
            return _deny('Force push rewrites remote history')
        dry_run = '--dry-run' in flags or 'n' in short
        positional = [x for x in options if not x.startswith('-')]
        if (('--delete' in flags or 'd' in short) and not dry_run and '--' not in args and
                (merged := _merged_delete(verb, options, flags, short, words, not plain, args))):
            return merged
        if len(positional) > 2 or any(x in flags for x in _GIT['push_multi_flags']) or 'd' in short:
            return _deny('Push needs one explicit remote and refspec', 'release')
        remote, target = (positional + [None, None])[:2]
        source = target.split(':', 1)[0] if target else None
        if target:
            if target.startswith(':') or '*' in target or target.count(':') > 1:
                return _deny('Push needs one non-deleting refspec', 'release')
            target = target.split(':')[-1].removeprefix('refs/heads/')
        if changed_repo:
            remote = target = source = None  # Native cwd cannot attest a different Git repository.
        if dry_run:
            return Decision('allow', 'Dry-run push does not release', 'gitpush', remote, target, tuple(words), source)
        return Decision('release', 'Push needs an exact current release permit', 'gitpush', remote, target, tuple(words), source)
    if (verb == 'rm' or (verb == 'branch' and ('d' in short or '--delete' in flags)) or
            (verb == 'tag' and ('d' in short or '--delete' in flags)) or
            (verb == 'worktree' and args and args[0] in _GIT['worktree_delete'])):
        return _boundary('delete', 'Deletion is a boundary action')
    if verb in _GIT['boundary_merge_verbs']:
        return _boundary('merge', 'Local merge is a boundary action')
    return Decision()


def _is_release(name, words):
    return ((name == 'gh' and words[1:3] in _RELEASE['gh']) or
            (name == 'az' and (all(x in words for x in _RELEASE['az_requires']) or
                               (words[1:4] == _RELEASE['az_pr_update']['prefix'] and _RELEASE['az_pr_update']['word'] in words))) or
            (name in _RELEASE['package_tools'] and _RELEASE['package_verb'] in words[1:]) or
            (name in _RELEASE['deploy_tools'] and any(x in words[1:] for x in _RELEASE['deploy_words'])))


def _find_exec(words, depth):
    """Decisions for the commands a `find` runs through -exec, -execdir, -ok and -okdir."""
    decisions, i = [], 1
    while i < len(words):
        if words[i] in _FIND_EXEC:
            j, command = i + 1, []
            while j < len(words) and not (words[j] == ';' or (words[j] == '+' and words[j - 1] == '{}')):
                command.append(words[j])
                j += 1
            command = _unwrap(command)
            if command:
                decisions.append(_classify_segment(command, depth))
            i = j
        i += 1
    return decisions


def _first_by_severity(decisions, base):
    """The deny, else release, else boundary decision among the runner's commands, else the find itself."""
    for test in (lambda d: d.action == 'deny' and d.category != _MULTI, lambda d: d.action == 'release',
                 lambda d: bool(d.boundary)):
        for decision in decisions:
            if test(decision):
                return decision
    return base


def _classify_segment(words, depth):
    name = _exe_name(words[0])
    if name in _SHELLS:
        found = _shell_payload_rest(words)
        if found is None:
            return Decision()
        payload, rest = found
        decision = classify_command(payload, depth + 1)
        if _hard_deny(decision):
            return decision
        # Rule (6b): substitutions in the payload and the arguments after it.
        return _scan_substitutions(payload, depth) or _scan_pieces(rest, depth) or decision
    if name == 'eval':
        text = ' '.join(words[1:])
        decision = classify_command(text, depth + 1)
        if _hard_deny(decision):
            return decision
        return _scan_substitutions(text, depth) or decision
    if name == 'git':
        return _git(words)
    if _is_release(name, words):
        return Decision('release', 'Provider release needs structured authorization', 'providerrelease', argv=tuple(words))
    base = Decision()
    if (name in _BOUNDARY['delete_commands'] or (name == 'find' and _BOUNDARY['find_delete_flag'] in words[1:]) or
            (name == 'gh' and words[1:3] in _BOUNDARY['gh'])):
        base = _boundary('delete', 'Deletion is a boundary action')
    if name == 'find':
        return _first_by_severity(_find_exec(words, depth), base)
    return base


def _hard_deny(decision):
    """An always-deny verdict: not a malformed payload and not a release-class multi-segment verdict."""
    return decision.action == 'deny' and decision.category not in {'malformed', _MULTI}


def _scan_lines(body, depth, keep_release=False):
    """Classify each line of a body on its own (continuations joined). A line that fails to parse
    is skipped, never denied as malformed. Returns the first always-deny verdict, else (if asked)
    the first release-class verdict, else allow."""
    release = Decision()
    for line in body.replace('\\\n', '').split('\n'):
        if not line.strip():
            continue
        decision = classify_command(line, depth + 1)
        if _hard_deny(decision):
            return decision
        if keep_release and decision.action == 'release' and release.action == 'allow':
            release = decision
    return release


def _substitutions(body):
    """Command substitutions in an unquoted heredoc body. Quote characters are literal there, so the
    scan is quote-blind; an escaped dollar or backtick and `$((` arithmetic are skipped."""
    found, i, n = [], 0, len(body)
    while i < n:
        char = body[i]
        if char == '\\':
            i += 2
        elif body.startswith('$((', i):
            i += 3
        elif body.startswith('$(', i):
            depth, j = 1, i + 2
            while j < n and depth:
                if body[j] == '\\':
                    j += 1
                elif body[j] == '(':
                    depth += 1
                elif body[j] == ')':
                    depth -= 1
                j += 1
            content = body[i + 2:j - 1 if depth == 0 else j]
            found.append(content)
            found.extend(_substitutions(content))
            i = j
        elif char == '`':
            j = i + 1
            while j < n and body[j] != '`':
                j += 2 if body[j] == '\\' else 1
            content = body[i + 1:j]
            found.append(content)
            found.extend(_substitutions(content))
            i = j + 1
        else:
            i += 1
    return found


def _mark_redirects(segment):
    """SPEC A5 (O31): put a blank and _RMARK before each redirection operator outside quotes (before its
    descriptor prefix when a number or `{name}` is the whole word before it), so shlex starts a word there
    that reads as a redirection. Quotes, escapes and `#` comments follow _shlex_words (a `#` starts a
    comment only at the start of a word, O33); a `${...}` expansion is copied whole, nested braces included."""
    if '<' not in segment and '>' not in segment:
        return segment
    if _RMARK in segment:
        raise ValueError('Reserved character in command')
    out, quote, i, n = [], None, 0, len(segment)
    start, bare = 0, True  # Where the current word starts in out; whether it holds only bare characters.
    blank = True  # The previous character is a blank (or there is none): a `#` here starts a comment.
    here = 0  # 2 right after a `<<<`, 1 inside its operand word: a here-string operand is not word-split.
    while i < n:
        char = segment[i]
        at_blank, blank = blank, False
        if quote:
            if char == quote:
                quote = None
            elif char == '\\' and quote == '"':
                out.append(segment[i:i + 2])
                i += 2
                continue
        elif char in _SHLEX_BLANK:
            out.append(char)
            i += 1
            start, bare, blank = len(out), True, True
            here = 2 if here == 2 else 0
            continue
        elif char in "\"'":
            quote, bare = char, False
        elif char == '\\':
            out.append(segment[i:i + 2])
            i += 2
            bare, here = False, 1 if here else 0
            continue
        elif char == '#' and at_blank:
            end = segment.find('\n', i)
            end = n if end < 0 else end
            out.append(segment[i:end])
            i = end
            continue
        elif segment.startswith('${', i):
            end = _brace_end(segment, i)
            out.append(_escape_blanks(segment[i:end]) if here else segment[i:end])
            here = 1 if here else 0
            i = end
            bare = False
            continue
        elif char in '<>&':
            match = _REDIRECT_OP.match(segment, i)
            if match:
                if bare and _FD_WORD.fullmatch(''.join(out[start:])):
                    out.insert(start, ' ' + _RMARK)
                else:
                    out.append(' ' + _RMARK)
                out.append(match.group())
                i = match.end()
                if i < n and segment[i] not in _SHLEX_BLANK:
                    out.append(_RMARK)  # A second mark right after the operator says its operand is glued.
                start, bare = len(out), False  # A glued operand is never a descriptor prefix.
                here = 2 if match.group() == '<<<' else 0
                continue
        here = 1 if here else 0
        out.append(char)
        i += 1
    return ''.join(out)


def _brace_end(text, i):
    """Index just past the `}` that closes the `${` at text[i], counting nested `${` (R2k minor 5); the
    end of text when it is never closed."""
    depth, n = 0, len(text)
    while i < n:
        if text.startswith('${', i):
            depth += 1
            i += 2
            continue
        if text[i] == '}':
            depth -= 1
            if not depth:
                return i + 1
        i += 1
    return n


def _escape_blanks(text):
    """Escape the blanks of text that stand outside quotes, so shlex keeps it one word."""
    out, quote = [], None
    for char in text:
        if quote:
            quote = None if char == quote else quote
        elif char in "\"'":
            quote = char
        elif char in _SHLEX_BLANK:
            out.append('\\')
        out.append(char)
    return ''.join(out)


def _words(segment):
    """SPEC A5 (O31): the shlex words of a segment (comments dropped) as (all words, the words without
    redirections, the here-string operands). A redirection is an unquoted operator, with or without a
    descriptor prefix, together with its operand word, glued or spaced, wherever it stands. A heredoc
    operator is one too (O33): its placeholder is dropped from the words without redirections."""
    marked_text = _mark_redirects(segment)
    words = _shlex_words(marked_text)
    if _RMARK not in marked_text:
        return words, words.copy(), []
    original, kept, operands, skip = [], [], [], None
    for word in words:
        marked = word.startswith(_RMARK)
        plain = word.replace(_RMARK, '')
        original.append(plain)
        if skip:
            if skip == '<<<':
                operands.append(plain)
            skip = None
            continue
        match = _REDIRECT_WORD.match(plain) if marked else None
        if not match:
            kept.append(plain)
            continue
        here = '<<<' if match.group().endswith('<<<') else '>'
        if word.startswith(_RMARK, 1 + match.end()):  # Glued operand (even an empty one, as in `<<<""`).
            if here == '<<<':
                operands.append(plain[match.end():])
        else:
            skip = here
    return original, kept, operands


def _command_words(segment, operands=None):
    """The command words of a segment: redirections dropped, wrappers unwrapped. Here-string operands
    are added to operands when given (rule 6b still scans them as producer text)."""
    if '<' not in segment and '>' not in segment:
        return _unwrap(_shlex_words(segment))
    _, words, here = _words(segment)
    if operands is not None:
        operands.extend(here)
    return _unwrap(words)


def _consumer_mode(segment, allow_eval=True):
    """How a pipeline segment reads a heredoc: 'c' (shell with -c), 'script' (shell without -c,
    source, `.` or eval) or None. Wrappers (xargs included) are unwrapped first."""
    kept = _command_words(segment)
    if not kept:
        return None
    if _exe_name(kept[0]) in _SHELLS:
        return 'c' if _shell_payload(kept) is not None else 'script'
    if kept[0] in {'.', 'source'} or (allow_eval and kept[0] == 'eval'):
        return 'script'
    return None


def _body_decision(body, modes, depth):
    """Classify text a shell consumer reads, as SPEC A5 rule (1): under -c an unparsable body is ignored."""
    if not body.strip():
        return Decision()
    decision = classify_command(body, depth + 1)
    if 'script' not in modes and decision.category == 'malformed':
        decision = _scan_lines(body, depth, keep_release=True)
    return decision


_ANSI = {'a': '\a', 'b': '\b', 'e': '\x1b', 'E': '\x1b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t',
         'v': '\v', '\\': '\\', "'": "'", '"': '"', '?': '?'}
_ANSI_NUMERIC = (('x', re.compile(r'[0-9A-Fa-f]{1,2}'), 16), ('u', re.compile(r'[0-9A-Fa-f]{1,4}'), 16),
                 ('U', re.compile(r'[0-9A-Fa-f]{1,8}'), 16))
_ANSI_OCTAL = re.compile(r'[0-7]{1,3}')


def _ansi_escape(text, i):
    """Decode the escape that starts at text[i] (a backslash). Returns (decoded text, next index)."""
    char = text[i + 1]
    if char in _ANSI:
        return _ANSI[char], i + 2
    try:
        for letter, pattern, base in _ANSI_NUMERIC:
            match = pattern.match(text, i + 2) if char == letter else None
            if match:
                return chr(int(match.group(), base)), match.end()
        match = _ANSI_OCTAL.match(text, i + 1)
        if match:
            return chr(int(match.group(), 8)), match.end()
    except (ValueError, OverflowError):
        pass
    return '\\' + char, i + 2


def _dollar_decode(text):
    """Quote-aware: replace each unquoted $'...' word part by its decoded, re-quoted text."""
    if "$'" not in text:
        return text
    out, quote, escaped, i, n = [], None, False, 0, len(text)
    while i < n:
        char = text[i]
        if escaped:
            escaped = False
        elif char == '\\' and quote != "'":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == '$' and text.startswith("$'", i):
            j, buf = i + 2, []
            while j < n and text[j] != "'":
                if text[j] == '\\' and j + 1 < n:
                    decoded, j = _ansi_escape(text, j)
                    buf.append(decoded)
                else:
                    buf.append(text[j])
                    j += 1
            if j >= n:
                out.append(text[i:])
                break
            out.append(shlex.quote(''.join(buf)))
            i = j + 1
            continue
        out.append(char)
        i += 1
    return ''.join(out)


def _read_balanced(text, i):
    """Index just past the `)` that closes a `(` already consumed before text[i] (quote-aware)."""
    end = _balanced_end(text, i)
    return len(text) if end < 0 else end


_CASE_PREV = frozenset(['if', 'then', 'elif', 'else', 'while', 'until', 'do', '!', '{', 'time'])


def _skip_heredoc_bodies(text, i, pending):
    """Index just past the bodies of the heredocs in pending, which start at text[i]. A body that never
    ends is not skipped (the operator may not have been a heredoc, as in `$((1 << 2))`)."""
    j, n = i, len(text)
    for dash, delimiter in pending:
        while True:
            if j >= n:
                return i
            end = text.find('\n', j)
            line = text[j:n if end < 0 else end]
            j = n if end < 0 else end + 1
            if (line.lstrip('\t') if dash else line) == delimiter:
                break
    return j


def _balanced_end(text, i):
    """Like _read_balanced, but -1 when the `(` is never closed. Besides quotes it skips `$'...'` strings
    (escaped quotes included) and `#` comments, and does not count the `)` that ends a `case` pattern
    (SPEC A5, O17)."""
    depth, quote, n = 1, None, len(text)
    cases = []  # One [state, depth] per open `case`; state is 'head', 'pattern' or 'body'.
    pending = []  # Heredoc (dash, delimiter) pairs whose bodies start after the next newline (SPEC A5, O20).
    start = True  # At a command position, where `case` is a keyword.
    while i < n:
        char = text[i]
        if char == '\\' and quote != "'":
            i += 2
            start = False
            continue
        if quote:
            if char == quote:
                quote = None
            i += 1
            continue
        top = cases[-1] if cases and cases[-1][1] == depth else None
        if char in "\"'":
            quote, start = char, False
        elif text.startswith("$'", i):
            i += 2
            while i < n and text[i] != "'":
                i += 2 if text[i] == '\\' else 1
            start = False
        elif char == '#' and (i == 0 or text[i - 1] in ' \t\n;&|()'):
            end = text.find('\n', i)
            i = n if end < 0 else end
            continue
        elif char in ' \t':
            pass
        elif char == '(':
            if not (top and top[0] == 'pattern'):  # In a case pattern the opening parenthesis is optional.
                depth += 1
            start = True
        elif char == ')':
            if top and top[0] == 'pattern':
                top[0] = 'body'
            else:
                depth -= 1
                if depth == 0:
                    return i + 1
            start = True
        elif char == '<' and text.startswith('<<', i) and not text.startswith('<<<', i) and (
                i == 0 or text[i - 1] != '<') and _HEREDOC.match(text, i):
            found = _HEREDOC.match(text, i)
            pending.append((bool(found.group(1)), found.group(2).strip('"\'\\')))
            i = found.end()
            start = False
            continue
        elif char in ';&|\n':
            if top and top[0] == 'body' and text[i:i + 2] in {';;', ';&'}:
                top[0] = 'pattern'
                i += 1
            elif char == '\n' and pending:
                i = _skip_heredoc_bodies(text, i + 1, pending)
                pending = []
                start = True
                continue
            start = True
        elif char not in '$`<>':
            end = i
            while end < n and text[end] not in ' \t\n;&|()<>"\'\\$`':
                end += 1
            word = text[i:end] if text[end:end + 1] not in {'"', "'", '\\', '$', '`'} else ''
            if word == 'in' and top and top[0] == 'head':
                top[0] = 'pattern'
            elif word == 'case' and start:
                cases.append(['head', depth])
            elif word == 'esac' and start and top and top[0] != 'head':
                cases.pop()
            start = word in _CASE_PREV
            i = end
            continue
        else:
            start = False
        i += 1
    return -1


def _skip_double(text, i):
    """Index just past the double quote that closes a string opened before text[i]."""
    n = len(text)
    while i < n:
        if text[i] == '\\':
            i += 2
        elif text[i] == '"':
            return i + 1
        elif text.startswith('$(', i):
            i = _read_balanced(text, i + 2)
        elif text[i] == '`':
            close = text.find('`', i + 1)
            i = n if close < 0 else close + 1
        else:
            i += 1
    return n


def _read_word(text, i):
    """Index just past the shell word that starts at text[i]."""
    n = len(text)
    while i < n:
        char = text[i]
        if char in ' \t\n;|&<>()':
            break
        if char == '\\':
            i += 2
        elif char == "'":
            close = text.find("'", i + 1)
            i = n if close < 0 else close + 1
        elif char == '"':
            i = _skip_double(text, i + 1)
        elif text.startswith('$(', i):
            i = _read_balanced(text, i + 2)
        elif char == '`':
            close = text.find('`', i + 1)
            i = n if close < 0 else close + 1
        else:
            i += 1
    return min(i, n)


def _scan_ops(text):
    """Quote-aware pre-pass (SPEC A5 rule 6) that finds here-strings and process substitutions without
    changing the text. Returns ([(command text around a here-string, its word)], [(text before a
    `<(`, its inner text)]). The command text is the segment the operator sits in, as `_split` cuts it."""
    herestrings, procsubs, pending, parens = [], [], [], []
    start, quote, escaped, n = 0, None, False, len(text)
    for i, char in enumerate(text):
        if escaped:
            escaped = False
        elif char == '\\' and quote != "'":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == '<' and text.startswith('<<<', i) and (i == 0 or text[i - 1] != '<'):
            j = i + 3
            while j < n and text[j] in ' \t':
                j += 1
            end = _read_word(text, j)
            pending.append((text[start:i], text[j:end], end))
        elif char == '<' and text.startswith('<(', i) and (i == 0 or text[i - 1] not in '<>'):
            close = _read_balanced(text, i + 2)
            inner = text[i + 2:close - 1] if text[close - 1:close] == ')' else text[i + 2:close]
            procsubs.append((text[start:i], inner))
        elif char == '&' and ((i and text[i - 1] in '<>') or text[i + 1:i + 2] == '>'):
            continue
        elif char == '|' and i and text[i - 1] == '>':
            continue
        elif char == '(' and i and text[i - 1] == '$' and not _backslashed(text, i - 1):
            # O34: a `$(` substitution does not cut the command around it (`bash $(true) <<< ...`);
            # its inner text is a command of its own.
            parens.append((start, pending))
            pending, start = [], i + 1
        elif char in ';|&()\n':
            herestrings.extend((before + ' ' + (text[end:i] if i >= end else ''), word) for before, word, end in pending)
            pending = []
            start = i + 1
            if char == '(':
                parens.append(None)
            elif char == ')' and parens and parens[-1] is not None:
                start, pending = parens.pop()
            elif char == ')' and parens:
                parens.pop()
    herestrings.extend((before + ' ' + text[end:], word) for before, word, end in pending)
    return herestrings, procsubs


def _is_arithmetic(text, i):
    """True when text[i:] starts `$((` that is arithmetic. `$((cmd) )` is a command substitution whose
    first `)` closes the inner group before a matching `))` (SPEC A5, O17). Never closed counts as arithmetic."""
    if not text.startswith('$((', i):
        return False
    inner = _balanced_end(text, i + 3)
    return inner < 0 or text[inner:inner + 1] == ')'


def _raw_substitutions(text, ticks=None):
    """Quote-aware scan of raw text (SPEC A5 rule 6b) for the `$(...)` and backtick substitutions the
    outer shell runs: unquoted or inside double quotes, never inside single quotes. Nested quotes and
    substitutions are tracked, so the text is not cut the way shlex or _split cut it. Returns
    (contents of the outermost substitutions, False when one is never closed). `$((` is arithmetic
    unless its first `)` closes before a matching `))`."""
    found, closed, i, n, quote = [], True, 0, len(text), False

    def command(i):  # text[i] starts `$(` or a backtick; returns the index to resume from.
        nonlocal closed
        if ticks is not None:
            ticks.append((text[i] == '`', i, quote))
        if text[i] == '`':
            j = i + 1
            while j < n and text[j] != '`':
                j += 2 if text[j] == '\\' else 1
            closed = closed and j < n
            found.append(re.sub(r'\\([`\\$])', r'\1', text[i + 1:min(j, n)]))
            return j + 1
        end = _balanced_end(text, i + 2)
        closed = closed and end >= 0
        found.append(text[i + 2:n if end < 0 else end - 1])
        return n if end < 0 else end

    while i < n:
        char = text[i]
        if char == '\\':
            i += 2
        elif quote:
            if char == '"':
                quote = False
                i += 1
            elif char == '`' or (text.startswith('$(', i) and not _is_arithmetic(text, i)):
                i = command(i)
            else:
                i += 1
        elif char == "'":
            close = text.find("'", i + 1)
            i = n if close < 0 else close + 1
        elif char == '"':
            quote = True
            i += 1
        elif _is_arithmetic(text, i):
            i += 3
        elif char == '`' or text.startswith('$(', i):
            i = command(i)
        else:
            i += 1
    return found, closed


def _tick_to_dollar(text):
    """SPEC A5 (O25): rewrite each closed, unquoted backtick substitution (never inside quotes) as the `$(...)` form of the same
    content, so it keeps the same class in the same position. Inside double quotes a backtick stays one
    (_backtick_scan classifies it, with its escaped inner backticks unescaped). Inside backticks the shell reads backslash-backtick,
    backslash-backslash and backslash-dollar as the plain character, so an escaped backtick there is a
    nested substitution, rewritten in turn. A top-level escaped backtick stays a literal."""
    out, i, n, quote = [], 0, len(text), False
    while i < n:
        char = text[i]
        if char == '\\':
            out.append(text[i:i + 2])
            i += 2
        elif char == '`' and not quote:
            j = i + 1
            while j < n and text[j] != '`':
                j += 2 if text[j] == '\\' else 1
            if j >= n:  # Never closed: leave it for the malformed checks.
                out.append(text[i:])
                break
            content = re.sub(r'\\([`\\$])', r'\1', text[i + 1:j])
            out.append('$(' + _tick_to_dollar(content) + ')')
            i = j + 1
        elif char == "'" and not quote:
            close = text.find("'", i + 1)
            end = n if close < 0 else close + 1
            out.append(text[i:end])
            i = end
        else:
            if char == '"':
                quote = not quote
            out.append(char)
            i += 1
    return ''.join(out)


_ASSIGN_PREFIX = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\+?=')
_SKIP_WORDS = 32  # Words of one segment kept to find its command name; a longer all-skip prefix counts as command position.


def _skips(word):
    """True when a leading word is skipped before the command name (SPEC A5): reserved words, `time`,
    `function`/`coproc` headers, `case`, redirects, assignments and the wrappers table."""
    return word == 'function' or not _unwrap([word])


_HERE_OPERATOR = re.compile(r'[0-9]*<<<?')


def _backslashed(text, i):
    """True when the character at i follows an odd run of backslashes: it is escaped, so it is no word start."""
    j = i
    while j and text[j - 1] == '\\':
        j -= 1
    return (i - j) % 2 == 1


def _command_positions(text, ats):
    """SPEC A5 (O20, O23, O28): for each index in ats (ascending, each the start of a substitution), True
    when the substitution is at command position: after a separator or group opener, with only the words
    the command-name rule skips since (see _skips; wrapper options and values included). One forward,
    quote-aware pass: separators inside quotes or after a backslash do not count, and a literal `{` or `)`
    argument is not a separator. A case pattern is not a command position; the body of a case arm is."""
    result, limit, n = [], len(ats), len(text)
    seg, settled, overflow = [], False, False  # Bare words of the segment, whether its command name came, too many words.
    stack, cases = [], []  # Open `(` groups; open `case` states ('head', 'pattern', 'body').
    t = i = 0
    no_start = -1  # no_start: the index just after the `)` of a `<(` or `>(`, where a `#` is no word start.

    def here():
        if cases and cases[-1] != 'body':
            return False
        if settled:
            return False
        if overflow:
            return True
        try:
            return not _unwrap(seg.copy())
        except ValueError:
            return False

    def word(bare):
        nonlocal seg, settled, overflow
        at_command = here()
        if bare == 'case' and at_command:
            cases.append('head')
        elif bare == 'in' and cases and cases[-1] == 'head':
            cases[-1] = 'pattern'
        elif bare == 'esac' and cases and cases[-1] in ('body', 'pattern') and not seg and not settled:
            cases.pop()
        if settled or overflow:
            return
        if not seg and not _skips(bare):
            settled = True
        elif len(seg) < _SKIP_WORDS:
            seg.append(bare)
        else:
            overflow = True

    def reset():
        nonlocal seg, settled, overflow
        seg, settled, overflow = [], False, False

    while i < n and t < limit:
        char = text[i]
        if char in ' \t':
            i += 1
            continue
        token = 'word'
        end = i + 1
        if char == '#' and i != no_start and (i == 0 or (text[i - 1] in _WORD_START and not _backslashed(text, i))):
            found = text.find('\n', i)
            end, token = (n if found < 0 else found), 'comment'
        elif char == '\n':
            token = 'sep'
        elif char == ';':
            token = 'sep'
            if text.startswith(';;&', i):
                end = i + 3
            elif text[i:i + 2] in (';;', ';&'):
                end = i + 2
            if cases and cases[-1] == 'body' and end > i + 1:
                cases[-1] = 'pattern'
        elif char == '|':
            token = 'pipe'
        elif char == '&' and text[i + 1:i + 2] != '>':
            token = 'sep'
        elif char in '<>&' and text.startswith('(', i + 1) and char != '&':
            token = 'skip'  # `<(` or `>(`: the `(` after it opens the process substitution.
        elif char in '<>&':
            while end < n and text[end] in '<>':
                end += 1
            if text[end:end + 1] == '&' and text[end - 1] in '<>' or text[end:end + 1] == '|' and text[end - 1] == '>':
                end += 1
            token = 'redirect'
        elif char == '(':
            token = 'open'
        elif char == ')':
            token = 'close'
        else:
            end = max(_read_word(text, i), i + 1)
            if (text[i:end].isdigit() or _FD_WORD.fullmatch(text[i:end])) and text[end:end + 1] in ('<', '>') and text[end:end + 2] != '<(' and text[end:end + 2] != '>(':
                while end < n and text[end] in '<>':
                    end += 1
                if text[end:end + 1] == '&' or (text[end:end + 1] == '|' and text[end - 1] == '>'):
                    end += 1
                token = 'redirect'
        if token == 'redirect' and end < n and text[end] not in ' \t\n;&|()<>' and _HERE_OPERATOR.fullmatch(text[i:end]):
            end = max(_read_word(text, end), end)  # SPEC A5 (O28): `<<<x` and `<<EOF` glue their operand, as the command-name rule reads them.
        while t < limit and ats[t] < end:
            if ats[t] <= i:
                result.append(here())
            elif token == 'word':
                match = _ASSIGN_PREFIX.match(text, i)  # A substitution inside a `NAME=` word keeps the position before it.
                result.append(here() if match and ats[t] >= match.end() else False)
            else:
                result.append(here())
            t += 1
        raw = text[i:end]
        if token == 'sep' or (token == 'pipe' and not (cases and cases[-1] == 'pattern')):
            reset()
        elif token == 'open':
            if not (cases and cases[-1] == 'pattern'):
                stack.append(('proc' if i and text[i - 1] in '<>' else 'group', seg, settled, overflow))
                reset()
        elif token == 'close':
            if cases and cases[-1] == 'pattern':
                cases[-1] = 'body'
                reset()
            elif stack:
                kind, seg, settled, overflow = stack.pop()
                if kind == 'proc':
                    no_start = end
                    word('<()')
                else:
                    seg, settled, overflow = [], True, False
            else:
                reset()
        elif token in ('word', 'redirect'):
            try:
                parts = _plain_split(raw)
            except ValueError:
                parts = []
            word(parts[0] if len(parts) == 1 else raw)
        i = end
    while t < limit:
        result.append(here())
        t += 1
    return result


def _backtick_scan(text, depth):
    """SPEC A5 (O20, O23): a backtick substitution anywhere in the text is a command, as `$(...)` is.
    The `$(...)` ones are classified by the segment split, except at command position, where (like a
    backtick there) the substitution's output runs, so its text is producer text."""
    if depth > 8:
        return None
    ticks = []  # One (is a backtick, start index, inside double quotes) per substitution.
    contents = _raw_substitutions(text, ticks)[0]
    for content, (tick, _, _), at_command in zip(contents, ticks, _command_positions(text, [at for _, at, _ in ticks])):
        if at_command:
            hit = _scan_text(content, depth + 1, as_command=True)  # At command position its output runs.
        elif not tick:
            hit = _backtick_scan(content, depth + 1)
        else:
            hit = classify_command(content, depth + 1)
        if hit and _hard_deny(hit):
            return hit
    return None


def _quoted_substitutions(text, depth):
    """SPEC A5 (O26): a `$(...)` inside a double-quoted word keeps the full class of its content, as the
    unquoted one does (the segment split cuts that one out; here the quoted word stays whole). Returns the
    decision of each such substitution, found at any depth of unquoted substitutions. A double-quoted
    backtick is unchanged: _backtick_scan classifies it. Nesting above depth 8 raises ValueError, which
    classify_command turns into the malformed deny (accepted limit)."""
    if '$(' not in text or '"' not in text:
        return []
    if depth > 8:
        raise ValueError('Quoted substitution nested too deep')  # Fail-safe: a malformed deny, never an empty result.
    ticks = []
    found = []
    for content, (tick, _, quoted) in zip(_raw_substitutions(text, ticks)[0], ticks):
        if tick:
            continue
        if quoted:
            found.append(classify_command(content, depth + 1))
        else:
            found.extend(_quoted_substitutions(content, depth + 1))
    return found


def _raw_commands(text):
    """Split raw text into commands of raw words, cutting on `; | & ( )` and newlines outside quotes and
    outside substitutions (unlike _split). A word keeps its quotes. A descriptor number glues to its
    redirection. Returns a list of word lists."""
    commands, words, i, n = [], [], 0, len(text)
    while i < n:
        char = text[i]
        if char in ' \t':
            i += 1
        elif char == '#':
            end = text.find('\n', i)
            i = n if end < 0 else end
        elif char in ';|&()\n':
            glued = (char == '&' and ((i and text[i - 1] in '<>') or text[i + 1:i + 2] == '>')) or (
                char == '|' and i and text[i - 1] == '>')
            if not glued:
                commands.append(words)
                words = []
            i += 1
        elif char in '<>':
            end = i
            while end < n and text[end] in '<>':
                end += 1
            words.append(text[i:end])
            i = end
        else:
            end = max(_read_word(text, i), i + 1)
            if (text[i:end].isdigit() or _FD_WORD.fullmatch(text[i:end])) and text[end:end + 1] in {'<', '>'}:
                while end < n and text[end] in '<>':
                    end += 1
            words.append(text[i:end])
            i = end
    commands.append(words)
    return [command for command in commands if command]


def _raw_scan(text, depth):
    """Rule (6b) for a `-c` payload or `eval` argument that shlex or _split would cut mid-substitution:
    find the substitutions in the raw command text and scan each as producer text. An unbalanced
    substitution there denies as malformed (fail-safe). Returns a Decision or None."""
    if depth > 8:
        return None
    for raws in _raw_commands(text):
        values = []
        for raw in raws:
            try:
                parts = _plain_split(raw)
            except ValueError:
                parts = []
            values.append(parts[0] if len(parts) == 1 else raw)
        kept, skip = [], False
        for raw, value in zip(raws, values):  # SPEC A5 (O31): unquoted redirections and their operands.
            redirect = None if skip else _REDIRECT.fullmatch(raw)
            if not skip and not redirect:
                kept.append(value)
            skip = bool(redirect) and not redirect.group(1)
        try:
            words = _unwrap(kept)
        except ValueError:
            continue
        if not words:
            continue
        name = _exe_name(words[0])
        if not (name == 'eval' or (name in _SHELLS and _shell_payload_rest(words) is not None)):
            continue
        for raw in raws:
            contents, closed = _raw_substitutions(raw)
            if not closed:
                return _deny('Unbalanced command substitution', 'malformed')
            for content in contents:
                hit = _scan_text(content, depth + 1, as_command=True)
                if hit:
                    return hit
    return None


def _only_redirects(segment):
    """True when the segment is blank or only redirections (`2>/dev/null`, `>&1`, `</dev/stdin`)."""
    try:
        words = _plain_split(segment)
    except ValueError:
        return False
    i = 0
    while i < len(words):
        redirect = _REDIRECT.fullmatch(words[i])
        if not redirect:
            return False
        i += 1 if redirect.group(1) else 2
    return i <= len(words)


def _pipe_joins(parts, k):
    """True when the `|` that ends parts[k] continues the pipeline (`|&` and a following group included)."""
    following = parts[k + 1] if k + 1 < len(parts) else None
    return following is not None and bool(following[0].strip() or following[1] in {'&', '\n', '('})


def _chains(text):
    """Pipelines as flat lists of segments, with `(...)` and `{ ...; }` groups transparent to a pipe on
    either side. Separate from `_pipelines`, which rules (1) to (3) keep using unchanged."""
    parts = list(_split(text))
    chains, cur, frames = [], [], []
    state = {'carry': False, 'pipe_before': False, 'flushes': 0}

    def flush():
        nonlocal cur
        if cur:
            for _, seen, feeder in reversed(frames):
                if feeder and state['flushes'] != seen:  # Later commands of a piped group read the same pipe.
                    cur = feeder + cur
                    break
            chains.append(cur)
            state['flushes'] += 1
        cur = []

    def pipe_follows(k):  # A part holding only redirects and a continuing `|` comes right after parts[k] (O20).
        return (k + 1 < len(parts) and _only_redirects(parts[k + 1][0]) and parts[k + 1][1] == '|'
                and _pipe_joins(parts, k + 1))

    for k, (seg, op) in enumerate(parts):
        s = seg.strip()
        if state['carry'] and not s and op in {'&', '\n'}:
            state['carry'] = False
            continue
        state['carry'] = False
        if k and parts[k - 1][1] == ')' and s and pipe_follows(k - 1):
            s = ''  # The redirects of a group that a pipe follows are not a command.
        if re.match(r'\{(\s|$)', s):
            s = s[1:].strip()
            frames.append(([], state['flushes'], list(cur) if state['pipe_before'] else None))
        closes = s == '}'
        if closes:
            s = ''
        if s:
            cur.append(s)
            for members, _, _ in frames:
                members.append(s)
        if closes and frames:
            members, seen, feeder = frames.pop()
            if state['flushes'] != seen:
                cur = (feeder or []) + list(members)  # The producers that fed the group reach what follows it (O17).
        if op == '(':
            if not state['pipe_before']:
                flush()
            frames.append(([], state['flushes'], list(cur) if state['pipe_before'] else None))
        elif op == ')':
            if frames:
                members, seen, feeder = frames.pop()
                if state['flushes'] != seen and pipe_follows(k):
                    cur = (feeder or []) + list(members)  # The group's producers feed the next stage too (O17).
                elif feeder and state['flushes'] != seen and cur:
                    cur = feeder + cur  # The group's last command still reads the pipe that fed it.
            if not pipe_follows(k):
                flush()
        elif op == '|' and _pipe_joins(parts, k):
            state['carry'] = not parts[k + 1][0].strip() and parts[k + 1][1] in {'&', '\n'}
            state['pipe_before'] = True
            continue
        else:
            flush()
        state['pipe_before'] = False if op != '(' else state['pipe_before']
    flush()
    return chains


def _scan_substitutions(text, depth):
    """Rule (6b): each `$(...)` and backtick substitution in text is producer text and a command."""
    if depth > 8:
        return None
    for content in _substitutions(text):
        hit = _scan_text(content, depth + 1, as_command=True)
        if hit:
            return hit
    return None


def _scan_pieces(args, depth):
    """Rule (6b) pieces of an argument list: each word and the words joined, split on newlines, on a
    literal backslash-n and on `;`, each classified; plus the substitutions inside each word."""
    if depth > 8 or not args:
        return None
    for word in args:
        hit = _scan_substitutions(word, depth)
        if hit:
            return hit
    for text in [*args, ' '.join(args)]:
        for piece in re.split(r'\n|\\n|;', text):
            if piece.strip():
                decision = classify_command(piece.strip(), depth + 1)
                if _hard_deny(decision):
                    return decision
    return None


def _scan_text(text, depth, as_command=False):
    """Rule (6b): an always-deny verdict hidden in producer text. A piece that fails to parse is skipped."""
    if depth > 8:
        return None
    text = _dollar_decode(text)
    if as_command:
        decision = classify_command(text, depth + 1)
        if _hard_deny(decision):
            return decision
    for content in _raw_substitutions(text)[0]:
        hit = _scan_text(content, depth + 1, as_command=True)
        if hit:
            return hit
    for segment in _segments(text):
        operands = []
        try:
            words = _command_words(segment, operands)
        except ValueError:
            continue
        hit = _scan_pieces(words[1:] + operands, depth)
        if hit:
            return hit
    return None


def _stream_items(text, ops, depth):
    """SPEC A5 rule (6): script text fed to a shell without a heredoc. Returns (decision, argv, counts) items."""
    items = []
    herestrings, procsubs = ops

    def consumer(command_text, allow_eval):
        try:
            return _consumer_mode(command_text, allow_eval), tuple(_command_words(command_text))
        except ValueError:
            return None, ()

    for command_text, word in herestrings:  # (6a)
        mode, argv = consumer(command_text, False)
        if mode is None:
            continue
        try:
            value = ' '.join(_plain_split(word))
        except ValueError:
            continue
        items.append((_body_decision(value, {mode}, depth), argv, False))
        hit = _scan_substitutions(value, depth)
        if hit:
            items.append((hit, argv, False))
    for before, inner in procsubs:  # (6b) process substitution given to, or redirected into, a shell
        mode, argv = consumer(before, False)
        if mode is not None:
            hit = _scan_text(inner, depth, as_command=True)
            if hit:
                items.append((hit, argv, False))
    for chain in _chains(text):  # (6b) pipeline with a later shell consumer
        for index, segment in enumerate(chain):
            mode, argv = consumer(segment, True)
            if mode is None:
                continue
            for producer in chain[:index]:
                hit = _scan_text(producer, depth)
                if hit:
                    items.append((hit, argv, False))
            break
    return items


def _heredoc_items(docs, pipelines, depth):
    """SPEC A5 rules (1) to (5): extra (decision, argv, counts) items for each heredoc body."""
    items = []
    for index, (body, quoted) in enumerate(docs):
        marker = '<<' + _MARK + str(index) + _MARK
        modes, argv = set(), ()
        for pipeline in pipelines:
            where = next((i for i, segment in enumerate(pipeline) if marker in segment), None)
            if where is not None:
                argv = tuple(_MARK_RE.sub('<<HEREDOC', word) for word in _shlex_words(pipeline[where]))
                # Rules (1) to (3): the consumer and every later command of its pipeline.
                modes = {_consumer_mode(segment) for segment in pipeline[where:]}
                break
        if 'script' in modes or 'c' in modes:
            # Under -c the body is not what the shell runs, so an unparsable body is ignored.
            items.append((_body_decision(body, modes, depth), argv, False))
        if not quoted:  # Rule (4): every class but malformed is kept and counts as a segment, as for O26.
            for content in _substitutions(body):
                decision = classify_command(content, depth + 1)
                if decision.klass != 'allow' and decision.category != 'malformed':
                    items.append((decision, argv, True))
        decision = _scan_lines(body, depth)  # Rule (5)
        if decision.action == 'deny':
            items.append((decision, argv, False))
    return items


_FOLD_LEVELS = 16  # Substitution nesting levels folded (O33); a substitution nested deeper denies (O34).
_SUFFIX_CAP = 32  # Command readings after pure-substitution words in one segment (FX4); more denies.
_READING_BUDGET = 1024  # Extra readings (O33 removed, wrapper twin, FX4 suffix) per call, nested shells included (FX6).
_BUDGET = {'left': _READING_BUDGET}
_RANK = {'deny': 4, 'release-multi': 3, 'release': 2, 'boundary': 1}


def _stricter(first, second):
    """The stricter of two verdicts (O34): deny > release-multi > release > boundary > allow; first on a tie."""
    return second if _RANK.get(second.klass, 0) > _RANK.get(first.klass, 0) else first


def _extra(build):
    """One extra reading of a segment (FX6). It spends the per-call budget; past it the command denies as
    malformed. A reading the words cannot form (a wrapper option left without its value) is dropped, as
    the shell could not run that expansion: it is no reason to deny the command."""
    _BUDGET['left'] -= 1
    if _BUDGET['left'] < 0:
        raise ValueError('Too many command readings')
    try:
        return build()
    except ValueError:
        return []


def _removed_reading(full, kept, whole):
    """O33 and O34: the words of a segment with its pure-substitution words removed, then unwrapped.
    eval arguments keep them; a shell keeps them only at and after its -c payload."""
    words = _unwrap([word for word, raw in zip(full, kept) if not _PURE_SUB.fullmatch(raw)])
    if not words or not whole or whole[0] != words[0]:
        return words
    if words[0] == 'eval' or _exe_name(words[0]) not in _SHELLS:
        return whole if words[0] == 'eval' else words
    if full[len(full) - len(whole):] != whole:
        return whole  # Rewritten by a runner (watch, flock -c): no substitution word stands before options.
    out, payload = [whole[0]], False
    for word, raw in zip(whole[1:], kept[len(kept) - len(whole) + 1:]):
        if payload or not _PURE_SUB.fullmatch(raw):
            out.append(word)
        payload = payload or bool(re.fullmatch(r'-[A-Za-z]+', word) and 'c' in word[1:])
    return out


def _suffix_reading(full, kept, pure):
    """FX4: the words after a pure-substitution word, read as the command."""
    rest = _unwrap(full)
    return _removed_reading(full, kept, rest) if any(pure) else rest


def _fold(text, subs):
    """SPEC A5 (O33): text with each unquoted `$(...)` (backticks are rewritten to it first; `$((...))`
    included) replaced by a numbered placeholder, so a substitution never cuts its simple command. The
    inner texts are appended to subs. An unclosed `$(` and the text after it are left as they are."""
    out, quote, i, n = [], None, 0, len(text)
    while i < n:
        char = text[i]
        if char == '\\' and quote != "'":
            out.append(text[i:i + 2])
            i += 2
            continue
        if quote:
            quote = None if char == quote else quote
        elif char in "\"'":
            quote = char
        elif text.startswith('$(', i):
            end = _balanced_end(text, i + 2)
            if end < 0:
                out.append(text[i:])
                break
            out.append(_SMARK + str(len(subs)) + _SMARK)
            subs.append(text[i + 2:end - 1])
            i = end
            continue
        out.append(char)
        i += 1
    return ''.join(out)


def _folded_segments(text, subs, level=0):
    """The segments of text with its substitutions folded (O33), each followed by the segments of the
    substitutions it holds, so their content is still classified."""
    if level >= _FOLD_LEVELS:
        if _fold(text, []) != text:  # O34: a substitution nested deeper than the cap denies as malformed.
            raise ValueError('Substitution nesting too deep')
        return list(_segments(text))
    result = []
    for segment in _segments(_fold(text, subs)):
        result.append(segment)
        for match in _SUB_RE.finditer(segment):
            result.extend(_folded_segments(subs[int(match.group(1))], subs, level + 1))
    return result


_PYTHON = re.compile(r'python(\d+(\.\d+)*)?')
_TEST_SCRIPT = re.compile(r'(?:run|run-script)')


def _positionals(words):
    return [word for word in words if not word.startswith(('-', '+'))]


def _is_test_probe(module, rest):
    """A single-test target: unittest `pkg.mod.Class.test_x` (a test method under a capitalized class name), pytest
    `file::test_x`. Anything else, a dotted package or module such as `src.app.tests` included, runs a suite."""
    targets = _positionals(rest)
    if len(targets) != 1:
        return False
    if module == 'unittest':
        parts = targets[0].split('.')
        return len(parts) >= 3 and parts[-1].startswith('test') and parts[-2][:1].isupper() and all(parts)
    return '::' in targets[0] and bool(targets[0].rsplit('::', 1)[1]) and not targets[0].startswith('::')


def _words_run_suite(words, depth):
    if not words or depth > 4:
        return False
    exe, rest = _exe_name(words[0]), words[1:]
    args = _positionals(rest)
    if exe in _SHELLS:
        payload = _shell_payload(words)
        return payload is not None and runs_test_suite(payload, depth + 1)
    if exe in ('uv', 'poetry', 'pipenv') and 'run' in rest:
        return _words_run_suite(rest[rest.index('run') + 1:], depth + 1)
    if exe in ('pytest', 'py.test'):
        return not _is_test_probe('pytest', rest)
    if exe == 'coverage' and 'run' in rest:  # `coverage run [options] -m pytest` reads like python
        return _words_run_suite(['python'] + rest[rest.index('run') + 1:], depth + 1)
    if _PYTHON.fullmatch(exe):
        if '-m' in rest[:-1]:
            module, after = rest[rest.index('-m') + 1], rest[rest.index('-m') + 2:]
        else:  # the joined form `-munittest`
            joined = [k for k, word in enumerate(rest) if word.startswith('-m') and len(word) > 2]
            if not joined:
                return False
            module, after = rest[joined[0]][2:], rest[joined[0] + 1:]
        return module in ('pytest', 'unittest') and not _is_test_probe(module, after)
    if exe in ('npm', 'pnpm', 'yarn'):
        tests = ('test', 't') if exe != 'yarn' else ('test',)  # npm and pnpm alias `t` to `test`
        return bool(args) and (args[0] in tests or (_TEST_SCRIPT.fullmatch(args[0]) and len(args) > 1 and args[1].startswith('test')))
    if exe == 'npx':
        return bool(args) and (args[0] in ('vitest', 'jest') or (args[0] == 'playwright' and args[1:2] == ['test']))
    if exe in ('go', 'cargo'):
        return args[:1] == ['test']
    return exe == 'make' and 'test' in args


def runs_test_suite(command, _depth=0):
    """True when a shell command runs a whole test suite (pytest, unittest, npm test, go test and the like).
    A single-test probe is not a suite. Best effort and bounded like classify_command, not a sandbox."""
    if not isinstance(command, str) or not command.strip() or len(command) > 131072:
        return False
    try:
        return any(_words_run_suite(_command_words(segment), _depth) for segment in _segments(command))
    except ValueError:
        return False


def classify_command(command: str, _depth=0) -> Decision:
    if _depth:
        return _classify_command(command, _depth)
    _BUDGET['left'] = _READING_BUDGET
    decision = _classify_command(command, 0)
    return _deny('Malformed shell quoting', 'malformed') if _BUDGET['left'] < 0 else decision


def _classify_command(command, _depth):
    if _BUDGET['left'] < 0:
        return _deny('Malformed shell quoting', 'malformed')  # The reading budget is spent (FX6).
    if not isinstance(command, str) or not command.strip() or len(command) > 131072 or _depth > 8:
        return _deny('Invalid or excessively nested command', 'malformed')
    if _RMARK in command or _SMARK in command:  # Reserved placeholder characters (R2k minor 4).
        return _deny('Malformed shell quoting', 'malformed')
    try:
        text, docs = _strip_heredocs(command)
        text = _tick_to_dollar(_dollar_decode(text))
        subs = []
        segments = [_words(segment)[:2] for segment in _folded_segments(text, subs)]

        def render(word):  # The placeholders of a word back to their text.
            return _SUB_RE.sub(lambda m: '$(' + subs[int(m.group(1))] + ')', _MARK_RE.sub('<<HEREDOC', word))

        items = []  # (decision, original words, counts as a segment)
        for original, kept in segments:
            heredoc = any(_MARK in word for word in original)
            original = [render(word) for word in original]
            full = [render(word) for word in kept]
            whole = _unwrap(full)  # Redirections removed (O31, heredocs included).
            readings = [whole]
            pure = [bool(_PURE_SUB.fullmatch(raw)) for raw in kept]
            if any(pure):
                # A word made only of substitutions may expand to nothing (O33): the segment is classified
                # with it removed and with it kept, and the stricter verdict wins (O34).
                readings.insert(0, _extra(lambda: _removed_reading(full, kept, whole)))
                if any(_exe_name(word) in _WRAPPER_VALUES for word in full[:pure.index(True)]):
                    # After a wrapper it may also fill an option value and the next slot (two words).
                    readings.append(_extra(lambda: _unwrap([twin for word, sub in zip(full, pure) for twin in [word] * (1 + sub)])))
                    # Or fill an option value while a later one expands to nothing (FX4): the words after
                    # each pure-substitution word are also read as the command. A suffix that starts with
                    # another pure substitution or an option names no new command; past the cap it denies.
                    heads = [k for k, sub in enumerate(pure[:-1]) if sub and not pure[k + 1] and full[k + 1][:1] != '-']
                    if len(heads) > _SUFFIX_CAP:
                        raise ValueError('Too many substitution words')
                    for k in heads:
                        readings.append(_extra(lambda: _suffix_reading(full[k + 1:], kept[k + 1:], pure[k + 1:])))
            decision = None
            for words in readings:
                if not words:
                    continue
                if words[0] == 'eval' and heredoc:
                    found = _deny('Malformed heredoc', 'malformed')  # R2b F3 fail-safe.
                else:
                    found = _classify_segment(words, _depth)
                decision = found if decision is None else _stricter(decision, found)
            if decision is not None:
                items.append((decision, original, True))
        items.extend(_heredoc_items(docs, _pipelines(text), _depth))
        items.extend(_stream_items(text, _scan_ops(text), _depth))
        raw_hit = _raw_scan(text, _depth) or _backtick_scan(text, _depth)
        if raw_hit:
            items.append((raw_hit, (), False))
        items.extend((decision, (), True) for decision in _quoted_substitutions(text, _depth))
    except ValueError as exc:
        return _deny('Malformed heredoc' if str(exc).startswith('Heredoc') else 'Malformed shell quoting', 'malformed')
    for decision, _, _ in items:
        if decision.action == 'deny' and decision.category != _MULTI:
            return decision
    total = sum(1 for _, _, counts in items if counts)
    releases = [(d, o) for d, o, _ in items if d.action == 'release']
    if any(d.category == _MULTI for d, _, _ in items) or len(releases) > 1 or (releases and total > 1):
        return _deny('Execute release actions separately', _MULTI)
    if releases:
        # A prior cd/env or nested shell must not inherit a plain Git permit.
        return replace(releases[0][0], argv=tuple(releases[0][1]))
    merged = [o for d, o, _ in items if d.category == _MERGED]
    if merged:
        # SPEC 5.14 item 2: a merged-delete stands alone and runs plainly, or the whole command denies.
        words = list(merged[0])
        plain = words[:1] == ['git'] and not any('$(' in word or '`' in word for word in words)
        if len(items) > 1:
            substituted = any('$(' in word or '`' in word for _, o, _ in items for word in o)
            return _deny(_PLAIN_REASON if substituted else _SEPARATE_REASON)
        if not plain:
            return _deny(_PLAIN_REASON)
    for kind in ('delete', 'merge'):
        for decision, _, _ in items:
            if decision.boundary == kind:
                return decision
    result = Decision()
    for decision, original, _ in items:
        if decision.category:
            result = replace(decision, argv=tuple(original))
    return result
