#!/bin/sh
# Hook shells can start with a minimal PATH that lacks Homebrew; search it first.
PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"; export PATH
# Python on Windows defaults to the ANSI code page; the ledger, state and skills are UTF-8.
PYTHONUTF8=1; export PYTHONUTF8
# --cli runs the Orchestra CLI with the same interpreter discovery (used by the mod).
orchestra_script="orchestra_hook.py"
if [ "$1" = "--cli" ]; then
    shift
    orchestra_script="orchestra.py"
fi
orchestra_script="$(dirname "$0")/$orchestra_script"
# Hook shells can resolve Apple's Python 3.9 first. Versioned names are 3.11 or later by
# construction, so the common case starts Python once with no version probe.
for orchestra_python in python3.14 python3.13 python3.12 python3.11; do
    if command -v "$orchestra_python" >/dev/null 2>&1; then
        exec "$orchestra_python" "$orchestra_script" "$@"
    fi
done
# Windows installs expose `python` (and the `py` launcher) rather than python3.
for orchestra_python in python py; do
    if command -v "$orchestra_python" >/dev/null 2>&1 && "$orchestra_python" -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' >/dev/null 2>&1; then
        exec "$orchestra_python" "$orchestra_script" "$@"
    fi
done
# Windows: a per-user or system python.org install may not be on the hook shell PATH (and the
# Microsoft Store stub shadows `python`), so probe the standard install directories directly.
for orchestra_python in "$LOCALAPPDATA"/Programs/Python/Python3*/python.exe "$HOME"/AppData/Local/Programs/Python/Python3*/python.exe "/c/Program Files"/Python3*/python.exe; do
    if [ -x "$orchestra_python" ] && "$orchestra_python" -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' >/dev/null 2>&1; then
        exec "$orchestra_python" "$orchestra_script" "$@"
    fi
done
# Only when no versioned interpreter exists, probe the plain name.
if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' >/dev/null 2>&1; then
    exec python3 "$orchestra_script" "$@"
fi
echo 'Orchestra needs Python 3.11 or later. Install a supported Python runtime.' >&2
exit 2
