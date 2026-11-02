#!/usr/bin/env bash
# Keystone GUI end-to-end tests (TESTING.md: E2E through GTK accessibility with Dogtail).
#
# Usage: keystone-gui/tests/e2e/run.sh [test_file.py ...]   (default: every test_*.py)
#
# 1. Builds the debug `keystone` binary (simulator build), the `e2e_prepare` helper
#    and the plaintext-key scanner (SEC-04), which every flow test runs over the whole
#    temporary folder.
# 2. Re-runs itself under `xvfb-run` (headless X server) and `dbus-run-session` (a
#    private session bus, started inside the X session so the AT-SPI registry can
#    synthesise keyboard events), with accessibility switched on.
# 3. Runs each test in its own Python process. Every file a test writes goes to one
#    `mktemp -d` folder that is deleted at the end (TESTING.md TEST-12); test data is
#    synthetic (TEST-11).
#
# Exit code 0 only when every test passed. A test never "skips": it passes or fails.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"

if [[ -z "${KEYSTONE_E2E_INNER:-}" ]]; then
  for tool in xvfb-run dbus-run-session gsettings; do
    command -v "$tool" >/dev/null || { echo "E2E: missing tool: $tool" >&2; exit 2; }
  done
  (cd "$ROOT" && cargo build --quiet -p keystone-gui --bin keystone --example e2e_prepare \
    && cargo build --quiet -p keystone-testkit --example scan_plaintext_keys)
  export KEYSTONE_BIN="$ROOT/target/debug/keystone"
  export KEYSTONE_PREPARE="$ROOT/target/debug/examples/e2e_prepare"
  export KEYSTONE_SCANNER="$ROOT/target/debug/examples/scan_plaintext_keys"
  export KEYSTONE_WORDLIST="$ROOT/keystone-core/src/passphrase/eff_large_wordlist.txt"
  export KEYSTONE_E2E_INNER=1
  exec xvfb-run -a -s "-screen 0 1280x1024x24 -nolisten tcp" \
    dbus-run-session -- "${BASH_SOURCE[0]}" "$@"
fi

TMP="$(mktemp -d -t keystone-e2e.XXXXXXXX)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT
export KEYSTONE_E2E_TMP="$TMP"

# Keep every settings, cache and runtime file inside the temporary folder.
export XDG_CONFIG_HOME="$TMP/config" XDG_CACHE_HOME="$TMP/cache" XDG_DATA_HOME="$TMP/data"
export XDG_RUNTIME_DIR="$TMP/runtime"
mkdir -p "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_DATA_HOME" "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"
export GSETTINGS_BACKEND=keyfile GTK_A11Y=atspi NO_AT_BRIDGE=0
# No bytecode caches in the source tree: tests write only to the temporary folder.
export PYTHONDONTWRITEBYTECODE=1
unset WAYLAND_DISPLAY
gsettings set org.gnome.desktop.interface toolkit-accessibility true

# A Python whose GObject bindings and Dogtail import cleanly.
PY=""
for candidate in python3 python3.12 python3.13 python3.11; do
  if command -v "$candidate" >/dev/null 2>&1 \
    && "$candidate" -c 'import gi, dogtail' >/dev/null 2>&1; then
    PY="$candidate"
    break
  fi
done
if [[ -z "$PY" ]]; then
  echo "E2E: no Python with python3-gi and python3-dogtail found" >&2
  exit 2
fi

if [[ $# -gt 0 ]]; then
  tests=("$@")
else
  mapfile -t tests < <(cd "$HERE" && ls test_*.py | sort)
fi

passed=()
failed=()
for test in "${tests[@]}"; do
  name="$(basename "$test" .py)"
  log="$TMP/$name.log"
  echo "=== $name"
  if (cd "$HERE" && "$PY" "$HERE/$(basename "$test")") >"$log" 2>&1; then
    passed+=("$name")
    echo "PASS $name"
  else
    failed+=("$name")
    echo "FAIL $name"
    sed 's/^/    /' "$log" | tail -n 60
  fi
done

echo
echo "E2E summary: ${#passed[@]} passed, ${#failed[@]} failed"
for name in "${passed[@]}"; do echo "  PASS $name"; done
for name in "${failed[@]}"; do echo "  FAIL $name"; done
[[ ${#failed[@]} -eq 0 ]]
