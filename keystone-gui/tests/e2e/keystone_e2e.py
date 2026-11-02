"""Shared helpers for the Keystone Dogtail E2E tests.

The tests drive Keystone only through the accessibility tree and the keyboard
(NFR-04): widgets are found by accessible role and name, focus is moved with Tab,
buttons and check boxes are pressed with Space, and text is typed. Results are read
from labels, which always start with a status word ("OK:", "Note:", "Warning:",
"Blocked:"), never from colour.

Every file goes under $KEYSTONE_E2E_TMP (a `mktemp -d` folder, TEST-12); every
certificate name carries "KEYSTONE TEST" (TEST-11).
"""

import base64
import hashlib
import os
import re
import subprocess
import sys
import time

TMP = os.environ["KEYSTONE_E2E_TMP"]

from dogtail.config import config  # noqa: E402

config.logDebugToFile = False
config.logDebugToStdOut = False
config.searchShowingOnly = True
config.defaultDelay = 0.05
config.actionDelay = 0.2
config.typingDelay = 0.03
config.searchBackoffDuration = 0.2
config.searchCutoffCount = 25

from dogtail import rawinput  # noqa: E402
from dogtail.tree import root, SearchError  # noqa: E402


class E2EFailure(AssertionError):
    pass


def check(condition, message):
    if not condition:
        raise E2EFailure(message)


def make_dirs(*names):
    """Creates fresh folders under the temporary folder and returns their paths."""
    base = os.path.join(TMP, f"case-{time.monotonic_ns()}")
    os.makedirs(base)
    paths = []
    for name in names:
        path = os.path.join(base, name)
        os.makedirs(path)
        paths.append(path)
    return paths


def prepare(scenario, *drives, stdin=None):
    """Prepares a drive state with the e2e_prepare helper. Returns what it printed
    (the `master` scenario prints the synthetic master passphrase's words)."""
    done = subprocess.run(
        [os.environ["KEYSTONE_PREPARE"], scenario, *drives],
        check=True,
        input=stdin,
        capture_output=True,
        text=True,
    )
    return done.stdout


def drive_args(primary, backup, export):
    return ["--primary", primary, "--backup", backup, "--export", export]


def assert_no_plaintext_keys():
    """SEC-04, SEC-08: the plaintext-key scanner finds no unencrypted private key
    anywhere in the E2E temporary folder (every drive, export drive and log)."""
    done = subprocess.run(
        [os.environ["KEYSTONE_SCANNER"], TMP], capture_output=True, text=True
    )
    check(
        done.returncode == 0,
        f"plaintext-key scanner failed ({done.returncode}): {done.stdout}{done.stderr}",
    )


def certificate_fingerprint(path):
    """SHA-256 of the DER certificate in a PEM file, as AB:CD:... (FR-20)."""
    with open(path) as handle:
        text = handle.read()
    body = text.split("-----BEGIN CERTIFICATE-----")[1].split("-----END CERTIFICATE-----")[0]
    digest = hashlib.sha256(base64.b64decode("".join(body.split()))).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def files_under(folder):
    found = []
    for base, _, files in os.walk(folder):
        found.extend(os.path.join(base, name) for name in files)
    return sorted(found)


class Keystone:
    """One running Keystone process and its accessibility tree."""

    def __init__(self, *args, wrapper=()):
        self.log_path = os.path.join(TMP, f"keystone-{time.monotonic_ns()}.log")
        self.log = open(self.log_path, "w")
        env = dict(os.environ)
        env.pop("GTK_MODULES", None)
        self.process = subprocess.Popen(
            [*wrapper, os.environ["KEYSTONE_BIN"], *args],
            stdout=self.log,
            stderr=subprocess.STDOUT,
            env=env,
        )
        self.app = self._find_app()

    def _find_app(self, timeout=40):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            check(self.process.poll() is None, f"Keystone exited early: {self.output()}")
            try:
                for app in root.applications():
                    if app.name == "keystone":
                        return app
            except Exception:  # the registry may not be ready yet
                pass
            time.sleep(0.3)
        raise E2EFailure("Keystone did not appear in the accessibility tree")

    def output(self):
        self.log.flush()
        with open(self.log_path) as handle:
            return handle.read()

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.log.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    # -- finding widgets -------------------------------------------------------

    def find_all(self, predicate, showing=True):
        return self.app.findChildren(
            lambda node: (not showing or node.showing) and predicate(node),
            showingOnly=showing,
        )

    def labels(self, showing=True):
        return [n.name for n in self.find_all(lambda n: n.roleName == "label", showing)]

    def wait_for(self, predicate, what, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            check(self.process.poll() is None, f"Keystone exited: {self.output()}")
            found = self.find_all(predicate)
            if found:
                return found[0]
            time.sleep(0.25)
        raise E2EFailure(
            f"timed out waiting for {what}; visible labels: {self.labels()}"
        )

    def wait_label(self, text, timeout=30, exact=True):
        if exact:
            return self.wait_for(
                lambda n: n.roleName == "label" and n.name == text, f"label {text!r}", timeout
            )
        return self.wait_for(
            lambda n: n.roleName == "label" and text in n.name, f"label containing {text!r}", timeout
        )

    def wait_heading(self, text, timeout=30):
        """Waits until the screen whose heading is `text` is shown."""
        return self.wait_label(text, timeout)

    def widget(self, name, role, timeout=15):
        return self.wait_for(
            lambda n: n.roleName == role and n.name == name, f"{role} {name!r}", timeout
        )

    def button(self, name, timeout=15):
        return self.widget(name, "push button", timeout)

    def has_label(self, text, exact=True):
        if exact:
            return any(label == text for label in self.labels())
        return any(text in label for label in self.labels())

    def labels_matching(self, pattern):
        regex = re.compile(pattern)
        return [label for label in self.labels() if regex.search(label)]

    # -- keyboard --------------------------------------------------------------

    def focused(self):
        nodes = self.find_all(lambda n: n.focused)
        return nodes[-1] if nodes else None

    def press(self, key):
        rawinput.pressKey(key)
        time.sleep(0.15)

    def type(self, text):
        rawinput.typeText(text)
        time.sleep(0.15)

    def tab_to(self, name, role, max_tabs=60, backwards=False):
        """Moves the keyboard focus with Tab (or Shift+Tab) until the widget with
        `role` and `name` has it. Returns the number of key presses."""
        for presses in range(max_tabs + 1):
            node = self.focused()
            if node is not None and node.roleName == role and node.name == name:
                return presses
            if backwards:
                rawinput.keyCombo("<Shift>Tab")
            else:
                rawinput.pressKey("Tab")
            time.sleep(0.12)
        raise E2EFailure(
            f"{role} {name!r} was not reached with the keyboard; focus is on "
            f"{self.describe(self.focused())}"
        )

    def activate(self, name, role="push button"):
        """Moves the focus to a button or check box with Tab and presses Space."""
        self.tab_to(name, role)
        self.press("space")

    def focus_order(self, tabs):
        """The (role, name) pairs focused by `tabs` presses of Tab."""
        order = []
        for _ in range(tabs):
            rawinput.pressKey("Tab")
            time.sleep(0.12)
            node = self.focused()
            order.append((node.roleName, node.name) if node is not None else (None, None))
        return order

    @staticmethod
    def describe(node):
        return "nothing" if node is None else f"{node.roleName} {node.name!r}"

    # -- common steps ------------------------------------------------------------

    def type_into(self, name, text, role="text"):
        """Moves the focus to the field `name` with Tab and types `text`."""
        self.tab_to(name, role)
        self.type(text)

    def open_home(self):
        """Drive selection (prefilled) -> start-up checks -> clock -> home."""
        self.wait_heading("Choose the CA drives")
        self.activate("Check drives")
        self.wait_heading("Start-up checks")
        self.continue_to_home()

    def continue_to_home(self):
        """From the start-up checks: Continue, confirm the time (SEC-16), home."""
        self.wait_heading("Start-up checks")
        self.wait_label("Start-up checks")
        self.activate("Continue")
        self.wait_heading("Confirm the date and time")
        self.activate("Confirm date and time")
        self.wait_heading("What do you want to do?")

    def done_to_home(self):
        """From a result screen: Done, the start-up checks run again, then home."""
        self.activate("Done")
        self.wait_heading("Start-up checks")
        self.wait_for(
            lambda n: n.roleName == "push button" and n.name == "Continue",
            "Continue after the start-up checks",
            timeout=60,
        )
        self.continue_to_home()

    def shown_words(self):
        words = {}
        for label in self.labels():
            match = re.fullmatch(r"(\d+)\. ([a-z-]+)", label)
            if match:
                words[int(match.group(1))] = match.group(2)
        return words

    def confirm_passphrase(self, count):
        """FR-03: reads the words shown once, ticks, retypes every group and confirms.
        Returns the words in order (synthetic test passphrase)."""
        self.wait_heading("Write down your passphrase")
        words = self.shown_words()
        check(sorted(words) == list(range(1, count + 1)), f"words shown: {words}")
        self.activate(f"I have written down all {count} words", role="check box")
        self.activate("Retype the words")
        self.wait_heading("Type the words again")
        numbers = list(range(1, count + 1))
        groups = [numbers[i : i + 4] for i in range(0, count, 4)]
        for group, members in enumerate(groups, start=1):
            self.tab_to(f"Word {members[0]}", "text")
            for number in members:
                self.type(words[number])
                self.press("Return")
            self.activate(f"Check group {group}")
            self.wait_label(f"OK: Group {group} matches and is kept.")
        self.activate("Confirm passphrase")
        return [words[n] for n in numbers]

    def result_fingerprints(self):
        """Every SHA-256 fingerprint shown on a result screen (FR-20). Each is a
        selectable label named by its "SHA-256 fingerprint" heading; its text is read."""
        pattern = re.compile(r"^([0-9A-F]{2}:){31}[0-9A-F]{2}$")
        found = []
        for node in self.find_all(
            lambda n: n.roleName == "label" and n.name == "SHA-256 fingerprint"
        ):
            try:
                text = node.text
            except Exception:  # a node without the text interface
                continue
            if text and pattern.match(text):
                found.append(text)
        return found


def run(test):
    """Runs one test function and reports PASS or FAIL with the reason."""
    name = test.__module__ if test.__module__ != "__main__" else sys.argv[0]
    try:
        test()
    except Exception as error:  # report every failure the same way
        print(f"FAIL: {error.__class__.__name__}: {error}")
        raise
    print(f"PASS: {os.path.basename(name)}")
