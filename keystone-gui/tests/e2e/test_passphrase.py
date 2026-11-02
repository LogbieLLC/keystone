"""Passphrase show-once and confirmation, keyboard only, through the development
test hook that opens a master passphrase confirmation directly.

Checks: numbered words in groups of 4 on a dedicated screen with a hide control;
retyping only after the "I have written down all N words" tick; autocompletion from
the wordlist; a wrong word marks only its group; "View the words again" keeps the
confirmed groups; after confirmation the words are gone from the window and from
the accessibility tree.

# Covers: FR-03 AC3, FR-03 AC4, SEC-17, NFR-04
"""

import os
import re

from keystone_e2e import Keystone, check, run


def wordlist():
    with open(os.environ["KEYSTONE_WORDLIST"]) as handle:
        return [line.split("\t")[1].strip() for line in handle if line.strip()]


def unique_prefix(word, words):
    """The shortest prefix of `word` that no other list word starts with."""
    for length in range(1, len(word) + 1):
        prefix = word[:length]
        if sum(1 for w in words if w.startswith(prefix)) == 1:
            return prefix
    return word


def shown_words(keystone):
    words = {}
    for label in keystone.labels():
        match = re.fullmatch(r"(\d+)\. ([a-z-]+)", label)
        if match:
            words[int(match.group(1))] = match.group(2)
    return words


def type_group(keystone, words, numbers, typed=None):
    """Types the words of one group into its boxes, pressing Enter after each word
    (Enter completes a unique prefix and moves to the next box)."""
    keystone.tab_to(f"Word {numbers[0]}", "text")
    for number in numbers:
        text = (typed or {}).get(number, words[number])
        keystone.type(text)
        keystone.press("Return")


def test():
    all_words = wordlist()
    with Keystone("--test-hook", "passphrase-confirmation") as keystone:
        keystone.wait_heading("Write down your passphrase")
        words = shown_words(keystone)
        check(sorted(words) == list(range(1, 11)), f"words shown: {words}")
        check(all(w in all_words for w in words.values()), "a word is not from the list")
        for group in ("Group 1", "Group 2", "Group 3"):
            keystone.wait_label(group)

        # Hide control.
        keystone.activate("Hide the words", role="toggle button")
        keystone.wait_label(
            "Note: The words are hidden. Press Show the words to see them again."
        )
        check(not shown_words(keystone), "words still visible while hidden")
        keystone.activate("Show the words", role="toggle button")
        keystone.wait_label("1. " + words[1])

        # Retyping is gated by the tick (FR-03 AC4).
        retype = keystone.button("Retype the words")
        check(not retype.sensitive, "retyping enabled before the tick")
        keystone.activate("I have written down all 10 words", role="check box")
        check(keystone.button("Retype the words").sensitive, "tick did not enable retyping")
        keystone.activate("Retype the words")
        keystone.wait_heading("Type the words again")
        focused = keystone.focused()
        check(
            focused is not None and focused.name == "Word 1",
            f"focus is on {keystone.describe(focused)}",
        )
        keystone.wait_label("Note: Group 1: type all 4 words.")

        # Group 1 correct, typed in full.
        type_group(keystone, words, [1, 2, 3, 4])
        keystone.activate("Check group 1")
        keystone.wait_label("OK: Group 1 matches and is kept.")

        # Group 2 with one wrong (but valid) list word: only group 2 is marked.
        wrong = next(w for w in ("zoom", "abacus", "zone") if w != words[7])
        type_group(keystone, words, [5, 6, 7, 8], typed={7: wrong})
        keystone.activate("Check group 2")
        keystone.wait_label(
            "Blocked: Group 2 does not match. Type these 4 words again; the other groups are kept."
        )
        check(
            keystone.has_label("OK: Group 1 matches and is kept."),
            f"group 1 was not kept: {keystone.labels()}",
        )
        check(
            keystone.has_label("Note: Group 3: type all 2 words."),
            f"group 3 changed: {keystone.labels()}",
        )
        check(not keystone.button("Confirm passphrase").sensitive, "confirm enabled early")

        # A word that is not on the list is refused.
        keystone.tab_to("Word 5", "text")
        keystone.type("qqqq")
        keystone.wait_label("Not a word from the list. Check the spelling.")
        for _ in range(4):
            keystone.press("BackSpace")

        # View the words again, then come back: group 1 stays confirmed.
        keystone.activate("View the words again")
        keystone.wait_heading("Write down your passphrase")
        check(shown_words(keystone) == words, "different words shown again")
        keystone.activate("Retype the words")
        keystone.wait_heading("Type the words again")
        check(
            keystone.has_label("OK: Group 1 matches and is kept."),
            f"group 1 lost after viewing again: {keystone.labels()}",
        )

        # Group 2 again, using autocompletion (unique prefixes + Enter).
        prefixes = {n: unique_prefix(words[n], all_words) for n in (5, 6, 7, 8)}
        type_group(keystone, words, [5, 6, 7, 8], typed=prefixes)
        keystone.activate("Check group 2")
        keystone.wait_label("OK: Group 2 matches and is kept.")
        type_group(keystone, words, [9, 10])
        keystone.activate("Check group 3")
        keystone.wait_label("OK: Group 3 matches and is kept.")
        keystone.wait_label(
            "OK: Every word matches. Press Confirm passphrase to continue; the words will not be shown again."
        )

        # Confirm: the words are never shown again (SEC-17).
        keystone.activate("Confirm passphrase")
        keystone.wait_heading("Passphrase test hook")
        keystone.wait_label("OK: Passphrase confirmed: 10 words", exact=False)
        everything = [
            node.name
            for node in keystone.app.findChildren(lambda n: True, showingOnly=False)
        ]
        leaked = [
            name
            for name in everything
            for word in words.values()
            if re.search(rf"\b{re.escape(word)}\b", name or "")
        ]
        check(not leaked, f"passphrase words still in the accessibility tree: {leaked}")
        check(
            not keystone.find_all(lambda n: n.name == "Write down your passphrase", showing=False),
            "the words screen still exists",
        )


if __name__ == "__main__":
    run(test)
