"""Tier-0 deterministic person backstop for cue-bearing forms the NER wobbles on
(RFC5322 mailbox `Name <email>`, git-author / Signed-off-by, From:/To:/owner: headers).
Found live 2026-06-18: v11r6 leaked names in these forms; this floor hard-guarantees them."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from privacy_gate import cue_name_spans  # noqa: E402


def _names(t):
    return [t[s['start']:s['end']] for s in cue_name_spans(t)]


CATCH = [
    ("From: Olivier Tremblay <o.tremblay@acme.ca>", "Olivier Tremblay"),
    ("To: Aisha Okonkwo <aisha@example.org>", "Aisha Okonkwo"),
    ("Author: Priya Ramaswamy <priya@dev.io>", "Priya Ramaswamy"),
    ("Signed-off-by: Kwame Mensah <kwame@kernel.org>", "Kwame Mensah"),
    ("# owner: Jean Tremblay <jean.tremblay@acme.ca>  card 4539 1488 0343 6467", "Jean Tremblay"),
    ('"Marie-Hélène Béland" <mh@x.ca>', "Marie-Hélène Béland"),
    ("commit a1b2c3d  Thandiwe Mkhize <t@x.io>  2024-01-02", "Thandiwe Mkhize"),
    ("Attn: Jean-Philippe Gagnon-Roy", "Jean-Philippe Gagnon-Roy"),
    ("Co-authored-by: Hassan El-Amrani <h@x.io>", "Hassan El-Amrani"),
    ("Reply-To: Bjørn Halvorsen <b@x.no>", "Bjørn Halvorsen"),
]

# distribution lists / role mailboxes / bare emails / lowercase fragments must NOT be tagged
NO_FP = [
    "Support <support@acme.ca>",
    "To: Marketing Team <mkt@acme.ca>",
    "no-reply <noreply@x.io>",
    "From: billing@acme.ca",
    "Notifications <notify@x.io>",
    "Email bob@acme.ca please",
    "the value is foo <bar@baz.io>",
]


def test_cue_name_catches():
    for text, name in CATCH:
        assert name in _names(text), f"{name!r} not caught in {text!r} (got {_names(text)})"


def test_cue_name_no_false_positives():
    for text in NO_FP:
        assert _names(text) == [], f"unexpected person span in {text!r}: {_names(text)}"
