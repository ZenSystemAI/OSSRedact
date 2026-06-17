"""Tests for the email_receipt generator (Quebec transactional EMAILS + retail/POS RECEIPTS, FR/EN).

Offset-exactness, the defining positives per layout (the email surfaces email/person/phone/address/
account_number/username/file_path; the held-out POS receipt surfaces tax_id always + the member-identity
path person/address/postal/phone/payment_card), the precision property (the mail-system metadata + the
mandatory till/receipt skeleton are NEVER labeled), shape invariants (tax_id GST RT / QST TQ, account
format, full-PAN Luhn, postal FSA), and the train/heldout layout split (the POS receipt is a structure the
train pool never produces).
Run: .venv-test/bin/python -m pytest training/gen/tests/test_email_receipt.py -v
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import email_receipt as ER  # noqa: E402
import layouts  # noqa: E402

_LABELS = set(json.load(open(os.path.join(os.path.dirname(__file__), '..', '..', 'labels_v20.json')))['labels'])


def _luhn(d):
    s = 0
    for i, c in enumerate(reversed(d)):
        x = int(c)
        if i % 2 == 1:
            x *= 2
            if x > 9:
                x -= 9
        s += x
    return s % 10 == 0


def test_offsets_exact_and_labels_in_scheme():
    random.seed(31)
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = ER.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                assert 0 <= s < e <= len(t)
                assert t[s:e].strip() != ""        # never an empty/whitespace span
                assert lab in _LABELS              # only the 20 labels


def test_required_positives_present():
    """Across both splits, every defining positive of the doctype appears: the email layout supplies
    email/person/phone_number/address/account_number/username/file_path; the held-out POS receipt supplies
    tax_id (always) and the member-identity path's payment_card/postal_code."""
    random.seed(32)
    seen = set()
    for sp in ("train", "heldout"):
        for _ in range(80):
            r = ER.gen(split=sp)
            seen |= {lab for _, _, lab in r['output']['spans']}
    need = {"email", "person", "phone_number", "address", "account_number", "username", "file_path",
            "tax_id", "postal_code", "payment_card"}
    assert need <= seen, f"missing {need - seen}"


def test_email_layout_positives_and_two_emails():
    """The email layout always carries BOTH the From: and To: addresses (two email positives) and never a
    tax_id (that is a receipt-only label here)."""
    random.seed(33)
    train_pool, _ = layouts.split_pools(ER.LAYOUTS)
    assert ER._layout_email in train_pool
    for _ in range(120):
        r = ER._layout_email(random.choice(["fr", "en"]))
        labs = [lab for _, _, lab in r['output']['spans']]
        assert labs.count("email") == 2          # From: + To: addresses, both positive
        assert "person" in labs                  # recipient greeting
        assert "account_number" in labs          # customer account number
        assert "username" in labs                # bare login / @handle
        assert "file_path" in labs               # attachment path
        assert "phone_number" in labs            # support phone
        assert "address" in labs                 # shipping address
        # v11 round-3: the email footer now carries the merchant's own GST/QST (tax_id) and address
        # postal_code, closing the train->heldout coverage gap for those labels.
        assert labs.count("tax_id") == 2         # merchant GST/HST (RT) + QST (TQ) in the footer
        assert "postal_code" in labs             # merchant address postal code in the footer


def test_receipt_tax_id_always_present_and_shapes():
    """Every POS receipt carries BOTH the store GST (RT) and QST (TQ) registration numbers as tax_id."""
    random.seed(34)
    for _ in range(120):
        r = ER._layout_receipt(random.choice(["fr", "en"]))
        t = r['input']
        taxes = [t[s:e] for s, e, lab in r['output']['spans'] if lab == "tax_id"]
        assert len(taxes) >= 2, taxes
        assert any(re.search(r'\d{9} RT \d{4}$', v) for v in taxes), taxes
        assert any(re.search(r'\d{10} TQ \d{4}$', v) for v in taxes), taxes


def test_decoys_never_labeled():
    """The mail-system metadata + the mandatory till/receipt skeleton must never be redacted: any amount
    ($), the tracking/confirmation URL, the Message-ID, the order reference (CMD-/REF-/ORD-/WEB-), the
    masked card tail, and every bare ISO/transaction date are DECOYS -> never inside a labeled span."""
    random.seed(35)
    masked = re.compile(r'\*{2,}|X{6,}|\.\.\.\d{4}$')
    order_ref = re.compile(r'^(CMD-|REF-|ORD-|CMD-W|WEB-)\d+$')
    for sp in ("train", "heldout"):
        for _ in range(250):
            r = ER.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                val = t[s:e]
                assert "$" not in val                       # amounts/subtotals/totals are decoys
                assert "https://" not in val                # tracking/confirmation URL is a decoy
                assert "Message-ID" not in val
                assert "<" not in val and ">" not in val    # the Message-ID brackets never land in a span
                assert not masked.search(val)               # a masked card tail is a decoy, not payment_card
                assert not order_ref.match(val)             # an order ref is a decoy, not account_number
                # no cued DOB exists in this doctype -> a bare ISO date is always a transaction decoy
                assert not re.fullmatch(r'20\d\d-\d\d-\d\d', val)


def test_positive_shapes():
    """account_number is institution-first or a bare numeric run; payment_card positives are Luhn-valid full
    PANs (never a masked tail); postal_code is a Quebec FSA; email positives contain exactly one '@'."""
    random.seed(36)
    acct_ok = re.compile(r'^(\d{3}-\d{4,5}-\d{6,9}|\d{7,11})$')
    saw_pan = False
    for sp in ("train", "heldout"):
        for _ in range(200):
            r = ER.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                v = t[s:e]
                if lab == "account_number":
                    assert acct_ok.match(v), v
                if lab == "payment_card":
                    saw_pan = True
                    digits = re.sub(r'\D', '', v)
                    assert 13 <= len(digits) <= 19 and _luhn(digits), v
                if lab == "postal_code":
                    assert re.match(r'^[GHJ]\d[A-Z] ?\d[A-Z]\d$', v), v
                if lab == "email":
                    assert v.count("@") == 1 and " " not in v, v
                if lab == "username":
                    assert "@" not in v.lstrip("@"), v       # bare login or a leading-@ handle, not an email
                    assert " " not in v, v
    assert saw_pan, "no full-PAN payment_card positive ever emitted"


def test_username_is_not_email_or_path():
    """A username positive is a bare login / @handle: it must not be email-shaped (no domain) and must not
    be a file path (no slash), to teach the username vs email vs file_path collision."""
    random.seed(37)
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = ER.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                v = t[s:e]
                if lab == "username":
                    assert "." not in v.split("@")[-1] or "@" not in v   # no user@dom.tld email shape
                    assert "/" not in v and "\\" not in v                # not a path
                if lab == "file_path":
                    assert ("/" in v) or ("\\" in v)                     # paths carry a separator


def test_layouts_split_distinct():
    assert len(ER.LAYOUTS) >= 2
    train_pool, held_pool = layouts.split_pools(ER.LAYOUTS)
    assert set(train_pool).isdisjoint(set(held_pool))
    # the held-out layout (_layout_receipt) is a tabular POS till receipt; the train layout is an RFC 5322
    # email. They are genuinely distinct real structures, not reworded near-duplicates.
    assert ER._layout_receipt in held_pool and ER._layout_receipt not in train_pool
    assert ER._layout_email in train_pool and ER._layout_email not in held_pool
    # behavioural distinction: the held-out always surfaces tax_id (store registrations). The train email
    # now ALSO surfaces tax_id (v11 round-3 merchant footer), so the distinguishing positive is `email`:
    # the email layout always carries two email positives; the receipt never carries an email positive.
    random.seed(38)
    held_has_tax = all("tax_id" in {lab for _, _, lab in ER.gen(split="heldout")['output']['spans']}
                       for _ in range(40))
    train_has_tax = all("tax_id" in {lab for _, _, lab in ER.gen(split="train")['output']['spans']}
                        for _ in range(40))
    assert held_has_tax and train_has_tax        # both splits now train/test the tax_id label
    # the email always surfaces two emails; the receipt never carries an email positive at all
    held_has_email = any("email" in {lab for _, _, lab in ER.gen(split="heldout")['output']['spans']}
                         for _ in range(40))
    train_has_email = all("email" in {lab for _, _, lab in ER.gen(split="train")['output']['spans']}
                          for _ in range(40))
    assert train_has_email and not held_has_email
    # structural skeleton check: the email's RFC 5322 headers are absent from receipt rows, and the
    # receipt's till header is absent from email rows
    random.seed(39)
    held_txt = "\n".join(ER.gen(split="heldout")['input'] for _ in range(20))
    train_txt = "\n".join(ER.gen(split="train")['input'] for _ in range(20))
    assert "From: " in train_txt and "Message-ID: " in train_txt
    assert "From: " not in held_txt and "Message-ID: " not in held_txt
    assert ("Caisse " in held_txt or "Till " in held_txt)
    assert "Caisse " not in train_txt and "Till " not in train_txt
