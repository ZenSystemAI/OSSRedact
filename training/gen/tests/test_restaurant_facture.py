"""Tests for the restaurant_facture generator (Quebec MANDATORY restaurant invoice, MEV/WEB-SRM).

Offset-exactness, the sparse defining positives (tax_id always; person/phone/payment_card on the takeout
identity path), the precision property (the mandatory invoice skeleton -- '===' block, amounts, masked card
tail, transaction numbers, device id, restaurant name/phone/address, dates -- is NEVER labeled), the tax_id
shape invariant (GST RT / QST TQ), and the train/heldout layout split (held-out structure disjoint from
train: the customer-identity path).
Run: .venv-test/bin/python -m pytest training/gen/tests/test_restaurant_facture.py -v
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import restaurant_facture as RF  # noqa: E402
import layouts  # noqa: E402

_LABELS = set(json.load(open(os.path.join(os.path.dirname(__file__), '..', '..', 'labels_v20.json')))['labels'])


def test_offsets_exact_and_labels_in_scheme():
    random.seed(21)
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = RF.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                assert 0 <= s < e <= len(t)
                assert t[s:e].strip() != ""        # never an empty/whitespace span
                assert lab in _LABELS              # only the 20 labels


def test_required_positives_present():
    """tax_id is the always-present defining positive (mandatory TPS + TVQ registration numbers). The
    held-out takeout path additionally surfaces person, address, postal_code, phone_number, payment_card."""
    random.seed(22)
    seen = set()
    for sp in ("train", "heldout"):
        for _ in range(60):
            r = RF.gen(split=sp)
            seen |= {lab for _, _, lab in r['output']['spans']}
    need = {"tax_id", "person", "address", "postal_code", "phone_number", "payment_card"}
    assert need <= seen, f"missing {need - seen}"


def test_tax_id_always_present():
    """Every mandatory facture (both layouts) carries BOTH the TPS (RT) and TVQ (TQ) registration numbers."""
    random.seed(23)
    for sp in ("train", "heldout"):
        for _ in range(80):
            r = RF.gen(split=sp)
            t = r['input']
            taxes = [t[s:e] for s, e, lab in r['output']['spans'] if lab == "tax_id"]
            assert len(taxes) >= 2, taxes
            assert any(" RT " in v for v in taxes), taxes   # GST/TPS program account
            assert any(" TQ " in v for v in taxes), taxes   # QST/TVQ file number


def test_decoys_never_labeled():
    """The mandatory invoice skeleton must never be redacted. The whole '===' block, every amount/total/tip
    (anything with '$'), the masked card tail, transaction numbers, the device id, the QR web link, and every
    transaction date/time are DECOYS -> never inside a labeled span."""
    random.seed(24)
    masked = re.compile(r'\*{2,}|X{6,}|\.\.\.\d{4}$')
    for sp in ("train", "heldout"):
        for _ in range(250):
            r = RF.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                val = t[s:e]
                assert "$" not in val                       # amounts/totals/tips/balances are decoys
                assert "=" not in val                       # the '===' suite is never inside a label
                assert "https://" not in val                # the QR web link is a decoy
                assert not masked.search(val)               # a masked card tail is a decoy, not payment_card
                # a bare ISO transaction/remittance date is always a decoy here (no cued DOB in this doctype)
                assert not re.fullmatch(r'20\d\d-\d\d-\d\d', val)


def test_positive_shapes():
    """payment_card positives are Luhn-valid full PANs (never a masked tail); tax_id positives match the
    GST RT / QST TQ shapes; postal_code is a Quebec FSA."""
    random.seed(25)
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
    saw_pan = False
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = RF.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                v = t[s:e]
                if lab == "payment_card":
                    saw_pan = True
                    digits = re.sub(r'\D', '', v)
                    assert 13 <= len(digits) <= 19 and _luhn(digits), v
                if lab == "tax_id":
                    assert re.search(r'\d{9} RT \d{4}$', v) or re.search(r'\d{10} TQ \d{4}$', v), v
                if lab == "postal_code":
                    assert re.match(r'^[GHJ]\d[A-Z] ?\d[A-Z]\d$', v), v
    assert saw_pan, "no full-PAN payment_card positive ever emitted"


def test_resto_phone_is_decoy_customer_identity_strip_is_positive():
    """The restaurant HEADER phone is always a DECOY (org contact), in BOTH layouts. The dine-in train
    layout now carries a named-account customer-identity strip (~55%) -> person/address/postal_code/
    phone_number positives that cover the labels the held-out tests; any labeled phone is the customer's,
    never the restaurant's. dine-in still surfaces tax_id always + a brand-cued full-PAN payment_card."""
    random.seed(26)
    train_pool, _ = layouts.split_pools(RF.LAYOUTS)
    assert RF._layout_dinein in train_pool
    saw_dinein_pan = False
    saw_dinein_identity = False
    allowed = {"tax_id", "payment_card", "person", "address", "postal_code", "phone_number"}
    for _ in range(200):
        r = RF._layout_dinein(random.choice(["fr", "en"]))
        t = r['input']
        labs = {lab for _, _, lab in r['output']['spans']}
        assert labs <= allowed
        # the restaurant header phone (the value after the header 'Tel.:' cue) is never inside a labeled span
        phones = [t[s:e] for s, e, lab in r['output']['spans'] if lab == "phone_number"]
        for ph in phones:
            assert ("Telephone du client: " + ph) in t or ("Customer phone: " + ph) in t
        # the customer-identity strip is a co-occurring set: person <=> phone_number both present or both absent
        if "person" in labs or "phone_number" in labs:
            saw_dinein_identity = True
            assert {"person", "address", "postal_code", "phone_number"} <= labs
        if "payment_card" in labs:
            saw_dinein_pan = True
    assert saw_dinein_pan, "dine-in never emitted the brand-cued payment_card positive"
    assert saw_dinein_identity, "dine-in never emitted the new customer-identity strip positives"


def test_layouts_split_distinct():
    assert len(RF.LAYOUTS) >= 2
    train_pool, held_pool = layouts.split_pools(RF.LAYOUTS)
    assert set(train_pool).isdisjoint(set(held_pool))
    # the held-out layout (_layout_takeout) is the takeout/delivery structure (order ref + delivery wording
    # + 'Adresse de livraison' + credit-note path); the dine-in train layout is table-service. BOTH now carry
    # a customer-identity strip (so train COVERS the person/address/postal_code/phone_number labels the
    # held-out tests), but the held-out's DELIVERY skeleton stays disjoint from the dine-in skeleton.
    assert RF._layout_takeout in held_pool and RF._layout_takeout not in train_pool
    random.seed(27)
    # both splits surface customer identity (person) now -- the label-coverage gap is closed
    held_has_person = any("person" in {lab for _, _, lab in RF.gen(split="heldout")['output']['spans']}
                          for _ in range(40))
    train_has_person = any("person" in {lab for _, _, lab in RF.gen(split="train")['output']['spans']}
                           for _ in range(120))
    assert held_has_person and train_has_person
    # structural skeleton check: the held-out's distinctive DELIVERY wording is absent from train rows;
    # the dine-in train uses a plain 'Adresse:' line, never the held-out's 'Adresse de livraison:'.
    random.seed(28)
    held_txt = "\n".join(RF.gen(split="heldout")['input'] for _ in range(20))
    train_txt = "\n".join(RF.gen(split="train")['input'] for _ in range(20))
    assert ("Adresse de livraison" in held_txt or "Delivery address" in held_txt)
    assert "Adresse de livraison" not in train_txt and "Delivery address" not in train_txt
    assert ("Commande pour emporter" in held_txt or "Takeout / delivery order" in held_txt)
    assert "Commande pour emporter" not in train_txt and "Takeout / delivery order" not in train_txt


def test_mandatory_eq_skeleton_present_both_layouts():
    """The defining '===' suite (suite de signes d'egalite) before the tax/total block must appear in BOTH
    layouts -- it is the legally mandated structural feature, present in train and heldout alike."""
    random.seed(29)
    for sp in ("train", "heldout"):
        for _ in range(40):
            r = RF.gen(split=sp)
            assert "====" in r['input']                              # a run of '=' is present
            # mandated ordering: TPS amount line precedes TVQ amount line precedes the total line
            t = r['input']
            i_tps = max(t.find("Montant de la TPS"), t.find("GST amount"))
            i_tvq = max(t.find("Montant de la TVQ"), t.find("QST amount"))
            i_tot = max(t.find("Montant total de la fourniture"), t.find("Total amount of the supply"))
            assert -1 < i_tps < i_tvq < i_tot, (i_tps, i_tvq, i_tot)
