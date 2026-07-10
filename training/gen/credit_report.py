#!/usr/bin/env python3
"""credit_report generator: synthetic Quebec/Canada consumer credit disclosures in the REAL Equifax layout.

GROUNDED on the two scaffold PDFs (datasets/scaffolds/):
 - consumer_credit_report_user_guide.pdf : the Equifax Canada CONSUMER CREDIT FILE sample. A labeled
   "Field: value" Identification block (Name / Current Address / Previous Address / Date of Birth / SIN /
   Reference / Unique Number / File Number / Telephone #) followed by Inquiries, Employment, Summary, and
   a Member Trades tradeline section (Bus/ID code, masked-ish account numbers, payment-history grids).
 - Equifax-how-to-read-the-credit-report.pdf : the ACROFILE annotated tutorial. A STRUCTURALLY DIFFERENT
   terse one-line machine format: "*CONSUMER, JOHN, Q, JR  SINCE 03/10/81 FAD 12/28/05  FN-238",
   "BDS-03/03/1961, SSN 900-00-0000 SSN VER: Y", "****FORMER NAME - ...****", asterisk-delimited alert
   blocks, ZIP+street one-liners. This is the HELD-OUT structure (the model never trains on it).

This is the DENSEST multi-label doctype. The product is the contrast between the few real PII positives and
the dense surrounding NEGATIVES (credit scores, balances, credit limits, payment-history grids, inquiry
dates, creditor/agency org names, masked account tails).

POSITIVES (subject identity only):
 person (+ former names / AKA), address (+ former addresses), postal_code, date_of_birth (cued: DOB/BDS/
 date de naissance), government_id (a FULL unmasked SIN; the masked "999-999-999" / "XXX-XX-..." form is a
 DECOY), sensitive_account_id (Equifax Unique Number / File Number / reference), account_number (a FULL
 tradeline/banking account number; the masked "XXXXXX1234" tail is a DECOY), phone_number, organization
 (only the LABELED employer header; the same name in a tradeline/inquiry/collection line is a DECOY).

DECOYS (the false-positive moat): credit scores (Risk Score / Bankruptcy Navigator Index), balances /
 credit limits / high credit / amounts ($), payment-history grids (111111...), inquiry dates and all other
 dates (issue / reported / opened / DLA), creditor + collection-agency + inquiry-member ORG names, masked
 account tails (XXXXXX1234), masked SIN, bus/ID codes (481BB00000), court numbers, ECOA codes.

LAYOUTS (>=2 genuinely distinct real structures; held-out = the suffix):
 - _layout_disclosure : Equifax CA labeled "Field: value" Identification block + tradelines.   [train]
 - _layout_banking    : Identification + a Banking/Checking-Saving + Member-Trades TABLE form.  [train]
 - _layout_acrofile   : the ACROFILE terse one-line annotated machine format (US-style).         [heldout]

gen(lang, split) -> one offset-true row dict. Caller seeds `random`.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402
import layouts                  # noqa: E402

# Creditor / collection-agency / inquiry-member names. In a tradeline / inquiry / collection / public-record
# line these are NEGATIVE decoys (transaction-level counterparties, not the subject's identity).
_CREDITORS = ["CANADA BANK", "SMARTSHOP RETAIL", "ABC RETAIL INC", "NATIONAL CREDIT HOUSE", "MORTGAGE WORLD",
              "CANADA CAR LOANS", "RETAIL WORLD", "ABC CREDIT", "FURNITURE HOUSE", "CANADA COLLECTION",
              "BANQUE LAURENTIENNE", "FINANCIERE DESJARDINS", "CREDIT DU NORD", "MAISON DE MEUBLES"]
_DESCRIPTIONS = ["Personal Loan, Semi-Monthly Payments", "Second mortgage", "Revolving credit",
                 "Installment loan", "Pret personnel, paiements bimensuels", "Marge de credit",
                 "Carte de credit, paiements mensuels", "Auto loan, monthly payments"]


def _masked_sin() -> str:
    """The MASKED SIN form the real disclosure prints (e.g. 999-999-999 / XXX-XX-1234) -> NEGATIVE decoy.
    Never lifted to government_id; the FULL Luhn-valid V.sin() is the only government_id positive."""
    if random.random() < 0.5:
        return "999-999-999"
    return "XXX-XX-" + "".join(random.choice("0123456789") for _ in range(4))


def _masked_acct() -> str:
    """A MASKED tradeline account tail (e.g. XXXXXX1234 / ******4821) -> NEGATIVE decoy. Never labeled.
    Only a FULL bank_account() run is account_number."""
    mask = random.choice(["XXXXXX", "******", "XXXX", "....", "xxxxxx"])
    return mask + "".join(random.choice("0123456789") for _ in range(4))


def _bus_id() -> str:
    """An Equifax Bus/ID member code (e.g. 481BB00000, 007BB01351) -> NEGATIVE decoy (creditor member id,
    not the subject's account)."""
    return (f"{random.randint(1,999):03d}"
            + "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(2))
            + f"{random.randint(0,99999):05d}")


def _court_no() -> str:
    """A court file number on a public record (e.g. 481VC00214) -> NEGATIVE decoy."""
    return (f"{random.randint(1,999):03d}"
            + "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(2))
            + f"{random.randint(0,99999):05d}")


def _score() -> str:
    """An Equifax Risk Score / Bankruptcy Navigator Index (3-digit) -> NEGATIVE decoy. Bare 3-digit, no
    card_cvv cue -> stays O (collision rule 6)."""
    return str(random.randint(280, 850))


def _file_number() -> str:
    """Equifax File Number, dashed (00-00000000-00-000) -> sensitive_account_id (opaque consumer-file ref)."""
    return f"{random.randint(0,99):02d}-{random.randint(0,99999999):08d}-{random.randint(0,99):02d}-{random.randint(0,999):03d}"


def _unique_number() -> str:
    """Equifax Unique (consumer) Number, a 10-digit opaque file ref -> sensitive_account_id.
    HELD-OUT ONLY (the ACROFILE layout's frozen FILE ref). Train layouts must NOT use this -- a bare
    10-digit run collides with account_number's bare10 form (collision rule 1: never route a bare numeric
    run to sensitive_account_id). Train uses _opaque_file_ref() instead."""
    return "".join(random.choice("0123456789") for _ in range(10))


def _opaque_file_ref() -> str:
    """Equifax consumer-file ref for the TRAIN layouts -> sensitive_account_id, kept OPAQUE/alphanumeric so
    it never collides with a bare/hyphenated numeric account_number run (collision rule 1: sensitive_account_id
    = UUID-shaped / opaque alphanumeric ref, NEVER a bare numeric account). Equifax-style letter+digit file
    code, e.g. 'EFX-7H2K9Q4B1'."""
    body = "".join(random.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(10))
    return f"EFX-{body}"


def _pmt_grid() -> str:
    """A 24-month Trade Payment Profile grid (111111111111111111111111) -> NEGATIVE decoy."""
    return "".join(random.choice("111111112345") for _ in range(24))


def _money() -> str:
    """A credit-limit / balance / high-credit amount -> NEGATIVE decoy (always carries $)."""
    return "$" + f"{random.randint(100, 280000):,}"


def _mmYY() -> str:
    """An MM/DD/YY or MM/YY reported/opened/DLA date (no birth cue) -> NEGATIVE decoy."""
    if random.random() < 0.5:
        return f"{random.randint(1,12):02d}/{random.randint(80,99):02d}"
    return f"{random.randint(1,12):02d}/{random.randint(1,28):02d}/{random.randint(0,9)}{random.randint(0,9)}"


def _resample(sampler, avoid, tries: int = 12):
    """Draw from `sampler` a value NOT in the `avoid` set, so a hard-negative DECOY never lands on a string
    that is byte-identical to a labeled POSITIVE in the same document. Identical strings would be
    contradictory token-level supervision (the same token sequence labeled and unlabeled in one example),
    which defeats the positional collision-rule contrast the doc is meant to teach. `V.phone()` and
    `V.company()` have small value spaces, so chance collisions occur ~0.2% of rows without this guard."""
    v = sampler()
    for _ in range(tries):
        if v not in avoid:
            return v
        v = sampler()
    return v                      # extremely unlikely; accept after bounded retries (still offset-true)


def _decoy_phone(d: Doc, avoid) -> None:
    """A counterparty (creditor / inquiry-member / daytime) phone DECOY that never collides with a subject
    phone_number positive already labeled in this doc."""
    d.decoy(_resample(V.phone, avoid))


def _name_caps(lang: str) -> str:
    return V.person(lang, caps=(random.random() < 0.7))   # Equifax disclosures print the holder ALL-CAPS


def _addr_line(lang: str) -> str:
    """Build a synthetic address line; field only the street part (V.street_address) so the labeled span is
    address; the city/province/postal trailing is handled separately by the caller."""
    return V.street_address(lang)


# ---------- shared tradeline / inquiry / summary decoy block (the false-positive moat) ----------

def _member_trades(d: Doc, fr: bool, phones=frozenset()) -> None:
    """Append a Member Trades tradeline section. Each tradeline carries a creditor org DECOY, a bus/ID
    DECOY, reported/opened/DLA date DECOYS, a credit-limit/balance/$ DECOY, a 24-month payment grid DECOY,
    and a MASKED account tail DECOY -- but the FULL 'Account Number:' line is a real account_number positive.
    `phones` = the subject phone_number positives in this doc, so creditor phone DECOYS never collide."""
    d.add("Member Trades:\n" if not fr else "Comptes des membres:\n")
    d.add("Bus/ID Code  DT Rptd  DT Opnd  DLA  Credit Limit  High Credit  Balance\n")
    for _ in range(random.randint(2, 4)):
        if random.random() < 0.4:
            # TERSE POSITIONAL tradeline: the FULL numeric account number is a BARE run after creditor + bus/id
            # code (NO 'Account Number:' label). The field delimiter is VARIED PER TRADELINE across DISTINCTIVE
            # PUNCTUATION delimiters (pipe / semicolon / double-colon) that EXCLUDE comma. The held-out ACROFILE
            # tradeline is the SAME semantic shape (<creditor> <sep> <id-code> <sep> <ACCOUNT bare> <sep> $<money>)
            # but COMMA-delimited; comma is kept OUT of train so ACROFILE stays a TRUE generalization test, and
            # comma is itself a distinctive punctuation+space delimiter like these, so the cue generalizes.
            # v11 round-4 first taught this delimiter-agnostically and lifted ACROFILE account recall 0.89->0.97;
            # but it ALSO included TAB and DOUBLE-SPACE -- generic WHITESPACE indistinguishable from ordinary
            # table/alignment spacing -- which made the model read ANY whitespace-separated number as account
            # (phones / ZIPs / barcodes / masked card tails -> account FPs, and the tax_return tab-positional NEQ
            # tax_id -> account). v11 round-5 DROPS tab + double-space and keeps only distinctive punctuation:
            # recovers account precision (and tax_id/gov labeling) while holding the comma-generalization recall.
            sep = random.choice([" | ", " ; ", " :: ", " / "])
            d.decoy(random.choice(_CREDITORS)); d.add(sep)
            d.decoy(_bus_id()); d.add(sep)
            d.field(V.bank_account(form=random.choice(["bare", "bare10"])), "account_number"); d.add(sep)
            d.decoy(_money()); d.add(sep)
            d.decoy(random.choice(["R1", "I9", "O0", "PAYE", "PAID", "OUVERT", "OPEN"])); d.add(" (")
            d.decoy(_masked_acct()); d.add(")\n")
            continue
        d.decoy(random.choice(_CREDITORS)); d.add(" (")
        _decoy_phone(d, phones); d.add(") ")      # the creditor's phone is a DECOY (not the subject's)
        d.decoy(_bus_id()); d.add("\n  ")
        d.decoy(_mmYY()); d.add("  "); d.decoy(_mmYY()); d.add("  "); d.decoy(_mmYY()); d.add("  ")
        d.decoy(_money()); d.add("  "); d.decoy(_money()); d.add("  "); d.decoy(_money()); d.add("\n  ")
        # the FULL account number -> positive ; the masked tail beside it -> decoy
        d.add("Account Number: " if not fr else "Numero de compte: ")
        d.field(V.bank_account(form=random.choice(["bare", "bare10", "hyphen"])), "account_number")
        d.add("   (")
        d.decoy(_masked_acct()); d.add(")\n  ")
        d.add("Description: " if not fr else "Description: ")
        d.decoy(random.choice(_DESCRIPTIONS)); d.add("\n  ")
        d.add("Trade Payment Profile: " if not fr else "Profil de paiement: ")
        d.decoy(_pmt_grid()); d.add("\n")


def _inquiries(d: Doc, fr: bool, phones=frozenset()) -> None:
    """Inquiries section: each line is a member-name DECOY + an inquiry-date DECOY + member phone DECOY.
    Member phone DECOYS avoid the subject phone_number positives (`phones`) to prevent identical-string
    contradictory supervision."""
    d.add(("Demandes de credit:\n" if fr else "Inquiries:\n"))
    d.add("Date                 Member Name              Telephone\n")
    for _ in range(random.randint(2, 4)):
        d.decoy(_mmYY()); d.add("           ")
        d.decoy(random.choice(_CREDITORS)); d.add("        ")
        _decoy_phone(d, phones); d.add("\n")
    d.add(("Nombre total de demandes: " if fr else "Total number of inquiries: ")); d.decoy(str(random.randint(1, 40))); d.add("\n")


def _summary_scores(d: Doc, fr: bool) -> None:
    """Score / summary section: Risk Score + Bankruptcy Navigator Index + account counts -> all DECOYS."""
    d.add(("Pointage de risque Equifax: " if fr else "Equifax Risk Score: ")); d.decoy(_score()); d.add("\n")
    d.add("Bankruptcy Navigator Index: "); d.decoy(_score()); d.add("\n")
    d.add(("Utilisation du credit: " if fr else "Credit Utilization: "))
    d.decoy(str(random.randint(1, 99)) + "%"); d.add("   "); d.decoy(_money()); d.add("\n")


# ================= layout A (train): Equifax CA labeled "Field: value" consumer disclosure =================

def _dob_line(d: "Doc", lang: str, fr: bool) -> None:
    """Emit a date_of_birth positive with a VARIED birth-date cue. v11 round-5: the held-out ACROFILE cues DOB
    with a TERSE GLUED-HYPHEN bureau code ('BDS-1984-10-28'), but the train layouts only taught the formal
    'Date of Birth:' / 'DOB:' colon-space forms -- so the model missed EVERY ACROFILE BDS- DOB (54 of 2931 to O,
    the one genuine round-4 leak; the DOB collision rule means an uncued date is a decoy, so the model can ONLY
    know a date is a birthdate from its cue, and a cue it never saw is unlearnable). Teach a DIVERSE terse
    glued-hyphen bureau cue vocabulary so the glued-abbreviation->DOB pattern is learned (cue coverage, same
    accepted philosophy as round-2's terse-cue diversity; the held-out document STRUCTURE stays unseen and its
    bytes are unchanged -- only train gains the cue vocabulary)."""
    r = random.random()
    if r < 0.45:
        d.add("Date de naissance: " if fr else "Date of Birth: ")
    elif r < 0.7:
        d.add("DDN: " if fr else "DOB: ")
    else:
        d.add(random.choice(["BDS", "BD", "DDN", "DN", "DNAISS", "DOB", "NAISS"]) + "-")   # terse glued bureau cue
    d.field(V.dob(lang), "date_of_birth"); d.add("\n")


def _layout_disclosure(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="credit_report", lang=lang)

    d.add("DOSSIER DE CREDIT DU CONSOMMATEUR\n" if fr else "CONSUMER CREDIT FILE\n")
    d.add("1-800-465-7166   "); d.decoy(V.iso_date()); d.add("\n")     # bureau phone + report date (decoys)
    d.add(("Dossier demande par: " if fr else "File Requested by: "))
    d.decoy(V.username().upper()); d.add("\n\n")                        # requester code -> decoy

    d.add("Identification\n" if not fr else "Identification\n")
    d.add("Nom: " if fr else "Name: "); d.field(_name_caps(lang), "person"); d.add("\n")
    d.add(("Adresse actuelle: " if fr else "Current Address: "))
    d.field(_addr_line(lang), "address"); d.add(", " + V.city() + ", QC, ")    # city + QC -> negative
    d.field(V.postal_code(), "postal_code"); d.add("\n")
    d.add(("Adresse precedente: " if fr else "Previous Address: "))
    d.field(_addr_line(lang), "address"); d.add(", " + V.city() + ", QC, ")
    d.field(V.postal_code(), "postal_code"); d.add("\n")
    _dob_line(d, lang, fr)
    # SIN line: full Luhn-valid SIN -> government_id ; the masked form beside it -> decoy
    d.add("NAS: " if fr else "SIN: "); d.field(V.sin(valid=True), "government_id")
    d.add("   (" + ("masque: " if fr else "masked: ")); d.decoy(_masked_sin()); d.add(")\n")
    d.add(("Reference: " if fr else "Reference: ")); d.decoy(V.username().upper()); d.add("\n")
    d.add(("Numero unique: " if fr else "Unique Number: ")); d.field(_opaque_file_ref(), "sensitive_account_id"); d.add("\n")
    d.add(("Numero de dossier: " if fr else "File Number: ")); d.field(_opaque_file_ref(), "sensitive_account_id"); d.add("\n")
    # TERSE FILE marker -> sensitive_account_id (opaque file ref, no formal label). Mirrors the held-out
    # 'FILE <ref>' shape but uses the OPAQUE alphanumeric _opaque_file_ref() (collision rule 1: a bare/dashed
    # numeric run must stay account_number, never sensitive_account_id); co-occurs with the terse positional
    # account_number that _member_trades now emits below.
    d.add(("Ref. dossier " if fr else "FILE "))
    d.field(_opaque_file_ref(), "sensitive_account_id"); d.add("\n")

    # former / also-known-as names -> person positives (subject's prior identities)
    d.add(("Ancienne adresse: " if fr else "Former Address: "))
    d.field(_addr_line(lang), "address"); d.add(", " + V.city() + ", QC, ")
    d.field(V.postal_code(), "postal_code"); d.add("\n")
    d.add(("Aussi connu sous: " if fr else "AKA/Also Known As: ")); d.field(_name_caps(lang), "person"); d.add("\n")
    subj_phone = V.phone()
    d.add(("Telephone #: " if fr else "Telephone #: ")); d.field(subj_phone, "phone_number")
    d.add(("  Residence\n" if fr else "  Residential/Home\n"))
    # email on file -> email positive (~50%); mirrors the held-out GEN INFO email shape via the same V.email()
    if random.random() < 0.5:
        d.add(("Courriel au dossier: " if fr else "Email on file: ")); d.field(V.email(), "email"); d.add("\n")

    # Employment: the LABELED employer header -> organization positive
    d.add("Emploi\n" if fr else "Employment\n")
    d.add(("Employeur actuel: " if fr else "Current Employer: ")); d.field(V.company(lang), "organization")
    d.add(", " + ("PROPRIETAIRE\n" if fr else "OWNER\n"))

    phones = {subj_phone}
    _summary_scores(d, fr)
    _inquiries(d, fr, phones)
    _member_trades(d, fr, phones)
    d.add("Fin du rapport\n" if fr else "End of Report\n")
    return d.row()


# ================= layout B (train): Identification + a Banking + Member-Trades TABLE form =================

def _layout_banking(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="credit_report", lang=lang)

    d.add("DOSSIER DE CREDIT DU CONSOMMATEUR\n" if fr else "CONSUMER CREDIT FILE\n")
    d.add(("Numero unique " if fr else "Unique Number ")); d.field(_opaque_file_ref(), "sensitive_account_id"); d.add("\n")
    d.add(("Numero de dossier " if fr else "File Number ")); d.field(_opaque_file_ref(), "sensitive_account_id"); d.add("\n")
    # TERSE FILE marker -> sensitive_account_id (opaque alphanumeric _opaque_file_ref(); collision rule 1:
    # a bare/dashed numeric run stays account_number, never sensitive_account_id);
    # co-occurs in this same doc with the terse positional account_number from _member_trades.
    d.add(("Ref. dossier " if fr else "FILE "))
    d.field(_opaque_file_ref(), "sensitive_account_id"); d.add("\n")
    d.add(("Date d'ouverture du dossier: " if fr else "Date File Opened: ")); d.decoy(V.iso_date()); d.add("\n")
    d.add(("Date de derniere activite: " if fr else "Date of Last Activity: ")); d.decoy(V.iso_date()); d.add("\n")

    # Identification as a labeled block, but with a former-address + 2nd-former-address stack (real variant)
    _dob_line(d, lang, fr)
    d.add("NAS: " if fr else "SIN: "); d.decoy(_masked_sin()); d.add("   ")     # masked SIN shown first -> decoy
    d.add(("(complet: " if fr else "(full: ")); d.field(V.sin(valid=True), "government_id"); d.add(")\n")
    d.add("Nom: " if fr else "Name: "); d.field(_name_caps(lang), "person"); d.add("\n")
    d.add(("Adresse actuelle: " if fr else "Current Address: "))
    d.field(_addr_line(lang), "address"); d.add(", " + V.city() + ", QC, ")
    d.field(V.postal_code(), "postal_code"); d.add("\n")
    d.add(("Depuis: " if fr else "Since: ")); d.decoy(_mmYY()); d.add("\n")
    d.add(("Ancienne adresse: " if fr else "Former Address: "))
    d.field(_addr_line(lang), "address"); d.add(", " + V.city() + ", QC, ")
    d.field(V.postal_code(), "postal_code"); d.add("\n")
    d.add(("2e ancienne adresse: " if fr else "2nd Former Address: "))
    d.field(_addr_line(lang), "address"); d.add(", " + V.city() + ", QC, ")
    d.field(V.postal_code(), "postal_code"); d.add("\n")

    subj_phone = V.phone()
    phones = {subj_phone}

    d.add("Emploi\n" if fr else "Employment\n")
    cur_employer = V.company(lang)
    d.add(("Employeur actuel: " if fr else "Current Employer: ")); d.field(cur_employer, "organization"); d.add("\n")
    # past employer name -> DECOY (collision rule 3): same KIND of name, unlabeled line. Resample so it is
    # never byte-identical to the labeled current-employer org positive in this same doc.
    d.add(("Ancien employeur: " if fr else "Former Employer: "))
    d.decoy(_resample(lambda: V.company(lang), {cur_employer})); d.add("\n")

    # Banking / Checking-Saving section as a TABLE: Rptd Opnd Amount AccountNo AccountType
    d.add("Banking\n" if not fr else "Operations bancaires\n")
    d.add("Rptd          Opnd      Amount        Account No        Account Type\n")
    for _ in range(random.randint(1, 3)):
        d.decoy(random.choice(_CREDITORS)); d.add(", "); d.decoy(_bus_id()); d.add(", (")
        _decoy_phone(d, phones); d.add(")\n")
        d.decoy(_mmYY()); d.add("    "); d.decoy(_mmYY()); d.add("    "); d.decoy(_money()); d.add("    ")
        d.field(V.bank_account(form="hyphen"), "account_number"); d.add("    ")
        d.decoy(random.choice(["Chequing/Saving", "Cheque/Epargne", "Compte courant"])); d.add("\n")

    _summary_scores(d, fr)
    _member_trades(d, fr, phones)
    d.add(("Telephone #: " if fr else "Telephone #: ")); d.field(subj_phone, "phone_number"); d.add("\n")
    # email on file -> email positive (~50%); same V.email() shape as the held-out GEN INFO email
    if random.random() < 0.5:
        d.add(("Courriel au dossier: " if fr else "Email on file: ")); d.field(V.email(), "email"); d.add("\n")
    d.add("Fin du rapport\n" if fr else "End of Report\n")
    return d.row()


# ============ layout C (HELD-OUT): the ACROFILE terse one-line annotated machine format ============
# Structurally distinct: NO "Field:" prefixes. One-line records, asterisk-delimited blocks, US-style ZIP/SSN
# look-alikes, "*CONSUMER, X, Y" + "BDS-DD/MM/YYYY, SSN ..." + "****FORMER NAME - ...****". The model never
# trains on this skeleton.

def _zip5() -> str:
    """A US-style 5-digit ZIP in an ACROFILE address line. NOT a Quebec postal code -> NEGATIVE decoy
    (postal collision rule: only a G/H/J FSA with delivery context is postal_code)."""
    return f"{random.randint(10000, 99999)}"


def _acro_addr() -> str:
    """A terse ACROFILE address fragment '9412, MAIN, ST' -> the street part, fielded as address."""
    return f"{random.randint(10, 9999)}, " + random.choice(
        ["MAIN", "ORANGE GROVE", "KENNEDY", "RIVERSIDE", "DES ERABLES", "DU PARC"]) + ", " + \
        random.choice(["ST", "DR", "AVE", "RUE", "BLVD"])


def _layout_acrofile(lang: str) -> dict:
    fr = lang == "fr"     # ACROFILE is natively terse English; FR adds accented annotations only
    d = Doc(doctype="credit_report", lang=lang)

    # subject phone_number positives in this doc (TELEPHONE + CELLULAR) -> every phone DECOY must avoid them
    subj_tel = V.phone()
    subj_cell = V.phone()
    phones = {subj_tel, subj_cell}

    d.add("SAMPLE REPORT: ACROFILE\n")
    d.add("*ADDRESS DISCREPANCY - NO SUBSTANTIAL DIFFERENCE\n")
    d.add("*" * 60 + "\n")
    d.add("  * EXTENDED FRAUD VICTIM\n  * ACTIVE MILITARY\n")
    d.add("*" * 60 + "\n")
    # bureau line: a creditor/member org + bureau phone -> decoys (collision: org in a member line = negative)
    d.add("*001 "); d.decoy("Equifax Information Services"); d.add("\n")
    d.add("   "); d.decoy(_acro_addr()); d.add(" GA "); d.decoy(_zip5()); d.add(" "); _decoy_phone(d, phones); d.add("\n")

    # subject identity record: "*CONSUMER, JOHN, Q, JR  SINCE 03/10/81 FAD 12/28/05  FN-238"
    d.add("*"); d.field(_name_caps(lang), "person")
    d.add("   SINCE "); d.decoy(_mmYY()); d.add(" FAD "); d.decoy(_mmYY())
    d.add("   FN-"); d.decoy(str(random.randint(100, 999))); d.add("\n")     # FN file-seq tag -> decoy

    # address one-liner with ZIP (decoy) + reported date (decoy)
    d.add(" "); d.field(_acro_addr(), "address"); d.add(", QC "); d.decoy(_zip5())
    d.add(", TAPE RPT "); d.decoy(_mmYY()); d.add("\n")
    d.add("   TELEPHONE "); d.field(subj_tel, "phone_number"); d.add("  CRT RPTD "); d.decoy(_mmYY()); d.add("\n")
    # a second (former) address one-liner
    d.add(" "); d.field(_acro_addr(), "address"); d.add(", QC "); d.decoy(_zip5())
    d.add(", CRT RPT "); d.decoy(_mmYY()); d.add("\n")

    # AKA + former name -> person positives (the subject's prior identities)
    d.add("   ****ALSO KNOWN AS - "); d.field(_name_caps(lang), "person"); d.add("****\n")
    d.add("   ****FORMER NAME - "); d.field(_name_caps(lang), "person"); d.add("****\n")

    # "BDS-03/03/1961, SSN 900-00-0000 SSN VER: Y" : BDS = birth-date cue -> date_of_birth ; SSN masked -> decoy
    d.add("BDS-"); d.field(V.dob("en"), "date_of_birth")
    d.add(", SSN "); d.decoy(_masked_sin()); d.add(" SSN VER: Y\n")
    # a follow-on line showing the FULL government id (the only government_id positive in this layout)
    d.add("   ID TYPE C "); d.field(V.sin(valid=True), "government_id")
    # FILE ref -> sensitive_account_id. Use the OPAQUE _opaque_file_ref() (NOT a bare 10-digit run) so it
    # obeys collision rule 1 (sensitive_account_id = opaque/alphanumeric; a bare numeric run stays
    # account_number) and matches the TRAIN sensitive shape -- the v11 round-1/2 account<->sensitive confusion
    # came from a bare-numeric sensitive_account_id being byte-identical to account_number's bare10 form.
    d.add("   FILE "); d.field(_opaque_file_ref(), "sensitive_account_id"); d.add("\n")

    # ALERT CONTACT block with a full street ADDRESS + the GEN INFO email-hint line
    d.add("01 ALERT CONTACT* - MILITARY, RPTD- "); d.decoy(_mmYY()); d.add(", EFFECT: "); d.decoy(_mmYY()); d.add("\n")
    d.add(" ADDRESS - "); d.field(_acro_addr(), "address"); d.add(", APARTMENT "); d.decoy(str(random.randint(1, 99)))
    d.add(", QC, "); d.decoy(_zip5()); d.add("\n")
    d.add(" CELLULAR, "); d.field(subj_cell, "phone_number"); d.add("\n")
    d.add(" DAYTIME, "); _decoy_phone(d, phones); d.add(", EXT-"); d.decoy(str(random.randint(100, 99999))); d.add("\n")
    d.add(" GEN INFO: "); d.field(V.email(), "email"); d.add("\n")

    # Summary one-liner: "*SUM- 07/82-01/06, PR/OI-YES, ACCTS:7, HC$450-160K" -> all decoys
    d.add("*SUM- "); d.decoy(_mmYY()); d.add("-"); d.decoy(_mmYY())
    d.add(", PR/OI-YES, FB-NO, ACCTS:"); d.decoy(str(random.randint(1, 9)))
    d.add(", HC"); d.decoy(_money()); d.add("\n")
    d.add("INQUIRY ALERT - SUBJECT SHOWS "); d.decoy(str(random.randint(1, 9))); d.add(" INQUIRIES SINCE "); d.decoy(_mmYY()); d.add("\n")

    # terse tradeline one-liners: "06 11/05* LIEN, 111VF000, 1234567, $580" + masked tail + payment grid
    for _ in range(random.randint(2, 3)):
        d.add(f"{random.randint(1,9):02d} "); d.decoy(_mmYY()); d.add("* ")
        d.decoy(random.choice(_CREDITORS)); d.add(", "); d.decoy(_court_no()); d.add(", ")
        d.field(V.bank_account(form="bare"), "account_number"); d.add(", ")
        d.decoy(_money()); d.add(", VF, "); d.decoy(_mmYY()); d.add("  TAIL("); d.decoy(_masked_acct()); d.add(")\n")
        d.add("   PMT "); d.decoy(_pmt_grid()); d.add("\n")

    d.add("*****PUBLIC RECORDS OR OTHER INFORMATION*****\n")
    d.add("04 "); d.decoy(_mmYY()); d.add("* BKRPT "); d.decoy(_court_no())
    d.add(", DSP-"); d.decoy(_mmYY()); d.add(", INDIVD, PERSONAL\n")
    d.add("End of Report\n")
    return d.row()


LAYOUTS = [_layout_disclosure, _layout_banking, _layout_acrofile]   # acrofile (suffix) = held-out structure


def gen(lang: str = None, split: str = "train") -> dict:
    lang = lang or ("fr" if random.random() < 0.65 else "en")
    return layouts.choose(split, LAYOUTS)(lang)


if __name__ == "__main__":
    random.seed(0)
    for sp in ("train", "heldout"):
        r = gen(split=sp); t = r["input"]
        print("=" * 70, sp, r["meta"]["lang"], r["meta"]["doctype"])
        print(t[:600])
        print("POSITIVES:", [(lab, t[s:e]) for s, e, lab in r["output"]["spans"]])
        print()
