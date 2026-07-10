"""C: US ZIP detection, cue-gated (City, ST 12345 / zip: 12345) so bare 5-digit numbers are not nuked."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from privacy_gate import tier0_spans  # noqa: E402


def _zips(t):
    return {t[s['start']:s['end']] for s in tier0_spans(t) if s.get('rule') == 'tier0:us_zip'}


def test_state_cue_zip():
    assert _zips("Austin, TX 78701 USA") == {"78701"}
    assert _zips("Boston, MA 02108-1234 now") == {"02108-1234"}


def test_keyword_zip():
    assert _zips("zip code: 94043") == {"94043"}
    assert _zips("shipping ZIP 02110 fast") == {"02110"}


def test_no_false_positives():
    assert _zips("ok, in 12345 records found") == set()      # lowercase 'in' is not a state code
    assert _zips("the year was, well 12345 units") == set()  # 'well' not a 2-letter state
    assert _zips("order 78701 shipped today") == set()       # no comma/state/keyword cue
    assert _zips("call, ext 90210 please") == set()          # 'ext' not a state


def test_canadian_postal_not_us_zip():
    # QC is not a US state; CA postal is owned by POSTAL_RE, not the US-ZIP pass
    assert _zips("Montreal, QC H2X 1Y4") == set()
