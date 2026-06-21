"""C9: IPv6 floor (the IP rule was IPv4-only). Full + ::-compressed forms; no FP on times/versions."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from privacy_gate import tier0_spans  # noqa: E402


def _ips(t):
    return {t[s['start']:s['end']] for s in tier0_spans(t) if s['label'] == 'ip_address'}


def test_ipv6_forms():
    assert "2001:0db8:85a3:0000:0000:8a2e:0370:7334" in _ips("addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334 end")
    assert "fe80::1ff:fe23:4567:890a" in _ips("link fe80::1ff:fe23:4567:890a")
    assert "2606:4700:4700::1111" in _ips("dns 2606:4700:4700::1111 ok")


def test_ipv6_no_false_positive():
    assert _ips("the time is 12:34:56 today") == set()
    assert _ips("run std::vector<int> v") == set()
    assert _ips("ratio 16:9 aspect") == set()


def test_ipv4_still_works():
    assert "192.168.1.55" in _ips("host 192.168.1.55 up")
