"""Deploy mirror guard for the CPU gate service.

`deploy/gate_service_cpu.py` is the artifact named in the deploy runbook, while
`gate/gate_service_cpu.py` is the in-repo gate-service copy covered by the gate docs. They must not silently
drift: a previous edit fixed Finding C in `gate/` while the deploy artifact still had the old positional
`/redact` loop. Keep them byte-identical until one path is deliberately retired.
"""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_deploy_cpu_gate_matches_gate_copy():
    gate_copy = ROOT / 'gate' / 'gate_service_cpu.py'
    deploy_copy = ROOT / 'deploy' / 'gate_service_cpu.py'
    assert deploy_copy.read_text(encoding='utf-8') == gate_copy.read_text(encoding='utf-8')
