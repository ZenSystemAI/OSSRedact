"""Deploy mirror guard for the CPU gate service.

`deploy/gate_service_cpu.py` is the artifact named in the deploy runbook, while
`gate/gate_service_cpu.py` is the in-repo gate-service copy covered by the gate docs. They must not silently
drift: a previous edit fixed Finding C in `gate/` while the deploy artifact still had the old positional
`/redact` loop. Keep them byte-identical until one path is deliberately retired.

Phase 4: GATE_TOKEN bind/auth policy must land in gate/deploy service copies together (same source
bytes), and ``gate_http_policy.py`` must stay byte-identical across gate/, deploy/, and appliance/.
"""

import os
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_deploy_cpu_gate_matches_gate_copy():
    gate_copy = ROOT / 'gate' / 'gate_service_cpu.py'
    deploy_copy = ROOT / 'deploy' / 'gate_service_cpu.py'
    assert deploy_copy.read_text(encoding='utf-8') == gate_copy.read_text(encoding='utf-8')


def test_deploy_and_gate_cpu_share_gate_token_policy_surface():
    """Policy symbols (or their absence) cannot diverge between deploy and gate CPU copies."""
    gate_copy = (ROOT / 'gate' / 'gate_service_cpu.py').read_text(encoding='utf-8')
    deploy_copy = (ROOT / 'deploy' / 'gate_service_cpu.py').read_text(encoding='utf-8')
    assert deploy_copy == gate_copy
    # When policy is present, both copies carry the same contract tokens; when absent, both are red
    # together via test_gate_http_policy.py service wiring checks.
    for needle in ('GATE_TOKEN', 'X-OSSRedact-Gate-Token', 'gate_http_policy', 'require_gate_token_configured'):
        assert (needle in gate_copy) == (needle in deploy_copy)


def test_gate_http_policy_mirrors_are_byte_identical():
    """Pure GATE_TOKEN helpers cannot drift across gate, deploy, and appliance trees."""
    gate_policy = ROOT / 'gate' / 'gate_http_policy.py'
    deploy_policy = ROOT / 'deploy' / 'gate_http_policy.py'
    appliance_policy = ROOT / 'appliance' / 'gate_http_policy.py'
    missing = [p.relative_to(ROOT).as_posix() for p in (gate_policy, deploy_policy, appliance_policy) if not p.is_file()]
    assert not missing, (
        'gate_http_policy.py must exist in gate/, deploy/, and appliance/ '
        f'(missing: {", ".join(missing)})'
    )
    gate_bytes = gate_policy.read_bytes()
    assert deploy_policy.read_bytes() == gate_bytes
    assert appliance_policy.read_bytes() == gate_bytes


def test_default_drift_manifest_covers_gate_http_policy():
    """Default remote drift checks include the auth-policy runtime input."""
    drift_script = (ROOT / 'deploy' / 'check-gate-drift.sh').read_text(encoding='utf-8')
    default_manifest = re.search(
        r'(?ms)^else\n\s*FILES=\(\n(?P<files>.*?)^\s*\)\nfi$',
        drift_script,
    )

    assert default_manifest is not None, 'drift checker must declare a default FILES manifest'
    assert 'gate/gate_http_policy.py' in default_manifest.group('files').split()


def test_alternate_cpu_drift_manifest_uses_exact_repo_relative_gate_files():
    """The alternate CPU example names only the repo-relative gate runtime inputs."""
    drift_script = (ROOT / 'deploy' / 'check-gate-drift.sh').read_text(encoding='utf-8')
    cpu_example = re.search(
        r'(?m)^#\s*GATE_HOST=\S+\b.*\bGATE_FILES="(?P<files>[^"]*)".*$',
        drift_script,
    )

    assert cpu_example is not None, 'drift checker must document the alternate CPU GATE_FILES example'
    assert cpu_example.group('files').split() == [
        'gate/gate_service_cpu.py',
        'gate/privacy_gate.py',
        'gate/gate_http_policy.py',
    ]


def test_missing_gate_host_fails_before_ssh_boundary(tmp_path: Path):
    """Drift checks fail closed rather than selecting an implicit remote host."""
    fake_bin = tmp_path / "bin"
    fake_ssh = fake_bin / "ssh"
    marker = tmp_path / "ssh-invoked"
    fake_bin.mkdir()
    fake_ssh.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$*" > "$OSSREDACT_FAKE_SSH_MARKER"\n',
        encoding="utf-8",
    )
    fake_ssh.chmod(0o755)

    environment = os.environ.copy()
    environment.pop("GATE_HOST", None)
    environment.update(
        {
            "GATE_FILES": "gate/gate_http_policy.py",
            "GATE_REMOTE_BASE": "synthetic-remote",
            "OSSREDACT_FAKE_SSH_MARKER": str(marker),
        }
    )
    environment["PATH"] = f"{fake_bin}{os.pathsep}{environment.get('PATH', '')}"

    completed = subprocess.run(
        ["bash", str(ROOT / "deploy" / "check-gate-drift.sh")],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    assert completed.returncode != 0
    assert not marker.exists(), "checker invoked ssh without an explicitly selected gate host"


def test_gate_readme_deployment_lists_http_policy_runtime_input():
    """Deployment guidance lists the auth-policy file copied to the gate host."""
    readme = (ROOT / 'gate' / 'README.md').read_text(encoding='utf-8')
    deploy_section = readme.split('## Deploy', 1)[1].split('## Tests', 1)[0]

    assert '`gate_http_policy.py`' in deploy_section


def test_gate_readme_documents_checker_remote_base_variable():
    """Deployment guidance uses the checker's actual remote-base variable."""
    readme = (ROOT / 'gate' / 'README.md').read_text(encoding='utf-8')
    deploy_section = readme.split('## Deploy', 1)[1].split('## Tests', 1)[0]

    assert '`GATE_REMOTE_BASE`' in deploy_section


def test_gate_readme_does_not_name_unsupported_remote_dir_variable():
    """Deployment guidance does not advertise a variable the checker ignores."""
    readme = (ROOT / 'gate' / 'README.md').read_text(encoding='utf-8')
    deploy_section = readme.split('## Deploy', 1)[1].split('## Tests', 1)[0]

    assert 'GATE_REMOTE_DIR' not in deploy_section
