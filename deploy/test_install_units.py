"""Static contracts for desktop and headless OSSRedact systemd units.

These tests inspect repository unit text only. They deliberately do not contact a
systemd manager or resolve a user's home directory.
"""
import re
from ipaddress import ip_address
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]

USER_CPU = Path('deploy/systemd/user/ossredact-gate-cpu.service')
USER_EGRESS = Path('deploy/systemd/user/ossredact-egress.service')
SYSTEM_CPU = Path('deploy/ossredact-gate-cpu.service')
SYSTEM_EGRESS = Path('deploy/ossredact-egress.service')
PRIVATE_GPU = tuple(
    path.relative_to(ROOT)
    for path in sorted((ROOT / 'deploy').glob('ossredact-gate-gpu-*.service'))
)

ALL_UNITS = {
    'user CPU gate': USER_CPU,
    'user egress proxy': USER_EGRESS,
    'system CPU gate': SYSTEM_CPU,
    'system egress proxy': SYSTEM_EGRESS,
}
CPU_UNITS = {
    'user CPU gate': USER_CPU,
    'system CPU gate': SYSTEM_CPU,
}
EGRESS_UNITS = {
    'user egress proxy': USER_EGRESS,
    'system egress proxy': SYSTEM_EGRESS,
}

COMMON_HARDENING = {
    'NoNewPrivileges': 'yes',
    'PrivateTmp': 'yes',
    'CapabilityBoundingSet': '',
    'AmbientCapabilities': '',
    'RestrictSUIDSGID': 'yes',
    'LockPersonality': 'yes',
    'ProtectKernelTunables': 'yes',
    'ProtectKernelModules': 'yes',
    'ProtectKernelLogs': 'yes',
    'ProtectControlGroups': 'yes',
    'RestrictAddressFamilies': 'AF_UNIX AF_INET AF_INET6',
    'UMask': '0077',
    'ProtectHome': 'read-only',
    'ProtectSystem': 'strict',
}


def _read_unit(relative_path: Path) -> dict[str, dict[str, list[str]]]:
    """Return active systemd directives without interpreting install-time specifiers."""
    sections: dict[str, dict[str, list[str]]] = {}
    current_section: str | None = None

    for raw_line in (ROOT / relative_path).read_text(encoding='utf-8').splitlines():
        line = raw_line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if line.startswith('[') and line.endswith(']'):
            current_section = line[1:-1]
            sections.setdefault(current_section, {})
            continue

        assert current_section is not None, f'{relative_path}: directive outside a section: {line}'
        key, value = line.split('=', 1)
        sections[current_section].setdefault(key, []).append(value)

    return sections


def _values(unit: dict[str, dict[str, list[str]]], section: str, key: str) -> list[str]:
    return unit.get(section, {}).get(key, [])


def _value(unit: dict[str, dict[str, list[str]]], section: str, key: str) -> str:
    values = _values(unit, section, key)
    assert len(values) == 1, f'expected one {section}.{key}, found {values!r}'
    return values[0]

def _private_gpu_path() -> Path:
    assert len(PRIVATE_GPU) == 1, (
        'expected exactly one private GPU gate unit matching '
        'deploy/ossredact-gate-gpu-*.service, '
        f'found {[path.as_posix() for path in PRIVATE_GPU]!r}'
    )
    return PRIVATE_GPU[0]


def test_expected_desktop_and_headless_unit_names_exist_at_relative_paths():
    assert tuple(path.as_posix() for path in ALL_UNITS.values()) == (
        'deploy/systemd/user/ossredact-gate-cpu.service',
        'deploy/systemd/user/ossredact-egress.service',
        'deploy/ossredact-gate-cpu.service',
        'deploy/ossredact-egress.service',
    )
    assert tuple(path.name for path in ALL_UNITS.values()) == (
        'ossredact-gate-cpu.service',
        'ossredact-egress.service',
        'ossredact-gate-cpu.service',
        'ossredact-egress.service',
    )
    missing = [path.as_posix() for path in ALL_UNITS.values() if not (ROOT / path).is_file()]
    assert not missing, f'missing expected install units: {missing}'


def test_desktop_units_use_user_install_tree_optional_environment_and_default_target():
    cpu = _read_unit(USER_CPU)
    egress = _read_unit(USER_EGRESS)

    assert _value(cpu, 'Service', 'WorkingDirectory') == '%h/.local/share/ossredact/gate'
    assert _value(cpu, 'Service', 'ExecStart') == (
        '%h/.local/share/ossredact/.venv/bin/python '
        '%h/.local/share/ossredact/gate/gate_service_cpu.py'
    )
    assert 'CPU_GATE_MODEL=%h/.local/share/ossredact/models/ossredact-pii-base-int8' in _values(
        cpu, 'Service', 'Environment'
    )

    assert _value(egress, 'Service', 'WorkingDirectory') == '%h/.local/share/ossredact/appliance'
    assert _value(egress, 'Service', 'ExecStart') == (
        '%h/.local/share/ossredact/.venv/bin/python '
        '%h/.local/share/ossredact/appliance/egress_proxy.py'
    )

    for unit in (cpu, egress):
        assert _value(unit, 'Unit', 'Documentation') == 'file:%h/.local/share/ossredact/QUICKSTART.md'
        assert _values(unit, 'Service', 'EnvironmentFile') == ['-%h/.config/ossredact/environment']
        assert _value(unit, 'Install', 'WantedBy') == 'default.target'


def test_headless_units_retain_opt_install_tree_and_multi_user_target():
    cpu = _read_unit(SYSTEM_CPU)
    egress = _read_unit(SYSTEM_EGRESS)

    assert _value(cpu, 'Service', 'WorkingDirectory') == '/opt/ossredact/gate'
    assert _value(cpu, 'Service', 'ExecStart') == (
        '/opt/ossredact/.venv/bin/python /opt/ossredact/gate/gate_service_cpu.py'
    )
    assert 'CPU_GATE_MODEL=/opt/ossredact/models/ossredact-pii-base-int8' in _values(
        cpu, 'Service', 'Environment'
    )

    assert _value(egress, 'Service', 'WorkingDirectory') == '/opt/ossredact/appliance'
    assert _value(egress, 'Service', 'ExecStart') == (
        '/opt/ossredact/.venv/bin/python /opt/ossredact/appliance/egress_proxy.py'
    )

    for unit in (cpu, egress):
        assert not _values(unit, 'Service', 'EnvironmentFile')
        assert _value(unit, 'Install', 'WantedBy') == 'multi-user.target'


def test_cpu_and_egress_services_keep_loopback_only_port_contracts():
    for name, path in CPU_UNITS.items():
        environment = _values(_read_unit(path), 'Service', 'Environment')
        assert 'CPU_GATE_HOST=127.0.0.1' in environment, name
        assert 'CPU_GATE_PORT=8001' in environment, name

    for name, path in EGRESS_UNITS.items():
        environment = _values(_read_unit(path), 'Service', 'Environment')
        assert 'GATEWAY_HOST=127.0.0.1' in environment, name
        assert 'GATEWAY_PORT=8011' in environment, name
        assert 'GATEWAY_GATE_URL=http://127.0.0.1:8001' in environment, name


def test_all_units_keep_the_common_hardening_profile():
    for name, path in ALL_UNITS.items():
        unit = _read_unit(path)
        for directive, expected_value in COMMON_HARDENING.items():
            assert _value(unit, 'Service', directive) == expected_value, f'{name}: {directive}'


def test_private_devices_is_reserved_for_cpu_gate_units():
    for name, path in CPU_UNITS.items():
        assert _value(_read_unit(path), 'Service', 'PrivateDevices') == 'yes', name

    for name, path in EGRESS_UNITS.items():
        assert not _values(_read_unit(path), 'Service', 'PrivateDevices'), name


def test_egress_state_writes_remain_narrow_and_scope_specific():
    assert not _values(_read_unit(USER_CPU), 'Service', 'ReadWritePaths')
    assert not _values(_read_unit(SYSTEM_CPU), 'Service', 'ReadWritePaths')
    assert _values(_read_unit(USER_EGRESS), 'Service', 'ReadWritePaths') == ['-%h/.ossredact']


def test_system_egress_state_path_uses_the_configured_service_account_home():
    egress = _read_unit(SYSTEM_EGRESS)
    service_user = _value(egress, 'Service', 'User')

    assert service_user == 'ossredact'
    assert _values(egress, 'Service', 'ReadWritePaths') == [
        f'-/home/{service_user}/.ossredact'
    ]


def test_headless_install_rewrites_egress_state_path_for_selected_service_account():
    readme = (ROOT / 'deploy/README.md').read_text(encoding='utf-8')
    heading = '## Headless system-service installation (`/opt`)'
    _, separator, following_sections = readme.partition(heading)
    assert separator, f'missing {heading!r}'
    headless_installation, _, _ = following_sections.partition('\n## ')

    substitutions = {
        (
            match.group('source')
            .replace(r'\$', '$')
            .replace(r'\.', '.')
            .replace(r'\/', '/'),
            match.group('replacement')
            .replace(r'\$', '$')
            .replace(r'\.', '.')
            .replace(r'\/', '/'),
        )
        for match in re.finditer(
            r'''
                s(?P<delimiter>[^A-Za-z0-9\s])
                (?P<source>(?:\\.|(?!(?P=delimiter))[^\n])*)
                (?P=delimiter)
                (?P<replacement>(?:\\.|(?!(?P=delimiter))[^\n])*)
                (?P=delimiter)
            ''',
            headless_installation,
            re.VERBOSE,
        )
    }

    assert ('^User=ossredact$', 'User=$USER') in substitutions
    assert any(
        '/home/ossredact/.ossredact' in source
        and '/home/$USER/.ossredact' in replacement
        for source, replacement in substitutions
    )


@pytest.mark.skipif(
    not PRIVATE_GPU,
    reason='private GPU gate checks are unavailable in the public profile',
)
def test_gpu_gate_uses_uuid_cuda_selection_for_non_loopback_bind():
    environment = _values(_read_unit(_private_gpu_path()), 'Service', 'Environment')
    gpu_hosts = [
        setting.removeprefix('GPU_GATE_HOST=')
        for setting in environment
        if setting.startswith('GPU_GATE_HOST=')
    ]
    cuda_devices = [
        setting
        for setting in environment
        if setting.startswith('CUDA_VISIBLE_DEVICES=')
    ]

    assert len(gpu_hosts) == 1
    assert not ip_address(gpu_hosts[0]).is_loopback
    assert len(cuda_devices) == 1
    assert re.fullmatch(
        r'CUDA_VISIBLE_DEVICES=GPU-[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}',
        cuda_devices[0],
    )


@pytest.mark.skipif(
    not PRIVATE_GPU,
    reason='private GPU gate checks are unavailable in the public profile',
)
def test_gpu_gate_uses_required_root_environment_file_without_token_value():
    unit = _read_unit(_private_gpu_path())

    assert _values(unit, 'Service', 'EnvironmentFile') == ['/etc/ossredact/gpu-gate.env']
    assert not any(
        'TOKEN' in setting.partition('=')[0].upper()
        for setting in _values(unit, 'Service', 'Environment')
    )


@pytest.mark.skipif(
    not PRIVATE_GPU,
    reason='private GPU gate checks are unavailable in the public profile',
)
def test_gpu_gate_keeps_cuda_compatible_common_hardening():
    unit = _read_unit(_private_gpu_path())

    for directive, expected_value in COMMON_HARDENING.items():
        assert _value(unit, 'Service', directive) == expected_value, directive
    assert not _values(unit, 'Service', 'PrivateDevices')


@pytest.mark.skipif(
    not PRIVATE_GPU,
    reason='private GPU gate checks are unavailable in the public profile',
)
def test_gpu_gate_uses_private_cache_without_writable_paths():
    unit = _read_unit(_private_gpu_path())
    environment = _values(unit, 'Service', 'Environment')
    cache_root = '/var/cache/ossredact-gpu-gate'

    assert 'PYTHONDONTWRITEBYTECODE=1' in environment
    assert f'XDG_CACHE_HOME={cache_root}' in environment
    assert f'HF_HOME={cache_root}/huggingface' in environment
    assert f'TORCH_HOME={cache_root}/torch' in environment
    assert f'CUDA_CACHE_PATH={cache_root}/cuda' in environment
    assert _value(unit, 'Service', 'CacheDirectory') == 'ossredact-gpu-gate'
    assert _value(unit, 'Service', 'CacheDirectoryMode') == '0700'
    assert not _values(unit, 'Service', 'ReadWritePaths')
