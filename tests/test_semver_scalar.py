from packaging.version import parse as parse_version
from packaging.specifiers import SpecifierSet

def match_semver(runtime_str: str, required_spec: str) -> bool:
    """Matches runtime strings like 'node@24.15.0' against specifier sets like '>=20.0.0, <25.0.0'."""
    try:
        parts = runtime_str.split("@")
        if len(parts) != 2:
            return False
        ver = parse_version(parts[1])
        spec = SpecifierSet(required_spec)
        return ver in spec
    except Exception:
        return False

def test_semver_scalar_filtering():
    # Scenario: Patch is verified for node >= 22.0.0, < 25.0.0
    spec = ">=22.0.0, <25.0.0"
    
    assert match_semver("node@24.15.0", spec) is True
    assert match_semver("node@22.1.0", spec) is True
    assert match_semver("node@20.10.0", spec) is False
    assert match_semver("node@26.0.0", spec) is False

def test_npm_semver_filtering():
    spec = ">=11.0.0, <12.0.0"
    assert match_semver("npm@11.12.1", spec) is True
    assert match_semver("npm@11.12.5", spec) is True
    assert match_semver("npm@10.8.2", spec) is False
