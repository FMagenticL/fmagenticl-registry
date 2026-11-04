import yaml
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"


def test_all_github_workflows_parse_valid_yaml():
    """Every workflow file in .github/workflows/ must parse cleanly via PyYAML and contain valid step strings."""
    yml_files = sorted(WORKFLOWS_DIR.glob("*.yml"))
    assert len(yml_files) >= 2, "Expected at least deploy.yml and harvest.yml"

    for yml_path in yml_files:
        content = yml_path.read_text(encoding="utf-8")
        data = yaml.safe_load(content)
        assert isinstance(data, dict), f"{yml_path.name} did not parse to a dict"
        assert "name" in data and isinstance(data["name"], str), f"{yml_path.name} missing 'name'"
        assert "jobs" in data and isinstance(data["jobs"], dict), f"{yml_path.name} missing 'jobs'"

        # Concurrency writer lock check
        if yml_path.name in ("deploy.yml", "harvest.yml"):
            conc = data.get("concurrency", {})
            assert conc.get("group") == "registry-writer", f"{yml_path.name} must use registry-writer concurrency group"
            assert conc.get("cancel-in-progress") is False, f"{yml_path.name} must set cancel-in-progress: false"

        for job_name, job_spec in data["jobs"].items():
            assert "timeout-minutes" in job_spec, f"{yml_path.name}:{job_name} missing timeout-minutes"
            steps = job_spec.get("steps", [])
            assert len(steps) > 0, f"{yml_path.name}:{job_name} has 0 steps"
            for idx, step in enumerate(steps):
                if "run" in step:
                    assert isinstance(step["run"], str), (
                        f"{yml_path.name}:{job_name} step #{idx} ('{step.get('name')}') "
                        f"'run' parsed as {type(step['run']).__name__} instead of str (unquoted YAML flow mapping!)"
                    )
