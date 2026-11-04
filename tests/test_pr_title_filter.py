"""Exact-behaviour tests for the linked-PR title exclusion gate in harvest_github_failures."""
import pytest
from scripts.harvest_github_failures import is_excluded_pr_title


@pytest.mark.parametrize("title", [
    "feat(stdlib): add take/skip iterator adapters to baml.iter",
    "feat: allow `json?` literal values",
    "[Test] linear: Expect replicated rows to skip TP symmetric memory",
    "Document that runtime validation arguments are not applied to BaseSettings",
    "docs: fix typo", "chore: bump deps", "ci: pin runner", "chore(release): 1.2.3",
    "test: add coverage", "Add regression test for #12", "refactor(core): split module", "[CI] flaky job",
])
def test_non_fix_titles_excluded(title):
    assert is_excluded_pr_title(title) is True


@pytest.mark.parametrize("title", [
    "fix(temporal): run workflow lifecycle hooks",
    "Fix crash when a non-streaming Chat Completions response has no choices",
    "Return 422 instead of 503/500 for invalid values in request bodies",
    "[Fix] moe: Skip hash layers before topk_config in prefill",
    "Raise ValueError when a model returns the wrong number of embeddings",
])
def test_genuine_fix_titles_kept(title):
    assert is_excluded_pr_title(title) is False


def test_none_and_empty_safe():
    assert is_excluded_pr_title("") is False
    assert is_excluded_pr_title(None) is False
