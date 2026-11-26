"""Strictly read-only workspace scanner for FMagenticL v3.0."""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

_SKIP_DIRS = {".git/objects", ".git/refs", "node_modules", "__pycache__", ".venv", "venv"}
_HIGH_RISK_SYMLINK_TARGETS = {
    ".claude", ".cursor", ".vscode", ".mcp.json", "node_modules", ".git", "agents.md", "claude.md", "skill.md"
}
_WORKSPACE_SURFACES = {"workspace_config", "mcp_transport", "container_and_host"}


@dataclass
class WorkspaceFinding:
    signature_id: str
    severity: str
    title: str
    file_path: str
    line_number: int
    matched_indicator: str
    mitigation_steps: List[str]
    references: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class WorkspaceScanner:
    """Strictly read-only scanner evaluating workspace files against CONFIRMED_SIGNATURE entries."""

    def __init__(self, client: Optional[Any] = None):
        if client is None:
            from fmagenticl.client.middleware import FMagenticLClient
            client = FMagenticLClient(air_gap=True)
        self.client = client

    def _load_workspace_signatures(self) -> List[Dict[str, Any]]:
        sigs: List[Dict[str, Any]] = []
        if hasattr(self.client, "list_signatures"):
            for sig in self.client.list_signatures(confidence_tier="CONFIRMED_SIGNATURE", limit=1000):
                surface = (sig.get("observable") or {}).get("surface")
                if surface in _WORKSPACE_SURFACES:
                    sigs.append(sig)
        return sigs

    @staticmethod
    def _match_file_path(rel_lower: str, filename_lower: str, pattern_list: List[str]) -> bool:
        for pat in pattern_list:
            p = pat.strip().lower().rstrip("/")
            if not p:
                continue
            if rel_lower == p or rel_lower.startswith(p + "/") or filename_lower == p:
                return True
        return False

    @staticmethod
    def _find_line(text: str, regex: re.Pattern) -> Optional[int]:
        m = regex.search(text)
        if not m:
            return None
        return text[: m.start()].count("\n") + 1

    def scan_workspace(
        self,
        root_path: Union[str, Path],
        max_file_bytes: int = 2_000_000,
    ) -> Dict[str, Any]:
        root = Path(root_path)
        if not root.exists() or not root.is_dir():
            return {
                "root_path": str(root),
                "clean": True,
                "scanned_files": 0,
                "findings": [],
            }

        root_resolved = root.resolve()
        signatures = self._load_workspace_signatures()
        symlink_sig = next((s for s in signatures if s.get("id") == "SIG-2026-0030"), None)

        findings: List[WorkspaceFinding] = []
        scanned_files = 0

        for path in sorted(root.rglob("*")):
            try:
                rel_posix = path.relative_to(root).as_posix()
            except ValueError:
                continue
            rel_lower = rel_posix.lower()
            name_lower = path.name.lower()

            # Check symlinks BEFORE skip_dir filter
            if path.is_symlink():
                try:
                    resolved = path.resolve(strict=True)
                    in_root = resolved.is_relative_to(root_resolved)
                except OSError:
                    in_root = False
                is_high_risk = (
                    name_lower in _HIGH_RISK_SYMLINK_TARGETS
                    or rel_lower.startswith((".claude/", ".cursor/", ".vscode/"))
                )
                if not in_root or is_high_risk:
                    sig_id = symlink_sig["id"] if symlink_sig else "SIG-2026-0030"
                    sev = symlink_sig["severity"] if symlink_sig else "HIGH"
                    title = symlink_sig["title"] if symlink_sig else "Symlink Escape at Workspace Config or Skip Path"
                    mit = symlink_sig["mitigation_steps"] if symlink_sig else ["Remove escaping or high-risk symlink."]
                    refs = symlink_sig["references"] if symlink_sig else []
                    findings.append(
                        WorkspaceFinding(
                            signature_id=sig_id,
                            severity=sev,
                            title=title,
                            file_path=rel_posix,
                            line_number=1,
                            matched_indicator=f"symlink={rel_posix} in_root={in_root}",
                            mitigation_steps=list(mit),
                            references=list(refs),
                        )
                    )
                continue

            if any(rel_lower == s or rel_lower.startswith(s + "/") for s in _SKIP_DIRS):
                continue

            try:
                if not path.is_file() or not path.resolve().is_relative_to(root_resolved):
                    continue
                if path.stat().st_size > max_file_bytes:
                    continue
            except OSError:
                continue

            scanned_files += 1
            try:
                text = path.read_bytes().decode("utf-8", errors="replace")
            except OSError:
                continue

            for sig in signatures:
                if sig.get("id") == "SIG-2026-0030":
                    continue
                obs = sig.get("observable") or {}
                file_pats = obs.get("file_paths") or []
                if file_pats and not self._match_file_path(rel_lower, name_lower, file_pats):
                    continue
                if not file_pats:
                    continue

                regex_str = obs.get("detection_regex")
                config_keys = obs.get("config_keys") or []
                matched_line: Optional[int] = None
                matched_ind: str = ""

                if regex_str:
                    try:
                        pat = re.compile(regex_str, re.IGNORECASE)
                        m = pat.search(text)
                        if m:
                            matched_line = text[: m.start()].count("\n") + 1
                            matched_ind = m.group(0)[:80]
                    except re.error:
                        pass

                if matched_line is None and config_keys:
                    for ck in config_keys:
                        leaf = ck.split(".")[-1].replace("*", "").strip()
                        if leaf and leaf.lower() in text.lower():
                            idx = text.lower().find(leaf.lower())
                            matched_line = text[:idx].count("\n") + 1
                            matched_ind = ck
                            break

                if matched_line is not None:
                    findings.append(
                        WorkspaceFinding(
                            signature_id=sig["id"],
                            severity=sig["severity"],
                            title=sig["title"],
                            file_path=rel_posix,
                            line_number=matched_line,
                            matched_indicator=matched_ind,
                            mitigation_steps=list(sig.get("mitigation_steps") or []),
                            references=list(sig.get("references") or []),
                        )
                    )

        return {
            "root_path": str(root),
            "clean": len(findings) == 0,
            "scanned_files": scanned_files,
            "findings": [f.to_dict() for f in findings],
        }
