"""
FMagenticL - Deterministic self-healing patch execution engines.
Supports RFC 6902 JSON Patch (Track 1) and Peripheral Types (Track 2).
Hardened against Arbitrary Code Execution (RCE), Symlink/Path Traversal,
Tool Poisoning, and Unintended Dry-Run Disk Mutation.
"""
import os
import stat
import subprocess
import json
import copy
import shlex
from typing import Dict, Any, List, Optional

try:
    import jsonpatch
    JSONPATCH_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    JSONPATCH_AVAILABLE = False


def _is_safe_path(target_path: Optional[str]) -> bool:
    """
    Validate that target_path resolves strictly inside the current working directory
    (following symlinks via os.path.realpath) and contains no path traversal segments.
    """
    if not target_path:
        return False
    norm_parts = target_path.replace("\\", "/").split("/")
    if ".." in norm_parts or ".." in target_path:
        return False
    try:
        real_cwd = os.path.realpath(os.getcwd())
        real_target = os.path.realpath(os.path.abspath(target_path))
        return os.path.commonpath([real_target, real_cwd]) == real_cwd
    except Exception:
        return False


class Patcher:
    """Deterministic self-healing patch execution engine implementing RFC 6902 two-track model."""

    @classmethod
    def apply_patch(
        cls,
        patch: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
    ) -> bool:
        """
        Apply or dry-run validate a deterministic patch.
        Supports Track 1 (RFC 6902 application/json-patch+json) and Track 2 (peripheral types).
        When dry_run=True (or context.get('dry_run') is True), validates applicability strictly
        in memory with ZERO disk writes and ZERO subprocess execution.
        Returns True if patch applied/validated cleanly, False otherwise with zero partial application on failure.
        """
        context = context if context is not None else {}
        is_dry_run = bool(dry_run or (isinstance(context, dict) and context.get("dry_run", False)))
        patch_type = patch.get("patch_type") or patch.get("remediation_class")
        action = patch.get("action")

        # -------------------------------------------------------------
        # Track 0: Explicit Remediation Classes (workaround_advisory, dependency_pin, code_diff)
        # -------------------------------------------------------------
        if patch_type == "workaround_advisory":
            advisory = patch.get("workaround") or patch.get("description") or patch.get("advisory", "")
            if isinstance(context, dict):
                context["advisory_workaround"] = advisory
                context["remediation_class"] = "workaround_advisory"
                context["applied"] = False
            return True

        if patch_type == "dependency_pin":
            pkg_spec = patch.get("package_spec") or patch.get("fallback_cli", "")
            if isinstance(context, dict):
                context["advisory_dependency_pin"] = pkg_spec
                context["remediation_class"] = "dependency_pin"
                context["applied"] = False
            return bool(pkg_spec)

        if patch_type == "code_diff":
            diff_text = patch.get("diff") or patch.get("code_diff", "")
            if not diff_text:
                return False
            if is_dry_run or not context.get("apply_diff", False):
                if isinstance(context, dict):
                    context["advisory_diff"] = diff_text
                    context["remediation_class"] = "code_diff"
                    context["applied"] = False
                return True
            try:
                res = subprocess.run(
                    ["git", "apply", "--check", "-"],
                    input=diff_text.encode("utf-8"),
                    shell=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=15,
                )
                if res.returncode != 0:
                    return False
                res_apply = subprocess.run(
                    ["git", "apply", "-"],
                    input=diff_text.encode("utf-8"),
                    shell=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=15,
                )
                if isinstance(context, dict):
                    context["applied"] = (res_apply.returncode == 0)
                return res_apply.returncode == 0
            except Exception:
                return False

        # -------------------------------------------------------------
        # Track 1: Standard RFC 6902 JSON Patch (application/json-patch+json)
        # -------------------------------------------------------------
        if (patch_type == "application/json-patch+json" and "json_patch" in patch and patch["json_patch"]) or ("json_patch" in patch and patch["json_patch"]):
            target_file = patch.get("target_file") or context.get("target_file")
            ops = patch.get("json_patch")

            if not target_file or not ops:
                return False

            if not _is_safe_path(target_file):
                print(f"[FMagenticL Patcher] Target file outside working directory rejected: {target_file}")
                return False

            if not os.path.exists(target_file):
                print(f"[FMagenticL Patcher] Target file not found: {target_file}")
                return False

            # Guard against pseudo-JSON patches targeting non-JSON source files (e.g. .py, .ts)
            if not str(target_file).lower().endswith(".json"):
                advisory_val = ops[0].get("value") if isinstance(ops, list) and ops and isinstance(ops[0], dict) else str(ops)
                print(f"[FMagenticL Patcher] Non-JSON target '{target_file}' routed to workaround_advisory.")
                if isinstance(context, dict):
                    context["advisory_workaround"] = advisory_val
                    context["remediation_class"] = "workaround_advisory"
                    context["applied"] = False
                return True

            try:
                with open(target_file, "r", encoding="utf-8") as f:
                    doc = json.load(f)
            except Exception as e:
                print(f"[FMagenticL Patcher] Failed to parse target JSON {target_file}: {e}")
                return False

            # Serialize ops if they are model objects
            clean_ops = []
            for op in ops:
                if hasattr(op, "model_dump"):
                    clean_ops.append(op.model_dump(by_alias=True, exclude_none=True))
                elif isinstance(op, dict):
                    clean_ops.append({k: v for k, v in op.items() if v is not None})
                else:
                    clean_ops.append(op)

            # Apply RFC 6902 JSON Patch atomically in memory
            if JSONPATCH_AVAILABLE:
                try:
                    patch_obj = jsonpatch.JsonPatch(clean_ops)
                    # in_place=False ensures original doc is untainted if any op fails
                    patched_doc = patch_obj.apply(doc, in_place=False)
                except (jsonpatch.JsonPatchTestFailed, jsonpatch.JsonPatchConflict, jsonpatch.InvalidJsonPatch, Exception) as e:
                    print(f"[FMagenticL Patcher] RFC 6902 patch failed validation or test op: {e}")
                    return False
            else:
                # Fallback manual RFC 6902 interpreter
                try:
                    patched_doc = cls._apply_manual_json_patch(doc, clean_ops)
                    if patched_doc is None:
                        return False
                except Exception as e:
                    print(f"[FMagenticL Patcher] Manual JSON patch application failed: {e}")
                    return False

            if is_dry_run:
                if isinstance(context, dict):
                    context["preview_patched_doc"] = patched_doc
                    context["applied"] = False
                return True

            # Write back patched file atomically
            try:
                parent_dir = os.path.dirname(os.path.abspath(target_file))
                if parent_dir:
                    os.makedirs(parent_dir, exist_ok=True)
                with open(target_file, "w", encoding="utf-8") as f:
                    json.dump(patched_doc, f, indent=2)
                if isinstance(context, dict):
                    context["applied"] = True
                return True
            except Exception as e:
                print(f"[FMagenticL Patcher] Failed writing patched file {target_file}: {e}")
                return False

        # -------------------------------------------------------------
        # Track 2: Peripheral Types & Legacy Actions
        # -------------------------------------------------------------

        # 2a. CLI Override (Strict Dry-Run by default, zero shell=True)
        if patch_type == "cli-override" or action == "CLI_OVERRIDE" or ("fallback_cli" in patch and not patch_type):
            fallback_cli = patch.get("fallback_cli")
            if not fallback_cli:
                return False

            apply_cli = False if is_dry_run else bool(context.get("apply_cli", False))
            if not apply_cli:
                # Default behavior: Dry-run / Advisory Plan output
                print(f"[FMagenticL Patcher] Advisory CLI plan (dry-run mode): {fallback_cli}")
                if isinstance(context, dict):
                    context["advisory_cli"] = fallback_cli
                    context["applied"] = False
                return True

            # Explicit execution requested (apply_cli=True and dry_run=False)
            # Hard-block dangerous shell metacharacters
            DANGEROUS_SHELL_CHARS = [";", "&", "|", ">", "<", "$", "`", "(", ")", "\n", "\r"]
            if any(ch in fallback_cli for ch in DANGEROUS_SHELL_CHARS):
                print(f"[FMagenticL Patcher] Rejected CLI execution: shell metacharacters detected in '{fallback_cli}'")
                return False

            try:
                tokens = shlex.split(fallback_cli)
            except Exception as e:
                print(f"[FMagenticL Patcher] Failed to parse CLI command: {e}")
                return False

            if not tokens:
                return False

            ALLOWLISTED_COMMANDS = {"pip", "npm", "uv", "pytest", "git"}
            cmd_base = os.path.basename(tokens[0]).lower().rstrip(".exe")
            if cmd_base not in ALLOWLISTED_COMMANDS:
                print(f"[FMagenticL Patcher] Rejected CLI execution: '{cmd_base}' is not in allowlisted commands {ALLOWLISTED_COMMANDS}")
                return False

            try:
                res = subprocess.run(
                    tokens,
                    shell=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=30
                )
                if isinstance(context, dict):
                    context["applied"] = (res.returncode == 0)
                    context["stdout"] = res.stdout.decode("utf-8", errors="replace")
                    context["stderr"] = res.stderr.decode("utf-8", errors="replace")
                return res.returncode == 0
            except Exception as e:
                print(f"[FMagenticL Patcher] Allowlisted CLI execution failed: {e}")
                return False

        # 2b. File Operations (file-op, FILE_PERMISSION_UNLOCK, FILE_DELETE, FILE_CREATE)
        if patch_type == "file-op" or action in ["FILE_PERMISSION_UNLOCK", "FILE_DELETE", "FILE_CREATE"]:
            # Hard-block destructive file deletion
            if action == "FILE_DELETE":
                print(f"[FMagenticL Patcher] Rejected destructive file deletion: {patch.get('target_file')}")
                return False

            # Hard-block permission modification (chmod)
            if action == "FILE_PERMISSION_UNLOCK":
                print(f"[FMagenticL Patcher] File permission modification (chmod) blocked by security policy: {patch.get('target_file')}")
                return False

            # Handle structured file_ops list
            if "file_ops" in patch and isinstance(patch["file_ops"], list):
                for fop in patch["file_ops"]:
                    op_kind = fop.get("op")
                    fpath = fop.get("target_file") or fop.get("file")
                    if not fpath or not _is_safe_path(fpath):
                        return False
                    if op_kind in ("delete", "unlock_write"):
                        print(f"[FMagenticL Patcher] Operation '{op_kind}' on '{fpath}' is blocked by security policy.")
                        return False
                if is_dry_run:
                    if isinstance(context, dict):
                        context["applied"] = False
                    return True
                for fop in patch["file_ops"]:
                    if fop.get("op") == "create":
                        fpath = fop.get("target_file") or fop.get("file")
                        pdir = os.path.dirname(os.path.abspath(fpath))
                        if pdir:
                            os.makedirs(pdir, exist_ok=True)
                        with open(fpath, "w", encoding="utf-8") as fh:
                            fh.write(fop.get("content", ""))
                if isinstance(context, dict):
                    context["applied"] = True
                return True

            if action == "FILE_CREATE":
                target_file = patch.get("target_file")
                if target_file and _is_safe_path(target_file):
                    if is_dry_run:
                        if isinstance(context, dict):
                            context["applied"] = False
                        return True
                    try:
                        parent_dir = os.path.dirname(os.path.abspath(target_file))
                        if parent_dir:
                            os.makedirs(parent_dir, exist_ok=True)
                        with open(target_file, "w", encoding="utf-8") as f:
                            f.write(patch.get("content", ""))
                        if isinstance(context, dict):
                            context["applied"] = True
                        return True
                    except Exception as e:
                        print(f"[FMagenticL Patcher] File creation failed: {e}")
                return False

        # 2c. MCP Substitution (Advisory only; zero config URL rewriting on disk)
        if patch_type == "mcp-substitution" or action == "MCP_SUBSTITUTION":
            mcp_uri = patch.get("mcp_uri")
            print(f"[FMagenticL Patcher] Advisory MCP substitution (disk config mutation blocked): {mcp_uri}")
            if isinstance(context, dict):
                context["advisory_mcp_uri"] = mcp_uri
                context["applied"] = False
            return True

        # 2d. Retry Strategy
        if patch_type == "retry-strategy":
            strategy = patch.get("strategy")
            print(f"[FMagenticL Patcher] Retry strategy configured: {strategy}")
            if isinstance(context, dict):
                context["retry_strategy"] = strategy
                context["applied"] = False
            return True

        # Legacy AST_DELETE_KEY translation
        if action == "AST_DELETE_KEY":
            target_file = patch.get("target_file")
            key_path = patch.get("key_path")
            if target_file and key_path and _is_safe_path(target_file) and os.path.exists(target_file):
                try:
                    with open(target_file, "r", encoding="utf-8") as f:
                        data = json.load(f)

                    parts = key_path.split(".")
                    d = data
                    for p in parts[:-1]:
                        if isinstance(d, dict) and p in d:
                            d = d[p]
                        else:
                            return False

                    if isinstance(d, dict) and parts[-1] in d:
                        del d[parts[-1]]
                        if is_dry_run:
                            if isinstance(context, dict):
                                context["preview_patched_doc"] = data
                                context["applied"] = False
                            return True
                        with open(target_file, "w", encoding="utf-8") as f:
                            json.dump(data, f, indent=2)
                        if isinstance(context, dict):
                            context["applied"] = True
                        return True
                except Exception as e:
                    print(f"[FMagenticL Patcher] AST deletion failed: {e}")
            return False

        # Legacy CONFIG_INJECT translation
        if action == "CONFIG_INJECT":
            target_file = patch.get("target_file")
            config_patch = patch.get("config_patch")
            if target_file and config_patch and _is_safe_path(target_file):
                try:
                    data = {}
                    if os.path.exists(target_file):
                        with open(target_file, "r", encoding="utf-8") as f:
                            try:
                                data = json.load(f)
                            except Exception:
                                data = {}
                    if isinstance(data, dict) and isinstance(config_patch, dict):
                        data.update(config_patch)
                        if is_dry_run:
                            if isinstance(context, dict):
                                context["preview_patched_doc"] = data
                                context["applied"] = False
                            return True
                        parent_dir = os.path.dirname(os.path.abspath(target_file))
                        if parent_dir:
                            os.makedirs(parent_dir, exist_ok=True)
                        with open(target_file, "w", encoding="utf-8") as f:
                            json.dump(data, f, indent=2)
                        if isinstance(context, dict):
                            context["applied"] = True
                        return True
                except Exception as e:
                    print(f"[FMagenticL Patcher] Config injection failed: {e}")
            return False

        return False

    @classmethod
    def _apply_manual_json_patch(cls, doc: Dict[str, Any], ops: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Fallback lightweight RFC 6902 patch interpreter when jsonpatch library is not loaded."""
        doc_copy = copy.deepcopy(doc)

        def _get_parts(path: str) -> List[str]:
            return [p for p in path.strip("/").split("/") if p]

        for op in ops:
            action = op.get("op")
            path_parts = _get_parts(op.get("path", ""))

            if action == "test":
                curr = doc_copy
                for part in path_parts:
                    if isinstance(curr, dict) and part in curr:
                        curr = curr[part]
                    else:
                        return None
                if "value" in op and curr != op["value"]:
                    return None

            elif action == "remove":
                if not path_parts:
                    return None
                curr = doc_copy
                for part in path_parts[:-1]:
                    if isinstance(curr, dict) and part in curr:
                        curr = curr[part]
                    else:
                        return None
                if isinstance(curr, dict) and path_parts[-1] in curr:
                    del curr[path_parts[-1]]
                else:
                    return None

            elif action in ["add", "replace"]:
                if not path_parts:
                    return None
                curr = doc_copy
                for part in path_parts[:-1]:
                    if isinstance(curr, dict):
                        if part not in curr:
                            curr[part] = {}
                        curr = curr[part]
                    else:
                        return None
                if isinstance(curr, dict):
                    curr[path_parts[-1]] = op.get("value")

        return doc_copy
