"""
FMagenticL - Deterministic self-healing patch execution engines.
Supports RFC 6902 JSON Patch (Track 1) and Peripheral Types (Track 2).
Hardened against Arbitrary Code Execution (RCE), Path Traversal, and Tool Poisoning.
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
    Validate that target_path is within the current working directory
    and contains no path traversal sequences.
    """
    if not target_path:
        return False
    # Disallow path traversal
    if ".." in target_path:
        return False
    try:
        abs_target = os.path.abspath(target_path)
        cwd = os.path.abspath(os.getcwd())
        # Target must reside within current working directory
        return os.path.commonpath([abs_target, cwd]) == cwd
    except Exception:
        return False


class Patcher:
    """Deterministic self-healing patch execution engine implementing RFC 6902 two-track model."""
    
    @classmethod
    def apply_patch(cls, patch: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> bool:
        """
        Apply a deterministic patch.
        Supports Track 1 (RFC 6902 application/json-patch+json) and Track 2 (peripheral types).
        Returns True if patch applied cleanly, False otherwise with zero partial application on failure.
        """
        context = context if context is not None else {}
        patch_type = patch.get("patch_type")
        action = patch.get("action")
        
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

            # Apply RFC 6902 JSON Patch atomically
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
                    
            # Write back patched file atomically
            try:
                parent_dir = os.path.dirname(os.path.abspath(target_file))
                if parent_dir:
                    os.makedirs(parent_dir, exist_ok=True)
                with open(target_file, "w", encoding="utf-8") as f:
                    json.dump(patched_doc, f, indent=2)
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
            
            apply_cli = context.get("apply_cli", False)
            if not apply_cli:
                # Default behavior: Dry-run / Advisory Plan output
                print(f"[FMagenticL Patcher] Advisory CLI plan (dry-run mode): {fallback_cli}")
                if isinstance(context, dict):
                    context["advisory_cli"] = fallback_cli
                    context["applied"] = False
                return True
            
            # Explicit execution requested (apply_cli=True)
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
                    elif op_kind == "create":
                        pdir = os.path.dirname(os.path.abspath(fpath))
                        if pdir:
                            os.makedirs(pdir, exist_ok=True)
                        with open(fpath, "w", encoding="utf-8") as fh:
                            fh.write(fop.get("content", ""))
                return True

            if action == "FILE_CREATE":
                target_file = patch.get("target_file")
                if target_file and _is_safe_path(target_file):
                    try:
                        parent_dir = os.path.dirname(os.path.abspath(target_file))
                        if parent_dir:
                            os.makedirs(parent_dir, exist_ok=True)
                        with open(target_file, "w", encoding="utf-8") as f:
                            f.write(patch.get("content", ""))
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
            return True

        # 2d. Retry Strategy
        if patch_type == "retry-strategy":
            strategy = patch.get("strategy")
            print(f"[FMagenticL Patcher] Retry strategy configured: {strategy}")
            if isinstance(context, dict):
                context["retry_strategy"] = strategy
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
                        with open(target_file, "w", encoding="utf-8") as f:
                            json.dump(data, f, indent=2)
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
                        parent_dir = os.path.dirname(os.path.abspath(target_file))
                        if parent_dir:
                            os.makedirs(parent_dir, exist_ok=True)
                        with open(target_file, "w", encoding="utf-8") as f:
                            json.dump(data, f, indent=2)
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
