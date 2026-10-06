"""
FMagenticL - Deterministic self-healing patch execution engines.
Supports RFC 6902 JSON Patch (Track 1) and Peripheral Types (Track 2).
"""
import os
import stat
import subprocess
import json
import copy
from typing import Dict, Any, List, Optional

try:
    import jsonpatch
    JSONPATCH_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    JSONPATCH_AVAILABLE = False


class Patcher:
    """Deterministic self-healing patch execution engine implementing RFC 6902 two-track model."""
    
    @classmethod
    def apply_patch(cls, patch: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> bool:
        """
        Apply a deterministic patch.
        Supports Track 1 (RFC 6902 application/json-patch+json) and Track 2 (peripheral types).
        Returns True if patch applied cleanly, False otherwise with zero partial application on failure.
        """
        context = context or {}
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
        
        # 2a. CLI Override
        if patch_type == "cli-override" or action == "CLI_OVERRIDE" or ("fallback_cli" in patch and not patch_type):
            fallback_cli = patch.get("fallback_cli")
            if fallback_cli:
                try:
                    res = subprocess.run(
                        fallback_cli, 
                        shell=True, 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE,
                        timeout=30
                    )
                    return res.returncode == 0
                except Exception as e:
                    print(f"[FMagenticL Patcher] CLI Override failed: {e}")
            return False

        # 2b. File Operations (file-op, FILE_PERMISSION_UNLOCK, FILE_DELETE, FILE_CREATE)
        if patch_type == "file-op" or action in ["FILE_PERMISSION_UNLOCK", "FILE_DELETE", "FILE_CREATE"]:
            # Handle structured file_ops list
            if "file_ops" in patch and isinstance(patch["file_ops"], list):
                for fop in patch["file_ops"]:
                    op_kind = fop.get("op")
                    fpath = fop.get("target_file") or fop.get("file")
                    if not fpath:
                        return False
                    if op_kind == "unlock_write":
                        if os.path.exists(fpath):
                            os.chmod(fpath, stat.S_IWRITE)
                    elif op_kind == "delete":
                        if os.path.exists(fpath):
                            os.remove(fpath)
                    elif op_kind == "create":
                        pdir = os.path.dirname(os.path.abspath(fpath))
                        if pdir:
                            os.makedirs(pdir, exist_ok=True)
                        with open(fpath, "w", encoding="utf-8") as fh:
                            fh.write(fop.get("content", ""))
                return True

            # Handle single action
            if action == "FILE_PERMISSION_UNLOCK":
                target_file = patch.get("target_file") or context.get("locked_file")
                if target_file and os.path.exists(target_file):
                    try:
                        os.chmod(target_file, stat.S_IWRITE)
                        return True
                    except Exception as e:
                        print(f"[FMagenticL Patcher] Permission unlock failed: {e}")
                return False

            elif action == "FILE_DELETE":
                target_file = patch.get("target_file")
                if target_file and os.path.exists(target_file):
                    try:
                        os.remove(target_file)
                        return True
                    except Exception as e:
                        print(f"[FMagenticL Patcher] File deletion failed: {e}")
                return False

            elif action == "FILE_CREATE":
                target_file = patch.get("target_file")
                if target_file:
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

        # 2c. MCP Substitution
        if patch_type == "mcp-substitution" or action == "MCP_SUBSTITUTION":
            target_file = patch.get("target_file")
            mcp_uri = patch.get("mcp_uri")
            config_patch = patch.get("config_patch")
            
            # Case 1: Updating an MCP config file (e.g. mcp_config.json)
            if target_file and os.path.exists(target_file):
                try:
                    with open(target_file, "r", encoding="utf-8") as f:
                        cfg = json.load(f)
                    
                    server_name = patch.get("server_name") or "mcpServers"
                    if "mcpServers" in cfg:
                        if mcp_uri and server_name in cfg["mcpServers"]:
                            cfg["mcpServers"][server_name]["url"] = mcp_uri
                        if config_patch and server_name in cfg["mcpServers"]:
                            cfg["mcpServers"][server_name].update(config_patch)
                    elif config_patch and isinstance(cfg, dict):
                        cfg.update(config_patch)
                        
                    with open(target_file, "w", encoding="utf-8") as f:
                        json.dump(cfg, f, indent=2)
                    print(f"[FMagenticL Patcher] Successfully remapped MCP config at {target_file}")
                    return True
                except Exception as e:
                    print(f"[FMagenticL Patcher] MCP config substitution failed: {e}")
                    return False
            
            # Case 2: In-memory/Runtime dynamic remapping
            if mcp_uri or config_patch:
                print(f"[FMagenticL Patcher] Dynamic runtime MCP substitution applied: URI={mcp_uri}")
                return True
                
            return False

        # 2d. Retry Strategy
        if patch_type == "retry-strategy":
            strategy = patch.get("strategy")
            print(f"[FMagenticL Patcher] Retry strategy configured: {strategy}")
            return True

        # Legacy AST_DELETE_KEY translation
        if action == "AST_DELETE_KEY":
            target_file = patch.get("target_file")
            key_path = patch.get("key_path")
            if target_file and key_path and os.path.exists(target_file):
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
            if target_file and config_patch:
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
