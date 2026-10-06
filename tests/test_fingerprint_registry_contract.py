"""
Registry contract test.

Verifies that every RAW_SEED_CASE in seed_hermes.py hashes to the
fingerprint stored in its corresponding patch file under patches/.

If this test fails, the client cannot resolve any patch in the registry:
the seed data has drifted from the fingerprint algorithm, or the
patches/ directory was regenerated with a different algorithm.

This is the end-to-end verification that links:
    seed_hermes.RAW_SEED_CASES
        -> fingerprint.compute_fingerprint
            -> patches/<fingerprint>.json
"""

import json
import os

from fmagenticl.client.fingerprint import compute_fingerprint
from fmagenticl.server.seed_hermes import RAW_SEED_CASES


PATCHES_DIR = os.path.join(os.path.dirname(__file__), "..", "patches")


def test_all_seed_cases_have_corresponding_patch_file():
    """
    Every seed case must have a matching file in patches/.
    Count parity is the first check.
    """
    patch_files = [f for f in os.listdir(PATCHES_DIR) if f.endswith(".json")]
    assert len(patch_files) == len(RAW_SEED_CASES), (
        f"Patch file count ({len(patch_files)}) does not match "
        f"seed case count ({len(RAW_SEED_CASES)})"
    )


def test_seed_fingerprints_match_patch_filenames():
    """
    For every seed case, compute the fingerprint and verify a file with
    that exact name exists in patches/.

    This is the contract: the client's compute_fingerprint output must
    match the filename the CDN serves.
    """
    mismatches = []
    for case in RAW_SEED_CASES:
        fp = compute_fingerprint(case["env"], case["fail"])
        fp_hex = fp.replace("sha256:", "")
        expected_file = f"{fp_hex}.json"
        file_path = os.path.join(PATCHES_DIR, expected_file)
        if not os.path.exists(file_path):
            mismatches.append(
                {
                    "case_id": case.get("id", "<unknown>"),
                    "computed_fingerprint": fp,
                    "expected_file": expected_file,
                    "file_exists": False,
                }
            )

    assert not mismatches, (
        f"{len(mismatches)} seed cases do not resolve to a patch file.\n"
        f"First failure: {mismatches[0]}"
    )


def test_patch_files_have_matching_fingerprint_field():
    """
    Every patch file must declare a fingerprint field that matches its
    own filename. Guards against a file being renamed without its
    contents being updated.
    """
    mismatches = []
    for filename in os.listdir(PATCHES_DIR):
        if not filename.endswith(".json"):
            continue
        file_path = os.path.join(PATCHES_DIR, filename)
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        declared = data.get("fingerprint", "")
        declared_hex = declared.replace("sha256:", "")
        if declared_hex != filename.replace(".json", ""):
            mismatches.append(
                {
                    "filename": filename,
                    "declared_fingerprint": declared,
                }
            )

    assert not mismatches, (
        f"{len(mismatches)} patch files have mismatched fingerprints.\n"
        f"First failure: {mismatches[0]}"
    )
