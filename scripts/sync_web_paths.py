#!/usr/bin/env python3
"""Sync the iStrix common web paths database.

Fetches curated web path lists from public sources (SecLists, assetnote)
and merges them into ``config/web_paths.yaml``.

Exit code 0 = no changes; exit code 1 = file modified (needs commit).
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from urllib.request import Request, urlopen

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
WEB_PATHS_PATH = PROJECT_ROOT / "config" / "web_paths.yaml"

# Curated sources of common web paths
_SOURCES = [
    {
        "name": "SecLists Discovery/Web-Content common.txt",
        "url": (
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
            "Discovery/Web-Content/common.txt"
        ),
    },
    {
        "name": "assetnote wordlists (raft-small-directories)",
        "url": (
            "https://raw.githubusercontent.com/assetnote/wordlists/master/"
            "data/automated/httparchive_directories_1m_2022_08_28.txt"
        ),
    },
]


def load_web_paths(path: Path) -> dict:
    """Load existing web_paths.yaml."""
    if path.exists():
        with open(path) as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}
    return {"metadata": {}, "paths": []}


def save_web_paths(path: Path, data: dict) -> None:
    """Write web_paths.yaml."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        yaml.safe_dump(data, f, default_flow_style=False, allow_unicode=True,
                       sort_keys=False)


def fetch_paths_from_source(source: dict[str, str]) -> set[str]:
    """Download a path list and return unique paths."""
    paths: set[str] = set()
    try:
        req = Request(source["url"], headers={"User-Agent": "iStrix-path-sync/0.1"})
        with urlopen(req, timeout=30) as resp:
            for line in resp:
                try:
                    decoded = line.decode("utf-8").strip()
                except UnicodeDecodeError:
                    decoded = line.decode("latin-1").strip()
                if not decoded or decoded.startswith("#"):
                    continue
                if len(decoded) > 200:
                    continue
                # Normalize
                if not decoded.startswith("/"):
                    decoded = "/" + decoded
                paths.add(decoded)
    except Exception as exc:
        print(f"[sync_web_paths] Fetch error ({source['name']}): {exc}", file=sys.stderr)
    else:
        print(f"[sync_web_paths] Fetched {len(paths)} paths from {source['name']}", file=sys.stderr)
    return paths


def merge_paths(existing: dict, new_paths: set[str]) -> tuple[dict, bool]:
    """Merge new paths into existing, deduplicating. Returns (merged, changed)."""
    current = set(existing.get("paths", []))
    to_add = new_paths - current

    if not to_add:
        print("[sync_web_paths] No new paths to add.")
        return existing, False

    merged = sorted(current | new_paths)
    existing["paths"] = merged
    print(f"[sync_web_paths] Added {len(to_add)} new paths (total: {len(merged)}).")
    return existing, True


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync iStrix web paths database")
    parser.add_argument("--limit", type=int, default=5000,
                        help="Max paths to keep (default: 5000)")
    parser.add_argument("--check-only", action="store_true",
                        help="Exit 1 if an update is available but do not write")
    args = parser.parse_args()

    existing = load_web_paths(WEB_PATHS_PATH)

    all_new: set[str] = set()
    for source in _SOURCES:
        paths = fetch_paths_from_source(source)
        all_new |= paths

    merged, changed = merge_paths(existing, all_new)

    # Trim to limit
    paths = merged.get("paths", [])
    if len(paths) > args.limit:
        merged["paths"] = paths[:args.limit]
        changed = True
        print(f"[sync_web_paths] Trimmed paths to {args.limit}")

    merged.setdefault("metadata", {})
    merged["metadata"]["last_updated"] = datetime.utcnow().strftime("%Y-%m-%d")
    merged["metadata"]["path_count"] = len(merged.get("paths", []))

    if not changed:
        print("[sync_web_paths] No changes needed.")
        return 0

    if args.check_only:
        print("[sync_web_paths] Changes available but --check-only set.")
        return 1

    save_web_paths(WEB_PATHS_PATH, merged)
    print(f"[sync_web_paths] Written {WEB_PATHS_PATH} ({merged['metadata']['path_count']} paths).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
