from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable


BASE_DIR = Path(__file__).resolve().parents[1]


def resource_path(relative_path: str) -> Path:
    """Return a project resource path that also works from a PyInstaller bundle."""
    bundle_dir = getattr(sys, "_MEIPASS", None)
    if bundle_dir:
        return Path(bundle_dir) / relative_path
    return BASE_DIR / relative_path


def runtime_output_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "output"
    return BASE_DIR / "output"


CONFIG_DIR = resource_path("config")
OUTPUT_DIR = runtime_output_dir()


def load_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [
        line.strip().lower()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def load_allowlist() -> set[str]:
    return set(load_lines(CONFIG_DIR / "allowlist_domains.txt"))


def load_suspicious_keywords() -> set[str]:
    return set(load_lines(CONFIG_DIR / "suspicious_keywords.txt"))


def is_domain_or_subdomain(domain: str, candidate_parent: str) -> bool:
    domain = (domain or "").lower().strip(".")
    parent = (candidate_parent or "").lower().strip(".")
    return domain == parent or domain.endswith(f".{parent}")


def is_allowlisted(domain: str, allowlist: Iterable[str] | None = None) -> bool:
    allowlist_set = set(allowlist or load_allowlist())
    return any(is_domain_or_subdomain(domain, item) for item in allowlist_set)


def ensure_output_dir() -> Path:
    output_dir = runtime_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir
