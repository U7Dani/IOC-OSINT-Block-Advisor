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


def load_trusted_saas() -> set[str]:
    return set(load_lines(CONFIG_DIR / "trusted_saas_domains.txt"))


def load_suspicious_keywords() -> set[str]:
    return set(load_lines(CONFIG_DIR / "suspicious_keywords.txt"))


def is_domain_or_subdomain(domain: str, candidate_parent: str) -> bool:
    domain = (domain or "").lower().strip(".")
    parent = (candidate_parent or "").lower().strip(".")
    return domain == parent or domain.endswith(f".{parent}")


def is_allowlisted(domain: str, allowlist: Iterable[str] | None = None) -> bool:
    allowlist_set = set(allowlist or load_allowlist())
    return any(is_domain_or_subdomain(domain, item) for item in allowlist_set)


def is_trusted_saas(domain: str, trusted: Iterable[str] | None = None) -> bool:
    trusted_set = set(trusted if trusted is not None else load_trusted_saas())
    return any(is_domain_or_subdomain(domain, item) for item in trusted_set)


# ---------------------------------------------------------------------------
# Allowlist por capas: cliente/organización (protección Fluidra)
# ---------------------------------------------------------------------------

def load_client_allowlist() -> set[str]:
    return set(load_lines(CONFIG_DIR / "client_allowlist_domains.txt"))


def load_client_senders() -> set[str]:
    return set(load_lines(CONFIG_DIR / "client_allowlist_senders.txt"))


def load_client_keywords() -> set[str]:
    return set(load_lines(CONFIG_DIR / "client_allowlist_keywords.txt"))


def load_tenant_allowlist() -> set[str]:
    return set(load_lines(CONFIG_DIR / "client_tenant_domains.txt"))


def load_review_only() -> set[str]:
    return set(load_lines(CONFIG_DIR / "review_only_domains.txt"))


def is_client_domain(domain: str, client_domains: Iterable[str] | None = None) -> bool:
    """Dominio o subdominio de la organización protegida (p. ej. Fluidra)."""
    domains = set(client_domains if client_domains is not None else load_client_allowlist())
    return any(is_domain_or_subdomain(domain, item) for item in domains)


def is_client_tenant(domain: str, tenants: Iterable[str] | None = None) -> bool:
    """Tenant corporativo legítimo configurado (p. ej. fluidra.sharepoint.com)."""
    tenant_set = set(tenants if tenants is not None else load_tenant_allowlist())
    return any(is_domain_or_subdomain(domain, item) for item in tenant_set)


def is_client_sender(email: str, senders: Iterable[str] | None = None, client_domains: Iterable[str] | None = None) -> bool:
    """Remitente protegido: exacto, @dominio, dominio, o dominio del cliente."""
    email = (email or "").lower().strip()
    if "@" not in email:
        return False
    domain = email.rsplit("@", 1)[-1]
    sender_set = set(senders if senders is not None else load_client_senders())
    for entry in sender_set:
        entry = entry.lower().strip()
        if not entry:
            continue
        if entry.startswith("@"):
            if is_domain_or_subdomain(domain, entry[1:]):
                return True
        elif "@" in entry:
            if email == entry:
                return True
        elif is_domain_or_subdomain(domain, entry):
            return True
    return is_client_domain(domain, client_domains)


def is_review_only(domain: str, review_only: Iterable[str] | None = None) -> bool:
    review_set = set(review_only if review_only is not None else load_review_only())
    return any(is_domain_or_subdomain(domain, item) for item in review_set)


def ensure_output_dir() -> Path:
    output_dir = runtime_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir
