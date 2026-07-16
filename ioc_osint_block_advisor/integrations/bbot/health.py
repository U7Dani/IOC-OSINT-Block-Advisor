"""End-to-end health check / diagnostics for the BBOT integration.

Never installs anything silently. When a capability is unavailable, the
report explains exactly why (missing binary, missing WSL distro, missing
Docker, missing API key, incompatible module, ...) instead of a bare
"Error".
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field

from .discovery import detect_runtime, discover_capabilities
from .models import BBOTCapabilities, BBOTRuntimeStatus
from .settings import BBOTSettings, default_workdir


@dataclass
class BBOTHealthReport:
    runtime: BBOTRuntimeStatus
    capabilities: BBOTCapabilities
    workdir_writable: bool
    workdir_path: str
    wsl_available: bool
    docker_available: bool
    settings_valid: bool
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.runtime.available and self.capabilities.loaded and self.workdir_writable


def run_health_check(settings: BBOTSettings) -> BBOTHealthReport:
    problems: list[str] = []

    runtime = detect_runtime(settings)
    if not runtime.available:
        problems.append(f"BBOT no disponible: {runtime.reason or 'motivo desconocido'}")

    capabilities = discover_capabilities(runtime, settings) if runtime.available else BBOTCapabilities(loaded=False)
    if runtime.available and not capabilities.loaded:
        problems.append("BBOT respondió, pero no se pudieron leer módulos/presets/output modules.")
    problems.extend(capabilities.warnings)

    workdir = default_workdir(settings)
    workdir_writable = _check_writable(workdir)
    if not workdir_writable:
        problems.append(f"El directorio de trabajo de BBOT no es escribible: {workdir}")

    wsl_available = shutil.which("wsl.exe") is not None or shutil.which("wsl") is not None
    docker_available = shutil.which("docker") is not None

    settings_valid = settings.runtime in ("auto", "native", "wsl", "docker", "disabled")
    if not settings_valid:
        problems.append(f"Valor de runtime inválido en configuración: '{settings.runtime}'.")

    return BBOTHealthReport(
        runtime=runtime,
        capabilities=capabilities,
        workdir_writable=workdir_writable,
        workdir_path=str(workdir),
        wsl_available=wsl_available,
        docker_available=docker_available,
        settings_valid=settings_valid,
        problems=problems,
    )


def _check_writable(path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False
