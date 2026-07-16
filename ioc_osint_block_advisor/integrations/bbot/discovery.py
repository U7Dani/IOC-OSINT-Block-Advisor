"""Runtime detection and dynamic capability discovery for BBOT.

Nothing here hardcodes a module/preset list: everything is parsed from the
output of the actually-installed ``bbot`` (native, WSL, or Docker). If BBOT
is not installed, or a specific query fails, we degrade to a structured,
explained "unavailable" status instead of crashing or fabricating data.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import time

from .command_builder import build_capability_query_argv
from .errors import BBOTCapabilityError
from .models import (
    Availability,
    BBOTCapabilities,
    BBOTModuleCapability,
    BBOTOutputModuleCapability,
    BBOTPresetCapability,
    BBOTRuntimeStatus,
)
from .settings import BBOTSettings, redact

logger = logging.getLogger(__name__)

_CAPABILITY_TIMEOUT = 20
_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?[A-Za-z0-9.\-]*)")


class _CapturedRun:
    def __init__(self, returncode: int, stdout: str, stderr: str):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _decode_output(raw: bytes) -> str:
    """Decode subprocess output, tolerating wsl.exe's quirk of emitting
    UTF-16LE (with embedded NUL bytes) instead of the requested/locale
    encoding whenever its stdout is redirected rather than a real console.
    """
    if not raw:
        return ""
    if b"\x00" in raw[:64]:
        try:
            return raw.decode("utf-16-le")
        except UnicodeDecodeError:
            pass
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode(errors="replace")


def _run_capture(argv: list[str], timeout: int = _CAPABILITY_TIMEOUT) -> _CapturedRun:
    """Blocking, short-lived capability query. Never uses shell=True."""
    try:
        completed = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            text=False,
            timeout=timeout,
            check=False,
        )
        return _CapturedRun(completed.returncode, _decode_output(completed.stdout), _decode_output(completed.stderr))
    except FileNotFoundError as exc:
        raise BBOTCapabilityError(redact(str(exc))) from exc
    except subprocess.TimeoutExpired as exc:
        raise BBOTCapabilityError(f"Comando agotó el tiempo de espera: {redact(' '.join(argv))}") from exc
    except OSError as exc:
        raise BBOTCapabilityError(redact(str(exc))) from exc


# ---------------------------------------------------------------------------
# Backend prefixes (native / WSL / Docker)
# ---------------------------------------------------------------------------


def backend_prefix(backend: str, settings: BBOTSettings) -> list[str]:
    """Argv prefix to run BBOT through the given backend. Empty for native."""
    if backend == "native":
        return []
    if backend == "wsl":
        prefix = ["wsl.exe"]
        if settings.wsl_distribution:
            prefix += ["--distribution", settings.wsl_distribution]
        prefix += ["--"]
        return prefix
    if backend == "docker":
        prefix = ["docker", "run", "--rm", "-i"]
        prefix += list(settings.docker_extra_args or [])
        prefix += [settings.docker_image or "blacklanternsecurity/bbot:stable"]
        return prefix
    raise ValueError(f"Backend desconocido: {backend}")


def _wrap_argv(backend: str, settings: BBOTSettings, bbot_argv: list[str]) -> list[str]:
    prefix = backend_prefix(backend, settings)
    if backend == "native":
        return bbot_argv
    # For wsl/docker, the executable inside bbot_argv[0] is the in-guest name.
    return [*prefix, *bbot_argv]


# ---------------------------------------------------------------------------
# Runtime detection
# ---------------------------------------------------------------------------


def _probe_backend(backend: str, settings: BBOTSettings) -> BBOTRuntimeStatus:
    executable = settings.executable or "bbot"
    try:
        argv = _wrap_argv(backend, settings, build_capability_query_argv(executable, "version"))
    except Exception as exc:  # pragma: no cover - defensive, argv building shouldn't raise here
        return BBOTRuntimeStatus(available=False, backend=backend, reason=str(exc))

    if backend == "native" and shutil.which(executable) is None:
        return BBOTRuntimeStatus(available=False, backend=backend, reason="Ejecutable 'bbot' no encontrado en PATH.")
    if backend == "wsl" and shutil.which("wsl.exe") is None and shutil.which("wsl") is None:
        return BBOTRuntimeStatus(available=False, backend=backend, reason="WSL no está disponible en este sistema.")
    if backend == "docker" and shutil.which("docker") is None:
        return BBOTRuntimeStatus(available=False, backend=backend, reason="Docker no está disponible en este sistema.")

    try:
        result = _run_capture(argv)
    except BBOTCapabilityError as exc:
        return BBOTRuntimeStatus(available=False, backend=backend, reason=str(exc))

    if result.returncode != 0:
        reason = redact(result.stderr.strip() or result.stdout.strip() or "bbot --version devolvió un código de error.")
        return BBOTRuntimeStatus(available=False, backend=backend, reason=reason)

    version_match = _VERSION_RE.search(result.stdout or result.stderr or "")
    version = version_match.group(1) if version_match else (result.stdout.strip() or "unknown")
    return BBOTRuntimeStatus(available=True, backend=backend, executable=executable, version=version)


def detect_runtime(settings: BBOTSettings) -> BBOTRuntimeStatus:
    """Detect a usable BBOT runtime according to ``settings.runtime``.

    In ``auto`` mode, tries native -> WSL -> Docker, in that order, and
    returns the first one that can actually run ``bbot --version``.
    """
    if settings.runtime == "disabled":
        return BBOTRuntimeStatus(available=False, backend="", reason="Integración BBOT deshabilitada por configuración.")

    if settings.runtime in ("native", "wsl", "docker"):
        status = _probe_backend(settings.runtime, settings)
        return status

    # auto
    attempts = []
    for backend in ("native", "wsl", "docker"):
        status = _probe_backend(backend, settings)
        if status.available:
            return status
        attempts.append(f"{backend}: {status.reason}")
    return BBOTRuntimeStatus(
        available=False,
        backend="",
        reason="Ningún runtime de BBOT disponible. " + " | ".join(attempts),
    )


# ---------------------------------------------------------------------------
# Capability parsing (tolerant text-table parsing — BBOT has no stable
# machine-readable module-listing format across versions, so this degrades
# to "loaded=False, warnings=[...]" rather than guessing wrong.)
# ---------------------------------------------------------------------------

_SEPARATOR_LINE_RE = re.compile(r"^[\s\-=_]+$")
_COLUMN_SPLIT_RE = re.compile(r" {2,}|\t+")

_MODULE_HEADER_HINTS = ("module", "name")
_PRESET_HEADER_HINTS = ("preset", "name")
_OUTPUT_HEADER_HINTS = ("output", "name")


def _split_table(raw: str) -> tuple[list[str] | None, list[list[str]]]:
    header: list[str] | None = None
    rows: list[list[str]] = []
    for line in raw.splitlines():
        line = line.rstrip()
        if not line.strip() or _SEPARATOR_LINE_RE.match(line):
            continue
        cols = [c.strip() for c in _COLUMN_SPLIT_RE.split(line.strip()) if c.strip()]
        if not cols:
            continue
        if header is None and any(h in line.lower() for h in ("name", "module", "preset", "description")):
            header = [c.lower() for c in cols]
            continue
        rows.append(cols)
    return header, rows


def _col_index(header: list[str] | None, hints: tuple[str, ...], default: int = 0) -> int:
    if not header:
        return default
    for hint in hints:
        for idx, col in enumerate(header):
            if hint in col:
                return idx
    return default


def parse_module_listing(raw: str) -> tuple[dict[str, BBOTModuleCapability], list[str]]:
    warnings: list[str] = []
    header, rows = _split_table(raw)
    modules: dict[str, BBOTModuleCapability] = {}
    if not rows:
        warnings.append("No se pudo interpretar la lista de módulos de BBOT (salida vacía o formato inesperado).")
        return modules, warnings

    name_idx = _col_index(header, _MODULE_HEADER_HINTS, 0)
    api_key_idx = _col_index(header, ("api key", "apikey", "needs api"), -1) if header else -1
    for cols in rows:
        if name_idx >= len(cols):
            warnings.append(f"Fila de módulo con formato inesperado, omitida: {cols!r}")
            continue
        name = cols[name_idx]
        if not re.match(r"^[A-Za-z0-9_\-]+$", name):
            continue
        rest = " ".join(c for i, c in enumerate(cols) if i != name_idx).lower()
        flags = set(re.findall(r"[a-z0-9_\-]+", rest))
        api_key_cell = cols[api_key_idx].strip().lower() if 0 <= api_key_idx < len(cols) else ""
        auth_required = api_key_cell in {"yes", "true", "y"} or "apikey" in rest or "api key" in rest
        modules[name] = BBOTModuleCapability(
            name=name,
            description=" ".join(c for i, c in enumerate(cols) if i != name_idx),
            flags=flags,
            passive="passive" in flags and "active" not in flags,
            active="active" in flags,
            safe="unsafe" not in flags and "aggressive" not in flags,
            loud="loud" in flags,
            invasive="invasive" in flags or "aggressive" in flags,
            auth_required=auth_required,
            installed=True,
            available=True,
        )
    return modules, warnings


def parse_preset_listing(raw: str) -> tuple[dict[str, BBOTPresetCapability], list[str]]:
    warnings: list[str] = []
    header, rows = _split_table(raw)
    presets: dict[str, BBOTPresetCapability] = {}
    if not rows:
        warnings.append("No se pudo interpretar la lista de presets de BBOT (salida vacía o formato inesperado).")
        return presets, warnings
    name_idx = _col_index(header, _PRESET_HEADER_HINTS, 0)
    for cols in rows:
        if name_idx >= len(cols):
            continue
        name = cols[name_idx]
        if not re.match(r"^[A-Za-z0-9_\-]+$", name):
            continue
        presets[name] = BBOTPresetCapability(
            name=name,
            description=" ".join(c for i, c in enumerate(cols) if i != name_idx),
        )
    return presets, warnings


def parse_output_module_listing(raw: str) -> tuple[dict[str, BBOTOutputModuleCapability], list[str]]:
    warnings: list[str] = []
    header, rows = _split_table(raw)
    out_modules: dict[str, BBOTOutputModuleCapability] = {}
    if not rows:
        warnings.append("No se pudo interpretar la lista de módulos de salida de BBOT.")
        return out_modules, warnings
    name_idx = _col_index(header, _OUTPUT_HEADER_HINTS, 0)
    for cols in rows:
        if name_idx >= len(cols):
            continue
        name = cols[name_idx]
        if not re.match(r"^[A-Za-z0-9_\-]+$", name):
            continue
        desc = " ".join(c for i, c in enumerate(cols) if i != name_idx)
        out_modules[name] = BBOTOutputModuleCapability(
            name=name,
            description=desc,
            auth_required="apikey" in desc.lower() or "api key" in desc.lower(),
        )
    return out_modules, warnings


def discover_capabilities(runtime: BBOTRuntimeStatus, settings: BBOTSettings) -> BBOTCapabilities:
    if not runtime.available:
        return BBOTCapabilities(loaded=False, warnings=[runtime.reason or "Runtime de BBOT no disponible."])

    warnings: list[str] = []
    executable = runtime.executable or settings.executable or "bbot"

    try:
        mod_argv = _wrap_argv(runtime.backend, settings, build_capability_query_argv(executable, "list_modules"))
        preset_argv = _wrap_argv(runtime.backend, settings, build_capability_query_argv(executable, "list_presets"))
        out_argv = _wrap_argv(runtime.backend, settings, build_capability_query_argv(executable, "list_output_modules"))
    except Exception as exc:  # pragma: no cover
        return BBOTCapabilities(loaded=False, warnings=[str(exc)])

    modules: dict[str, BBOTModuleCapability] = {}
    presets: dict[str, BBOTPresetCapability] = {}
    output_modules: dict[str, BBOTOutputModuleCapability] = {}

    try:
        mod_result = _run_capture(mod_argv)
        modules, mod_warnings = parse_module_listing(mod_result.stdout)
        warnings += mod_warnings
    except BBOTCapabilityError as exc:
        warnings.append(f"No se pudieron listar módulos: {exc}")

    try:
        preset_result = _run_capture(preset_argv)
        presets, preset_warnings = parse_preset_listing(preset_result.stdout)
        warnings += preset_warnings
    except BBOTCapabilityError as exc:
        warnings.append(f"No se pudieron listar presets: {exc}")

    try:
        out_result = _run_capture(out_argv)
        output_modules, out_warnings = parse_output_module_listing(out_result.stdout)
        warnings += out_warnings
    except BBOTCapabilityError as exc:
        warnings.append(f"No se pudieron listar módulos de salida: {exc}")

    loaded = bool(modules or presets or output_modules)
    return BBOTCapabilities(
        version=runtime.version,
        modules=modules,
        presets=presets,
        output_modules=output_modules,
        loaded=loaded,
        warnings=warnings,
        fetched_at=time.time(),
    )
