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
    BBOTCapabilities,
    BBOTFlagCapability,
    BBOTModuleCapability,
    BBOTModuleOption,
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
        return raw.decode("utf-8-sig")
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
# Capability parsing.
#
# BBOT 3.x (`bbot -l` / `-lp` / `-lo` / `-lf` / `-lmo`) renders a box-drawing
# grid table, e.g.:
#
#   +----------+------+---------------+-------------------------+
#   | Module   | Type | Needs API Key | Description             |
#   +==========+======+===============+=========================+
#   | ajaxpro  | scan | No            | Check for potentially   |
#   |          |      |               | vulnerable Ajaxpro ...  |
#   +----------+------+---------------+-------------------------+
#
# Cell text wraps across multiple physical lines within one logical row
# (bounded by "+---+" / "+===+" separator lines). This parser is
# intentionally format-driven (splits on the grid structure itself, not on
# whitespace heuristics) so it is not sensitive to column widths, and it
# degrades to "loaded=False, warnings=[...]" rather than guessing wrong if
# a future BBOT version changes the rendering entirely.
# ---------------------------------------------------------------------------

_GRID_BOUNDARY_RE = re.compile(r"^\+[+=\-]+\+$")

_MODULE_HEADER_HINTS = ("module", "name")
_PRESET_HEADER_HINTS = ("preset", "name")
_OUTPUT_HEADER_HINTS = ("module", "name")
_FLAG_HEADER_HINTS = ("flag", "name")
_OPTION_HEADER_HINTS = ("config option", "option", "name")


def _merge_row_lines(row_lines: list[str]) -> list[str]:
    """Merge the physical lines of one logical (possibly word-wrapped) grid
    row into a single list of stripped cell strings, joined with a space
    where a cell's text continued onto a following physical line."""
    per_line_cells = []
    ncols = 0
    for line in row_lines:
        parts = line.split("|")
        if parts and parts[0].strip() == "":
            parts = parts[1:]
        if parts and parts[-1].strip() == "":
            parts = parts[:-1]
        cells = [p.strip() for p in parts]
        per_line_cells.append(cells)
        ncols = max(ncols, len(cells))
    merged = [""] * ncols
    for cells in per_line_cells:
        for i, cell in enumerate(cells):
            if not cell:
                continue
            merged[i] = f"{merged[i]} {cell}".strip() if merged[i] else cell
    return merged


def _split_table(raw: str) -> tuple[list[str] | None, list[list[str]]]:
    """Parse a BBOT box-drawing grid table into (header, rows)."""
    header: list[str] | None = None
    rows: list[list[str]] = []
    current_row_lines: list[str] = []

    def _flush() -> None:
        nonlocal header
        if not current_row_lines:
            return
        cols = _merge_row_lines(current_row_lines)
        if not any(cols):
            return
        if header is None:
            header = [c.lower() for c in cols]
        else:
            rows.append(cols)

    for raw_line in raw.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if _GRID_BOUNDARY_RE.match(stripped):
            _flush()
            current_row_lines = []
            continue
        if "|" in line:
            current_row_lines.append(line)
    _flush()
    return header, rows


def _col_index(header: list[str] | None, hints: tuple[str, ...], default: int = 0) -> int:
    """Resolve a column index from the header, preferring an exact match
    over a substring match (so e.g. "modules" doesn't accidentally match
    the "# modules" column, and vice versa)."""
    if not header:
        return default
    for hint in hints:
        for idx, col in enumerate(header):
            if col.strip() == hint:
                return idx
    for hint in hints:
        for idx, col in enumerate(header):
            if hint in col:
                return idx
    return default


_NAME_RE = re.compile(r"^[A-Za-z0-9_\-]+$")


def parse_module_listing(raw: str) -> tuple[dict[str, BBOTModuleCapability], list[str]]:
    warnings: list[str] = []
    header, rows = _split_table(raw)
    modules: dict[str, BBOTModuleCapability] = {}
    if not rows:
        warnings.append("No se pudo interpretar la lista de módulos de BBOT (salida vacía o formato inesperado).")
        return modules, warnings

    name_idx = _col_index(header, _MODULE_HEADER_HINTS, 0)
    desc_idx = _col_index(header, ("description",), -1)
    flags_idx = _col_index(header, ("flags",), -1)
    api_key_idx = _col_index(header, ("needs api key", "api key", "apikey"), -1)

    for cols in rows:
        if name_idx >= len(cols):
            warnings.append(f"Fila de módulo con formato inesperado, omitida: {cols!r}")
            continue
        name = cols[name_idx]
        if not _NAME_RE.match(name):
            continue
        description = cols[desc_idx] if 0 <= desc_idx < len(cols) else ""
        flags_cell = cols[flags_idx] if 0 <= flags_idx < len(cols) else ""
        flags = {f.strip() for f in flags_cell.split(",") if f.strip()}
        api_key_cell = cols[api_key_idx].strip().lower() if 0 <= api_key_idx < len(cols) else ""
        auth_required = api_key_cell in {"yes", "true", "y"}
        modules[name] = BBOTModuleCapability(
            name=name,
            description=description,
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
    desc_idx = _col_index(header, ("description",), -1)
    for cols in rows:
        if name_idx >= len(cols):
            continue
        name = cols[name_idx]
        if not _NAME_RE.match(name):
            continue
        presets[name] = BBOTPresetCapability(
            name=name,
            description=cols[desc_idx] if 0 <= desc_idx < len(cols) else "",
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
    desc_idx = _col_index(header, ("description",), -1)
    api_key_idx = _col_index(header, ("needs api key", "api key", "apikey"), -1)
    for cols in rows:
        if name_idx >= len(cols):
            continue
        name = cols[name_idx]
        if not _NAME_RE.match(name):
            continue
        desc = cols[desc_idx] if 0 <= desc_idx < len(cols) else ""
        api_key_cell = cols[api_key_idx].strip().lower() if 0 <= api_key_idx < len(cols) else ""
        out_modules[name] = BBOTOutputModuleCapability(
            name=name,
            description=desc,
            auth_required=api_key_cell in {"yes", "true", "y"},
        )
    return out_modules, warnings


def parse_flag_listing(raw: str) -> tuple[dict[str, BBOTFlagCapability], list[str]]:
    warnings: list[str] = []
    header, rows = _split_table(raw)
    flags: dict[str, BBOTFlagCapability] = {}
    if not rows:
        warnings.append("No se pudo interpretar la lista de flags de BBOT.")
        return flags, warnings
    name_idx = _col_index(header, _FLAG_HEADER_HINTS, 0)
    desc_idx = _col_index(header, ("description",), -1)
    count_idx = _col_index(header, ("# modules",), -1)
    modules_idx = _col_index(header, ("modules",), -1)
    for cols in rows:
        if name_idx >= len(cols):
            continue
        name = cols[name_idx]
        if not _NAME_RE.match(name):
            continue
        module_names = []
        if 0 <= modules_idx < len(cols):
            module_names = [m.strip() for m in cols[modules_idx].split(",") if m.strip()]
        try:
            count = int(cols[count_idx]) if 0 <= count_idx < len(cols) and cols[count_idx].strip().isdigit() else len(module_names)
        except (TypeError, ValueError):
            count = len(module_names)
        flags[name] = BBOTFlagCapability(
            name=name,
            description=cols[desc_idx] if 0 <= desc_idx < len(cols) else "",
            module_count=count,
            modules=module_names,
        )
    return flags, warnings


def parse_module_option_listing(raw: str) -> tuple[dict[str, BBOTModuleOption], list[str]]:
    warnings: list[str] = []
    header, rows = _split_table(raw)
    options: dict[str, BBOTModuleOption] = {}
    if not rows:
        warnings.append("No se pudo interpretar las opciones de módulo de BBOT.")
        return options, warnings
    name_idx = _col_index(header, _OPTION_HEADER_HINTS, 0)
    type_idx = _col_index(header, ("type",), -1)
    desc_idx = _col_index(header, ("description",), -1)
    default_idx = _col_index(header, ("default",), -1)
    for cols in rows:
        if name_idx >= len(cols):
            continue
        name = cols[name_idx]
        # Config option names are dotted paths (e.g. "modules.crt.api_key"),
        # not simple identifiers, so they get their own, looser validation.
        if not re.match(r"^[A-Za-z0-9_.\-]+$", name):
            continue
        options[name] = BBOTModuleOption(
            name=name,
            type=cols[type_idx] if 0 <= type_idx < len(cols) else "",
            description=cols[desc_idx] if 0 <= desc_idx < len(cols) else "",
            default=cols[default_idx] if 0 <= default_idx < len(cols) else "",
        )
    return options, warnings


def discover_capabilities(runtime: BBOTRuntimeStatus, settings: BBOTSettings) -> BBOTCapabilities:
    if not runtime.available:
        return BBOTCapabilities(loaded=False, warnings=[runtime.reason or "Runtime de BBOT no disponible."])

    warnings: list[str] = []
    executable = runtime.executable or settings.executable or "bbot"

    try:
        mod_argv = _wrap_argv(runtime.backend, settings, build_capability_query_argv(executable, "list_modules"))
        preset_argv = _wrap_argv(runtime.backend, settings, build_capability_query_argv(executable, "list_presets"))
        out_argv = _wrap_argv(runtime.backend, settings, build_capability_query_argv(executable, "list_output_modules"))
        flag_argv = _wrap_argv(runtime.backend, settings, build_capability_query_argv(executable, "list_flags"))
        option_argv = _wrap_argv(runtime.backend, settings, build_capability_query_argv(executable, "list_module_options"))
    except Exception as exc:  # pragma: no cover
        return BBOTCapabilities(loaded=False, warnings=[str(exc)])

    modules: dict[str, BBOTModuleCapability] = {}
    presets: dict[str, BBOTPresetCapability] = {}
    output_modules: dict[str, BBOTOutputModuleCapability] = {}
    flags: dict[str, BBOTFlagCapability] = {}
    module_options: dict[str, BBOTModuleOption] = {}

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

    try:
        flag_result = _run_capture(flag_argv)
        flags, flag_warnings = parse_flag_listing(flag_result.stdout)
        warnings += flag_warnings
    except BBOTCapabilityError as exc:
        warnings.append(f"No se pudieron listar flags: {exc}")

    try:
        option_result = _run_capture(option_argv)
        module_options, option_warnings = parse_module_option_listing(option_result.stdout)
        warnings += option_warnings
    except BBOTCapabilityError as exc:
        warnings.append(f"No se pudieron listar opciones de módulo: {exc}")

    loaded = bool(modules or presets or output_modules)
    return BBOTCapabilities(
        version=runtime.version,
        modules=modules,
        presets=presets,
        output_modules=output_modules,
        flags=flags,
        module_options=module_options,
        loaded=loaded,
        warnings=warnings,
        fetched_at=time.time(),
    )
