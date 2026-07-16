"""Safe construction of BBOT command lines.

Hard rules (see FASE 6 of the integration brief):
  * Arguments are always built as a ``list[str]``, never a shell string.
  * ``shell=True`` is never used anywhere downstream (see runner.py).
  * Targets, module names, preset names, and output-module names are
    validated before being placed on the command line.
  * Module/preset/output-module names are checked against the *real*
    discovered inventory (see discovery.py) when one is supplied — unknown
    names are rejected rather than silently passed through to BBOT.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .errors import BBOTValidationError
from .models import BBOTCapabilities

# A target may be a domain, IP, CIDR, URL, or email. We do not attempt to be
# a full validator for each type (BBOT does that); we only reject inputs
# that look like they are trying to inject additional CLI arguments or
# shell metacharacters that would be meaningless/dangerous as a target.
_MAX_TARGET_LEN = 512
_FORBIDDEN_TARGET_CHARS = re.compile(r"[;&|`$(){}<>\n\r\"']")
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]*$")


def validate_target(target: str) -> str:
    target = (target or "").strip()
    if not target:
        raise BBOTValidationError("El target no puede estar vacío.")
    if len(target) > _MAX_TARGET_LEN:
        raise BBOTValidationError("El target excede la longitud máxima permitida.")
    if target.startswith("-"):
        raise BBOTValidationError(
            f"Target rechazado: '{target}' parece un argumento de línea de comandos, no un objetivo."
        )
    if _FORBIDDEN_TARGET_CHARS.search(target):
        raise BBOTValidationError(
            "Target rechazado: contiene caracteres no permitidos (posible intento de inyección)."
        )
    if ".." in target or target.startswith("/") or target.startswith("\\"):
        raise BBOTValidationError("Target rechazado: parece una ruta de archivo, no un objetivo OSINT.")
    return target


def _validate_name(name: str, kind: str) -> str:
    name = (name or "").strip()
    if not name or not _SAFE_NAME_RE.match(name):
        raise BBOTValidationError(f"Nombre de {kind} inválido: '{name}'.")
    return name


def validate_module_name(name: str, capabilities: BBOTCapabilities | None = None) -> str:
    name = _validate_name(name, "módulo")
    if capabilities is not None and capabilities.loaded and capabilities.modules:
        if name not in capabilities.modules:
            raise BBOTValidationError(f"Módulo desconocido para esta instalación de BBOT: '{name}'.")
    return name


def validate_preset_name(name: str, capabilities: BBOTCapabilities | None = None) -> str:
    name = _validate_name(name, "preset")
    if capabilities is not None and capabilities.loaded and capabilities.presets:
        if name not in capabilities.presets:
            raise BBOTValidationError(f"Preset desconocido para esta instalación de BBOT: '{name}'.")
    return name


def validate_output_module_name(name: str, capabilities: BBOTCapabilities | None = None) -> str:
    name = _validate_name(name, "módulo de salida")
    if capabilities is not None and capabilities.loaded and capabilities.output_modules:
        if name not in capabilities.output_modules:
            raise BBOTValidationError(f"Módulo de salida desconocido: '{name}'.")
    return name


def validate_flag(flag: str) -> str:
    return _validate_name(flag, "flag")


def validate_preset_file(path_str: str, allowed_dirs: list) -> str:
    """Validate a filesystem path to one of our bundled/custom preset YAML
    files (as opposed to a built-in BBOT preset *name*, which goes through
    ``validate_preset_name`` instead). Rejects anything outside the
    configured allowed directories, non-YAML files, or missing files."""
    from pathlib import Path

    if not path_str or ".." in str(path_str):
        raise BBOTValidationError(f"Ruta de preset inválida: '{path_str}'.")
    candidate = Path(path_str).resolve()
    if not candidate.is_file():
        raise BBOTValidationError(f"Fichero de preset no encontrado: '{path_str}'.")
    if candidate.suffix.lower() not in (".yml", ".yaml"):
        raise BBOTValidationError(f"El preset debe ser un fichero YAML: '{path_str}'.")

    for allowed in allowed_dirs:
        allowed_resolved = Path(allowed).resolve()
        try:
            candidate.relative_to(allowed_resolved)
            return str(candidate)
        except ValueError:
            continue
    raise BBOTValidationError(f"Fichero de preset fuera de los directorios permitidos: '{path_str}'.")


def _normalize_workdir(workdir) -> str:
    from pathlib import Path

    path = Path(workdir).resolve()
    # Reject obvious traversal attempts left in the raw string before resolve().
    if ".." in str(workdir):
        raise BBOTValidationError("El directorio de trabajo no puede contener '..'.")
    return str(path)


@dataclass
class BuiltCommand:
    """The list of argv the runner should execute, plus a redacted preview."""

    argv: list[str] = field(default_factory=list)
    preview: str = ""


def build_bbot_argv(
    executable: str,
    target: str,
    *,
    modules: list[str] | None = None,
    presets: list[str] | None = None,
    preset_files: list[str] | None = None,
    preset_file_allowed_dirs: list | None = None,
    output_modules: list[str] | None = None,
    exclude_modules: list[str] | None = None,
    flags: list[str] | None = None,
    workdir: str | None = None,
    json_output: bool = True,
    capabilities: BBOTCapabilities | None = None,
) -> BuiltCommand:
    """Build a validated argv list for a BBOT scan.

    Never returns a shell string. Callers must pass the result to a
    subprocess API that accepts an argument list (e.g. ``subprocess.Popen``
    with ``shell=False``, which is the default).
    """
    if not executable or not isinstance(executable, str):
        raise BBOTValidationError("Ejecutable de BBOT no configurado.")

    safe_target = validate_target(target)

    argv = [executable, "-t", safe_target]

    for preset in presets or []:
        argv += ["-p", validate_preset_name(preset, capabilities)]

    for preset_file in preset_files or []:
        argv += ["-p", validate_preset_file(preset_file, preset_file_allowed_dirs or [])]

    for mod in modules or []:
        argv += ["-m", validate_module_name(mod, capabilities)]

    for mod in exclude_modules or []:
        argv += ["-em", validate_module_name(mod, capabilities)]

    for flag in flags or []:
        argv += ["-f", validate_flag(flag)]

    for out_mod in output_modules or []:
        argv += ["-om", validate_output_module_name(out_mod, capabilities)]

    if workdir:
        argv += ["-o", _normalize_workdir(workdir)]

    if json_output:
        argv += ["--json"]

    # Never allow interactive confirmation prompts to hang the subprocess,
    # and keep output free of ANSI color codes we would otherwise have to
    # strip before JSON parsing.
    argv += ["--yes", "--no-color", "--silent"]

    return BuiltCommand(argv=argv, preview=" ".join(_shell_quote(a) for a in argv))


def build_capability_query_argv(executable: str, query: str) -> list[str]:
    """Build argv for one of the fixed, no-target capability queries.

    ``query`` must be one of a small fixed set — never derived from user
    input — so it is validated against an allowlist rather than the
    general-purpose name/target validators above.
    """
    allowed = {
        "version": ["--version"],
        "list_modules": ["-l"],
        "list_presets": ["-lp"],
        "list_output_modules": ["-lo"],
    }
    if query not in allowed:
        raise BBOTValidationError(f"Consulta de capacidades desconocida: '{query}'.")
    if not executable or not isinstance(executable, str):
        raise BBOTValidationError("Ejecutable de BBOT no configurado.")
    return [executable, *allowed[query]]


def _shell_quote(arg: str) -> str:
    """Cosmetic-only quoting for display/log previews — never used to execute."""
    if re.fullmatch(r"[A-Za-z0-9_.\-/:@]+", arg or ""):
        return arg
    return '"' + arg.replace('"', '\\"') + '"'
