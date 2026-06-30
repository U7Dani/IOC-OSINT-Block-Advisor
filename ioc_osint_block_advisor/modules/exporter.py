from __future__ import annotations

import csv
from pathlib import Path

from .utils import ensure_output_dir


def export_results(items, context: str, output_dir: Path | None = None) -> dict[str, Path]:
    out = output_dir or ensure_output_dir()
    out.mkdir(parents=True, exist_ok=True)

    files = {
        "domains": out / "blocklist_domains.txt",
        "urls": out / "blocklist_urls.txt",
        "senders": out / "blocklist_senders.txt",
        "hashes": out / "blocklist_hashes.txt",
        "review": out / "review_items.csv",
        "report": out / "full_report.md",
        "ticket": out / "ticket_summary.txt",
    }
    _write_lines(files["domains"], [i.domain for i in items if i.decision == "BLOCK_DOMAIN" and i.domain])
    _write_lines(files["urls"], [i.normalized for i in items if i.decision == "BLOCK_URL_EXACT"])
    _write_lines(files["senders"], [i.normalized for i in items if i.decision == "BLOCK_SENDER_EXACT"])
    _write_lines(files["hashes"], [i.normalized for i in items if i.decision == "BLOCK_HASH"])
    _write_review(files["review"], [i for i in items if i.decision == "REVIEW"])
    files["report"].write_text(_full_report(items, context), encoding="utf-8")
    files["ticket"].write_text(_ticket_summary(items), encoding="utf-8")
    return files


def _write_lines(path: Path, values: list[str]) -> None:
    unique = sorted({value for value in values if value})
    path.write_text("\n".join(unique) + ("\n" if unique else ""), encoding="utf-8")


def _write_review(path: Path, items) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["ioc", "type", "role", "score", "reason", "false_positive_risk", "sources"])
        for item in items:
            writer.writerow([item.normalized, item.ioc_type, item.role, item.score, item.reason, item.false_positive_risk, _sources(item)])


def _full_report(items, context: str) -> str:
    lines = [
        "# IOC OSINT Block Advisor - Full Report",
        "",
        "## Regla principal",
        "",
        "IOC observado no significa IOC bloqueable.",
        "",
        "## Contexto",
        "",
        context or "(sin contexto)",
        "",
        "## IOCs",
        "",
        "| IOC original | Normalizado | Tipo | Rol | Score | Decisión | Acción | Riesgo FP | Motivo | Fuentes |",
        "|---|---|---|---:|---:|---|---|---|---|---|",
    ]
    for item in items:
        lines.append(
            "| "
            + " | ".join(
                _md(value)
                for value in (
                    item.original,
                    item.normalized,
                    item.ioc_type,
                    item.role,
                    str(item.score),
                    item.decision,
                    item.recommended_action,
                    item.false_positive_risk,
                    item.reason,
                    _sources(item),
                )
            )
            + " |"
        )
    lines.extend(["", "## Evidencias OSINT", ""])
    for item in items:
        lines.append(f"### {item.normalized}")
        if not item.osint_results:
            lines.append("- Sin consultas OSINT externas.")
        for result in item.osint_results:
            lines.append(f"- {result.get('source')}: {result.get('status')} | score_delta={result.get('score_delta', 0)} | {result.get('evidence', '')}")
        lines.append("")
    return "\n".join(lines)


def _ticket_summary(items) -> str:
    blocking = [i for i in items if i.decision.startswith("BLOCK")]
    not_blocking = [i for i in items if i.decision in {"DO_NOT_BLOCK", "OBSERVED_ONLY"}]
    review = [i for i in items if i.decision == "REVIEW"]
    lines = [
        "Durante la validación se analizaron los IOCs observados en el contexto de la investigación. Se diferencia entre infraestructura legítima observada, URLs exactas potencialmente abusadas y destinos finales maliciosos.",
        "",
        "IOCs recomendados para bloqueo:",
    ]
    lines.extend(_ticket_lines(blocking, include_action=True) or ["- Ninguno"])
    lines.extend(["", "IOCs no recomendados para bloqueo:"])
    lines.extend(_ticket_lines(not_blocking) or ["- Ninguno"])
    lines.extend(["", "IOCs pendientes de revisión:"])
    lines.extend(_ticket_lines(review) or ["- Ninguno"])
    return "\n".join(lines) + "\n"


def _ticket_lines(items, include_action: bool = False) -> list[str]:
    lines = []
    for item in items:
        if include_action:
            lines.append(f"- {item.normalized} | Tipo: {item.ioc_type} | Acción: {item.recommended_action} | Motivo: {item.reason}")
        else:
            lines.append(f"- {item.normalized} | Motivo: {item.reason}")
    return lines


def _sources(item) -> str:
    if not item.osint_results:
        return "local_rules"
    return ", ".join(f"{r.get('source')}:{r.get('status')}" for r in item.osint_results)


def _md(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")
