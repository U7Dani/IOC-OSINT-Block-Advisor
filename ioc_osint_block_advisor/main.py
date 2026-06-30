from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from modules.classifier import classify_many
from modules.decision_engine import decide_many
from modules.exporter import export_results
from modules.extractor import extract_iocs
from modules.osint_runner import collect as collect_osint
from modules.utils import load_allowlist


BLOCKING_DECISIONS = {"BLOCK_DOMAIN", "BLOCK_URL_EXACT", "BLOCK_SENDER_EXACT", "BLOCK_HASH"}

COLUMNS = (
    "original",
    "normalized",
    "defanged",
    "type",
    "root_domain",
    "role",
    "score",
    "decision",
    "action",
    "reason",
    "fp_risk",
    "sources",
)

HEADERS = {
    "original": "IOC original",
    "normalized": "IOC normalizado",
    "defanged": "IOC defanged",
    "type": "Tipo",
    "root_domain": "Dominio raíz",
    "role": "Rol",
    "score": "Score",
    "decision": "Decisión",
    "action": "Acción recomendada",
    "reason": "Motivo",
    "fp_risk": "Riesgo de falso positivo",
    "sources": "Fuentes OSINT",
}

COLUMN_WIDTHS = {
    "original": 220,
    "normalized": 260,
    "defanged": 260,
    "type": 95,
    "root_domain": 150,
    "role": 150,
    "score": 70,
    "decision": 150,
    "action": 190,
    "reason": 360,
    "fp_risk": 160,
    "sources": 190,
}


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("IOC OSINT Block Advisor")
        self.geometry("1550x930")
        self.minsize(1180, 760)
        self.results = []
        self.result_by_iid: dict[str, object] = {}
        self.selected_result = None
        self.worker_queue: queue.Queue = queue.Queue()
        self._build_ui()

    def _build_ui(self) -> None:
        self._configure_style()
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        top = ttk.Frame(self, padding=(12, 10, 12, 6))
        top.grid(row=0, column=0, sticky="nsew")
        top.columnconfigure(0, weight=3)
        top.columnconfigure(1, weight=2)
        top.columnconfigure(2, weight=1)

        self.context_text = self._build_text_panel(top, "Contexto de la investigación", 0)
        self.iocs_text = self._build_text_panel(top, "IOCs observados", 1)
        self._build_summary_panel(top, 2)

        center = ttk.Frame(self, padding=(12, 4, 12, 6))
        center.grid(row=1, column=0, sticky="nsew")
        center.columnconfigure(0, weight=1)
        center.rowconfigure(0, weight=1)
        self._build_table(center)

        bottom = ttk.Frame(self, padding=(12, 4, 12, 8))
        bottom.grid(row=2, column=0, sticky="nsew")
        bottom.columnconfigure(0, weight=3)
        bottom.columnconfigure(1, weight=1)
        self._build_detail_panel(bottom)
        self._build_actions_panel(bottom)

        status_bar = ttk.Frame(self, padding=(12, 4))
        status_bar.grid(row=3, column=0, sticky="ew")
        status_bar.columnconfigure(0, weight=1)
        self.status = tk.StringVar(value="Listo.")
        self.rule_status = tk.StringVar(value="IOC observado no significa IOC bloqueable")
        ttk.Label(status_bar, textvariable=self.status).grid(row=0, column=0, sticky="w")
        ttk.Label(status_bar, textvariable=self.rule_status, style="Rule.TLabel").grid(row=0, column=1, sticky="e")

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TLabelframe", padding=8)
        style.configure("TLabelframe.Label", font=("Segoe UI", 10, "bold"))
        style.configure("Treeview", rowheight=26, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        style.configure("SummaryValue.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("SummaryLabel.TLabel", foreground="#56606a")
        style.configure("Rule.TLabel", foreground="#56606a")

    def _build_text_panel(self, parent: ttk.Frame, title: str, column: int) -> tk.Text:
        frame = ttk.LabelFrame(parent, text=title)
        frame.grid(row=0, column=column, sticky="nsew", padx=(0, 8) if column < 2 else 0)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        text = tk.Text(frame, height=9, wrap="word", undo=True, font=("Segoe UI", 9))
        scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        return text

    def _build_summary_panel(self, parent: ttk.Frame, column: int) -> None:
        frame = ttk.LabelFrame(parent, text="Resumen ejecutivo")
        frame.grid(row=0, column=column, sticky="nsew")
        for idx in range(2):
            frame.columnconfigure(idx, weight=1)
        self.summary_vars = {
            "total": tk.StringVar(value="0"),
            "blockable": tk.StringVar(value="0"),
            "review": tk.StringVar(value="0"),
            "not_blockable": tk.StringVar(value="0"),
            "avg_score": tk.StringVar(value="0.0"),
        }
        rows = (
            ("Total IOCs", "total"),
            ("Bloqueables", "blockable"),
            ("En revisión", "review"),
            ("No bloqueables", "not_blockable"),
            ("Score medio", "avg_score"),
        )
        for index, (label, key) in enumerate(rows):
            ttk.Label(frame, text=label, style="SummaryLabel.TLabel").grid(row=index, column=0, sticky="w", pady=3)
            ttk.Label(frame, textvariable=self.summary_vars[key], style="SummaryValue.TLabel").grid(row=index, column=1, sticky="e", pady=3)

    def _build_table(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="Resultados")
        frame.grid(row=0, column=0, sticky="nsew")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        self.table = ttk.Treeview(frame, columns=COLUMNS, show="headings", height=16, selectmode="browse")
        for column in COLUMNS:
            self.table.heading(column, text=HEADERS[column])
            self.table.column(column, width=COLUMN_WIDTHS[column], minwidth=60, stretch=column in {"reason", "normalized", "defanged"})
        y_scroll = ttk.Scrollbar(frame, orient="vertical", command=self.table.yview)
        x_scroll = ttk.Scrollbar(frame, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        self.table.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")
        self.table.bind("<<TreeviewSelect>>", self.on_result_selected)
        self.apply_table_tags()

    def _build_detail_panel(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="Detalle del IOC seleccionado")
        frame.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        frame.columnconfigure(1, weight=1)
        self.detail_vars = {
            "ioc": tk.StringVar(value="-"),
            "type": tk.StringVar(value="-"),
            "decision": tk.StringVar(value="-"),
            "action": tk.StringVar(value="-"),
            "risk": tk.StringVar(value="-"),
            "sources": tk.StringVar(value="-"),
        }
        rows = (
            ("IOC", "ioc"),
            ("Tipo", "type"),
            ("Decisión", "decision"),
            ("Acción recomendada", "action"),
            ("Riesgo de falso positivo", "risk"),
            ("Fuentes OSINT", "sources"),
        )
        for index, (label, key) in enumerate(rows):
            ttk.Label(frame, text=f"{label}:").grid(row=index, column=0, sticky="nw", padx=(0, 8), pady=2)
            if key == "ioc":
                ioc_row = ttk.Frame(frame)
                ioc_row.grid(row=index, column=1, sticky="ew", pady=2)
                ioc_row.columnconfigure(0, weight=1)
                ttk.Label(ioc_row, textvariable=self.detail_vars[key], wraplength=820).grid(row=0, column=0, sticky="ew")
                self.copy_ioc_button = ttk.Button(ioc_row, text="Copiar IOC", command=self.copy_selected_ioc, state="disabled")
                self.copy_ioc_button.grid(row=0, column=1, sticky="e", padx=(8, 0))
            else:
                ttk.Label(frame, textvariable=self.detail_vars[key], wraplength=920).grid(row=index, column=1, sticky="ew", pady=2)
        ttk.Label(frame, text="Motivo:").grid(row=len(rows), column=0, sticky="nw", padx=(0, 8), pady=(6, 2))
        self.reason_text = tk.Text(frame, height=4, wrap="word", font=("Segoe UI", 9), state="disabled")
        self.reason_text.grid(row=len(rows), column=1, sticky="nsew", pady=(6, 2))

    def _build_actions_panel(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="Acciones rápidas")
        frame.grid(row=0, column=1, sticky="nsew")
        frame.columnconfigure(0, weight=1)

        self.use_osint = tk.BooleanVar(value=False)
        self.analyze_button = ttk.Button(frame, text="Analizar IOCs", command=self.analyze)
        self.export_button = ttk.Button(frame, text="Exportar resultados", command=self.export)
        self.clear_button = ttk.Button(frame, text="Limpiar", command=self.clear)
        self.copy_block_button = ttk.Button(frame, text="Copiar para bloqueo", command=self.copy_blockable_ioc, state="disabled")
        self.copy_ticket_button = ttk.Button(frame, text="Copiar resumen para ticket", command=self.copy_ticket_summary, state="disabled")
        self.osint_check = ttk.Checkbutton(
            frame,
            text="Consultar OSINT externo\n(puede exponer IOCs a terceros)",
            variable=self.use_osint,
        )

        for index, button in enumerate((self.analyze_button, self.export_button, self.clear_button, self.copy_block_button, self.copy_ticket_button)):
            button.grid(row=index, column=0, sticky="ew", pady=(0, 7))
        self.osint_check.grid(row=5, column=0, sticky="w", pady=(8, 0))

    def analyze(self) -> None:
        context = self.context_text.get("1.0", "end").strip()
        iocs = self.iocs_text.get("1.0", "end").strip()
        if not context and not iocs:
            messagebox.showinfo("Sin datos", "Pega contexto o IOCs observados antes de analizar.")
            return
        self.status.set("Analizando...")
        self._set_analysis_state("disabled")
        thread = threading.Thread(target=self._analyze_worker, args=(context, iocs, self.use_osint.get()), daemon=True)
        thread.start()
        self.after(200, self._poll_worker)

    def _analyze_worker(self, context: str, iocs: str, use_osint: bool) -> None:
        try:
            extracted = extract_iocs(context, iocs)
            classified = classify_many(extracted, context, load_allowlist())
            if use_osint:
                for item in classified:
                    collect_osint(item)
            decided = decide_many(classified)
            self.worker_queue.put(("ok", decided))
        except Exception as exc:
            self.worker_queue.put(("error", exc))

    def _poll_worker(self) -> None:
        try:
            status, payload = self.worker_queue.get_nowait()
        except queue.Empty:
            self.after(200, self._poll_worker)
            return
        self._set_analysis_state("normal")
        if status == "error":
            self.status.set("Error durante el análisis.")
            messagebox.showerror("Error", str(payload))
            return
        self.results = payload
        self._render_results()
        self.refresh_summary(self.results)
        self.status.set(f"Análisis completado: {len(self.results)} IOC(s)")

    def _render_results(self) -> None:
        self.table.delete(*self.table.get_children())
        self.result_by_iid.clear()
        self.selected_result = None
        self._clear_detail()
        for item in self.results:
            iid = self.table.insert("", "end", values=self._row_values(item), tags=(self._tag_for_decision(self._field(item, "decision")),))
            self.result_by_iid[iid] = item
        self.apply_table_tags()

    def _row_values(self, item) -> tuple:
        return (
            self._field(item, "original"),
            self._field(item, "normalized"),
            self._field(item, "defanged"),
            self._field(item, "ioc_type", "type"),
            self._field(item, "root_domain"),
            self._field(item, "role"),
            self._field(item, "score", default=0),
            self._field(item, "decision"),
            self._field(item, "recommended_action", "action"),
            self._field(item, "reason"),
            self._field(item, "false_positive_risk", "fp_risk"),
            self._sources(item),
        )

    def refresh_summary(self, results) -> None:
        total = len(results)
        blockable = sum(1 for item in results if self._field(item, "decision") in BLOCKING_DECISIONS)
        review = sum(1 for item in results if self._field(item, "decision") == "REVIEW")
        not_blockable = sum(1 for item in results if self._field(item, "decision") in {"DO_NOT_BLOCK", "OBSERVED_ONLY"})
        scores = [float(self._field(item, "score", default=0) or 0) for item in results]
        avg_score = sum(scores) / total if total else 0
        self.summary_vars["total"].set(str(total))
        self.summary_vars["blockable"].set(str(blockable))
        self.summary_vars["review"].set(str(review))
        self.summary_vars["not_blockable"].set(str(not_blockable))
        self.summary_vars["avg_score"].set(f"{avg_score:.1f}")

    def on_result_selected(self, event=None) -> None:
        selected = self.table.selection()
        if not selected:
            self.selected_result = None
            self._clear_detail()
            return
        item = self.result_by_iid.get(selected[0])
        self.selected_result = item
        self.detail_vars["ioc"].set(self._field(item, "normalized") or self._field(item, "original") or "-")
        self.detail_vars["type"].set(self._field(item, "ioc_type", "type") or "-")
        self.detail_vars["decision"].set(self._field(item, "decision") or "-")
        self.detail_vars["action"].set(self._field(item, "recommended_action", "action") or "-")
        self.detail_vars["risk"].set(self._field(item, "false_positive_risk", "fp_risk") or "-")
        self.detail_vars["sources"].set(self._sources(item))
        self._set_reason(self._field(item, "reason") or "-")

        blockable_value = self.get_blockable_value(item)
        self.copy_ioc_button.configure(state="normal")
        self.copy_block_button.configure(state="normal" if blockable_value else "disabled")
        self.copy_ticket_button.configure(state="normal")

    def get_blockable_value(self, result) -> str:
        decision = self._field(result, "decision")
        if decision == "BLOCK_DOMAIN":
            return self._field(result, "domain") or self._field(result, "root_domain") or self._field(result, "normalized")
        if decision == "BLOCK_URL_EXACT":
            return self._field(result, "normalized")
        if decision == "BLOCK_SENDER_EXACT":
            return self._field(result, "normalized")
        if decision == "BLOCK_HASH":
            return self._field(result, "normalized")
        return ""

    def copy_blockable_ioc(self) -> None:
        value = self.get_blockable_value(self.selected_result)
        if not value:
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self.status.set(f"Copiado para bloqueo: {value}")

    def copy_selected_ioc(self) -> None:
        item = self.selected_result
        if not item:
            return
        value = self._field(item, "normalized") or self._field(item, "original")
        if not value:
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self.status.set(f"IOC copiado: {value}")

    def copy_ticket_summary(self) -> None:
        item = self.selected_result
        if not item:
            return
        summary = "\n".join(
            (
                f"IOC: {self._field(item, 'normalized') or self._field(item, 'original')}",
                f"Tipo: {self._field(item, 'ioc_type', 'type')}",
                f"Decisión: {self._field(item, 'decision')}",
                f"Acción recomendada: {self._field(item, 'recommended_action', 'action')}",
                f"Motivo: {self._field(item, 'reason')}",
                f"Riesgo de falso positivo: {self._field(item, 'false_positive_risk', 'fp_risk')}",
                f"Fuentes OSINT: {self._sources(item)}",
            )
        )
        self.clipboard_clear()
        self.clipboard_append(summary)
        self.status.set("Resumen del IOC copiado para ticket.")

    def apply_table_tags(self) -> None:
        self.table.tag_configure("block", background="#f8d7da")
        self.table.tag_configure("review", background="#fff3cd")
        self.table.tag_configure("do_not_block", background="#d1e7dd")
        self.table.tag_configure("observed", background="#dbe7f3")
        self.table.tag_configure("default", background="#ffffff")

    def export(self) -> None:
        if not self.results:
            messagebox.showinfo("Sin resultados", "Analiza IOCs antes de exportar.")
            return
        context = self.context_text.get("1.0", "end").strip()
        files = export_results(self.results, context)
        messagebox.showinfo("Exportación completada", f"Archivos generados en:\n{next(iter(files.values())).parent}")

    def clear(self) -> None:
        self.context_text.delete("1.0", "end")
        self.iocs_text.delete("1.0", "end")
        self.table.delete(*self.table.get_children())
        self.results = []
        self.result_by_iid.clear()
        self.selected_result = None
        self.refresh_summary([])
        self._clear_detail()
        self.status.set("Listo.")

    def _set_analysis_state(self, state: str) -> None:
        self.analyze_button.configure(state=state)
        self.export_button.configure(state=state)
        self.clear_button.configure(state=state)

    def _clear_detail(self) -> None:
        for var in self.detail_vars.values():
            var.set("-")
        self._set_reason("")
        self.copy_ioc_button.configure(state="disabled")
        self.copy_block_button.configure(state="disabled")
        self.copy_ticket_button.configure(state="disabled")

    def _set_reason(self, value: str) -> None:
        self.reason_text.configure(state="normal")
        self.reason_text.delete("1.0", "end")
        self.reason_text.insert("1.0", value)
        self.reason_text.configure(state="disabled")

    @staticmethod
    def _tag_for_decision(decision: str) -> str:
        if decision in BLOCKING_DECISIONS:
            return "block"
        if decision == "REVIEW":
            return "review"
        if decision == "DO_NOT_BLOCK":
            return "do_not_block"
        if decision == "OBSERVED_ONLY":
            return "observed"
        return "default"

    @staticmethod
    def _field(item, *names: str, default: str = ""):
        if item is None:
            return default
        if isinstance(item, dict):
            for name in names:
                if name in item and item.get(name) is not None:
                    return item.get(name)
            return default
        for name in names:
            if hasattr(item, name):
                value = getattr(item, name)
                if value is not None:
                    return value
        return default

    def _sources(self, item) -> str:
        if item is None:
            return "-"
        explicit = self._field(item, "osint_sources")
        if explicit:
            return explicit
        results = self._field(item, "osint_results", default=[])
        if not results:
            return "local_rules"
        return ", ".join(f"{r.get('source')}:{r.get('status')}" for r in results if isinstance(r, dict))


if __name__ == "__main__":
    App().mainloop()
