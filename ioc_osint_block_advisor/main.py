from __future__ import annotations

import queue
import threading
import tkinter as tk
from types import SimpleNamespace
from tkinter import messagebox, ttk

from modules.classifier import classify_ioc, classify_many
from modules.decision_engine import decide_many
from modules.exporter import export_results
from modules.extractor import extract_iocs
from modules.fang import defang, refang
from modules.osint_runner import collect as collect_osint
from modules.utils import load_allowlist


BLOCKING_DECISIONS = {"BLOCK_DOMAIN", "BLOCK_URL_EXACT", "BLOCK_SENDER_EXACT", "BLOCK_HASH"}

COLORS = {
    "bg": "#09172f",
    "bg2": "#0d2450",
    "panel": "#10203a",
    "panel_alt": "#142642",
    "panel_lift": "#162f54",
    "border": "#355778",
    "text": "#f1f7ff",
    "muted": "#b8c7dc",
    "blue": "#1d6fff",
    "blue_dark": "#143f84",
    "cyan": "#22d3ee",
    "violet": "#7c3aed",
    "magenta": "#d946ef",
    "red": "#ff6b7a",
    "red_bg": "#3b1828",
    "yellow": "#ffd166",
    "yellow_bg": "#3b2c14",
    "orange": "#ffab5e",
    "orange_bg": "#42260f",
    "green": "#74d99f",
    "green_bg": "#153826",
    "observed_bg": "#173452",
    "selection": "#1d6fff",
}

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
    "original": 240,
    "normalized": 300,
    "defanged": 260,
    "type": 95,
    "root_domain": 150,
    "role": 155,
    "score": 70,
    "decision": 165,
    "action": 210,
    "reason": 420,
    "fp_risk": 160,
    "sources": 200,
}


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("IOC OSINT Block Advisor")
        self.geometry("1600x960")
        self.minsize(1240, 790)
        self.configure(bg=COLORS["bg"])
        self.background_canvas: tk.Canvas | None = None
        self.results = []
        self.result_by_iid: dict[str, object] = {}
        self.selected_result = None
        self.worker_queue: queue.Queue = queue.Queue()
        self._build_ui()

    def _build_ui(self) -> None:
        self.setup_styles()
        self.create_gradient_background(self)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        self.create_header()

        top = ttk.Frame(self, padding=(18, 14, 18, 7), style="App.TFrame")
        top.grid(row=1, column=0, sticky="nsew")
        top.columnconfigure(0, weight=3)
        top.columnconfigure(1, weight=2)
        top.columnconfigure(2, weight=2)

        self.context_text = self._build_text_panel(top, "Contexto de la investigación", 0)
        self.iocs_text = self._build_text_panel(top, "IOCs observados", 1)
        self._build_summary_panel(top, 2)

        center = ttk.Frame(self, padding=(18, 7, 18, 7), style="App.TFrame")
        center.grid(row=2, column=0, sticky="nsew")
        center.columnconfigure(0, weight=1)
        center.rowconfigure(0, weight=1)
        self._build_table(center)

        bottom = ttk.Frame(self, padding=(18, 7, 18, 12), style="App.TFrame")
        bottom.grid(row=3, column=0, sticky="nsew")
        bottom.columnconfigure(0, weight=3)
        bottom.columnconfigure(1, weight=1)
        self._build_detail_panel(bottom)
        self._build_actions_panel(bottom)

        status_bar = ttk.Frame(self, padding=(18, 8), style="Status.TFrame")
        status_bar.grid(row=4, column=0, sticky="ew")
        status_bar.columnconfigure(0, weight=1)
        self.status = tk.StringVar(value="Listo.")
        self.rule_status = tk.StringVar(value="IOC observado no significa IOC bloqueable")
        ttk.Label(status_bar, textvariable=self.status, style="Status.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(status_bar, textvariable=self.rule_status, style="Rule.TLabel").grid(row=0, column=1, sticky="e")

    def setup_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(".", font=("Segoe UI", 9), background=COLORS["bg"], foreground=COLORS["text"])
        style.configure("App.TFrame", background="#0b1d3c")
        style.configure("Header.TFrame", background=COLORS["bg"])
        style.configure("Status.TFrame", background="#0a1932")
        style.configure("Card.TLabelframe", background=COLORS["panel"], bordercolor=COLORS["border"], relief="solid")
        style.configure(
            "Card.TLabelframe.Label",
            background=COLORS["panel"],
            foreground=COLORS["text"],
            font=("Segoe UI", 10, "bold"),
        )
        style.configure("CardBody.TFrame", background=COLORS["panel"])
        style.configure("Metric.TFrame", background=COLORS["panel_lift"], relief="solid", borderwidth=1)

        style.configure("Title.TLabel", background=COLORS["bg"], foreground=COLORS["text"], font=("Segoe UI", 20, "bold"))
        style.configure("Subtitle.TLabel", background=COLORS["bg"], foreground=COLORS["muted"], font=("Segoe UI", 10))
        style.configure("HeaderIcon.TLabel", background=COLORS["bg"], foreground=COLORS["cyan"], font=("Segoe UI Emoji", 25))
        style.configure("Field.TLabel", background=COLORS["panel"], foreground=COLORS["muted"], font=("Segoe UI", 9, "bold"))
        style.configure("Value.TLabel", background=COLORS["panel"], foreground=COLORS["text"], font=("Segoe UI", 9))
        style.configure("HighlightValue.TLabel", background=COLORS["panel"], foreground=COLORS["cyan"], font=("Segoe UI", 10, "bold"))
        style.configure("Status.TLabel", background="#0a1932", foreground=COLORS["cyan"], font=("Segoe UI", 9, "bold"))
        style.configure("Rule.TLabel", background="#0a1932", foreground=COLORS["muted"], font=("Segoe UI", 9))
        style.configure("SmallMuted.TLabel", background=COLORS["panel"], foreground=COLORS["muted"], font=("Segoe UI", 8))
        style.configure("SummaryLabel.TLabel", background=COLORS["panel_lift"], foreground=COLORS["muted"], font=("Segoe UI", 8, "bold"))
        style.configure("SummaryTotal.TLabel", background=COLORS["panel_lift"], foreground=COLORS["blue"], font=("Segoe UI", 19, "bold"))
        style.configure("SummaryBlock.TLabel", background=COLORS["panel_lift"], foreground=COLORS["red"], font=("Segoe UI", 19, "bold"))
        style.configure("SummaryReview.TLabel", background=COLORS["panel_lift"], foreground=COLORS["yellow"], font=("Segoe UI", 19, "bold"))
        style.configure("SummarySafe.TLabel", background=COLORS["panel_lift"], foreground=COLORS["green"], font=("Segoe UI", 19, "bold"))
        style.configure("SummaryScore.TLabel", background=COLORS["panel_lift"], foreground=COLORS["cyan"], font=("Segoe UI", 19, "bold"))

        style.configure("TScrollbar", background=COLORS["panel_alt"], troughcolor=COLORS["bg"], bordercolor=COLORS["border"], arrowcolor=COLORS["text"])
        style.configure(
            "Treeview",
            background="#0d1b31",
            fieldbackground="#0d1b31",
            foreground=COLORS["text"],
            bordercolor=COLORS["border"],
            rowheight=28,
            font=("Segoe UI", 9),
        )
        style.map("Treeview", background=[("selected", COLORS["selection"])], foreground=[("selected", "#ffffff")])
        style.configure(
            "Treeview.Heading",
            background="#16345c",
            foreground=COLORS["text"],
            bordercolor=COLORS["border"],
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        style.map("Treeview.Heading", background=[("active", "#1d477a")])

        self._configure_button_style("Primary.TButton", COLORS["blue"], "#2f8bff")
        self._configure_button_style("Secondary.TButton", "#21456f", "#2a5c95")
        self._configure_button_style("Dark.TButton", "#1b2d49", "#254066")
        self._configure_button_style("Copy.TButton", "#1769aa", "#2188d6")
        self._configure_button_style("Danger.TButton", "#8a2444", "#c33164")

        style.configure("TCheckbutton", background=COLORS["panel"], foreground=COLORS["text"], font=("Segoe UI", 9))
        style.map("TCheckbutton", background=[("active", COLORS["panel"])], foreground=[("disabled", COLORS["muted"])])

    def create_gradient_background(self, parent: tk.Tk) -> None:
        self.background_canvas = tk.Canvas(parent, highlightthickness=0, bd=0, bg=COLORS["bg"])
        self.background_canvas.place(x=0, y=0, relwidth=1, relheight=1)
        self.background_canvas.tk.call("lower", self.background_canvas._w)
        parent.bind("<Configure>", self.on_resize_background)

    def on_resize_background(self, event) -> None:
        if event.widget is self and self.background_canvas:
            self.draw_aurora_background(self.background_canvas, event.width, event.height)

    def draw_aurora_background(self, canvas: tk.Canvas, width: int, height: int) -> None:
        if width <= 1 or height <= 1:
            return
        canvas.delete("aurora")
        steps = max(80, min(180, height // 5))
        for index in range(steps):
            ratio = index / max(steps - 1, 1)
            color = self._blend("#09172f", "#0d2450", ratio)
            y0 = int(index * height / steps)
            y1 = int((index + 1) * height / steps) + 1
            canvas.create_rectangle(0, y0, width, y1, fill=color, outline="", tags="aurora")

        glow_shapes = (
            (-0.12, -0.20, 0.55, 0.55, "#1d6fff"),
            (0.46, -0.18, 1.12, 0.46, "#7c3aed"),
            (0.70, 0.18, 1.18, 0.84, "#d946ef"),
            (-0.18, 0.35, 0.42, 1.08, "#22d3ee"),
            (0.20, 0.58, 0.78, 1.18, "#123f84"),
        )
        for x0, y0, x1, y1, color in glow_shapes:
            canvas.create_oval(
                int(width * x0),
                int(height * y0),
                int(width * x1),
                int(height * y1),
                fill=color,
                outline="",
                stipple="gray75",
                tags="aurora",
            )

        for offset, color in ((0.25, "#22d3ee"), (0.38, "#7c3aed"), (0.52, "#d946ef")):
            y = int(height * offset)
            canvas.create_line(
                -40,
                y,
                int(width * 0.22),
                y - 40,
                int(width * 0.55),
                y + 20,
                width + 40,
                y - 30,
                smooth=True,
                fill=color,
                width=2,
                stipple="gray50",
                tags="aurora",
            )

    @staticmethod
    def _blend(start: str, end: str, ratio: float) -> str:
        start_rgb = tuple(int(start[i : i + 2], 16) for i in (1, 3, 5))
        end_rgb = tuple(int(end[i : i + 2], 16) for i in (1, 3, 5))
        mixed = tuple(int(a + (b - a) * ratio) for a, b in zip(start_rgb, end_rgb))
        return f"#{mixed[0]:02x}{mixed[1]:02x}{mixed[2]:02x}"

    def _configure_button_style(self, style_name: str, bg: str, active_bg: str) -> None:
        style = ttk.Style(self)
        style.configure(
            style_name,
            background=bg,
            foreground="#ffffff",
            bordercolor=COLORS["border"],
            focusthickness=0,
            padding=(12, 9),
            font=("Segoe UI", 9, "bold"),
        )
        style.map(
            style_name,
            background=[("active", active_bg), ("disabled", "#1a2534")],
            foreground=[("disabled", "#65768d")],
        )

    def create_header(self) -> None:
        header = ttk.Frame(self, padding=(16, 14, 16, 10), style="Header.TFrame")
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)
        ttk.Label(header, text="🛡", style="HeaderIcon.TLabel").grid(row=0, column=0, rowspan=2, sticky="w", padx=(0, 12))
        ttk.Label(header, text="IOC OSINT Block Advisor", style="Title.TLabel").grid(row=0, column=1, sticky="w")
        ttk.Label(
            header,
            text="Herramienta OSINT para análisis y recomendación de bloqueo de IOCs",
            style="Subtitle.TLabel",
        ).grid(row=1, column=1, sticky="w")
        accent = tk.Canvas(header, height=3, highlightthickness=0, bd=0, bg=COLORS["bg"])
        accent.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        accent.bind("<Configure>", self._draw_header_accent)

    def _draw_header_accent(self, event) -> None:
        canvas = event.widget
        canvas.delete("accent")
        width = max(event.width, 1)
        segments = 120
        for index in range(segments):
            ratio = index / max(segments - 1, 1)
            color = self._blend(COLORS["cyan"], COLORS["magenta"], ratio)
            x0 = int(index * width / segments)
            x1 = int((index + 1) * width / segments) + 1
            canvas.create_rectangle(x0, 0, x1, 3, fill=color, outline="", tags="accent")

    def create_card(self, parent: ttk.Frame, title: str) -> ttk.LabelFrame:
        return ttk.LabelFrame(parent, text=title, style="Card.TLabelframe")

    def _build_text_panel(self, parent: ttk.Frame, title: str, column: int) -> tk.Text:
        frame = self.create_card(parent, title)
        frame.grid(row=0, column=column, sticky="nsew", padx=(0, 10) if column < 2 else 0)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        text = tk.Text(
            frame,
            height=9,
            wrap="word",
            undo=True,
            font=("Consolas", 9),
            bg="#0a1424",
            fg=COLORS["text"],
            insertbackground=COLORS["cyan"],
            selectbackground=COLORS["selection"],
            relief="flat",
            borderwidth=0,
            padx=10,
            pady=8,
        )
        scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns", padx=(6, 0))
        return text

    def _build_summary_panel(self, parent: ttk.Frame, column: int) -> None:
        frame = self.create_card(parent, "Resumen ejecutivo")
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
        metrics = (
            ("Total IOCs", "total", "SummaryTotal.TLabel"),
            ("Bloqueables", "blockable", "SummaryBlock.TLabel"),
            ("En revisión", "review", "SummaryReview.TLabel"),
            ("No bloqueables", "not_blockable", "SummarySafe.TLabel"),
            ("Score medio", "avg_score", "SummaryScore.TLabel"),
        )
        for index, (label, key, value_style) in enumerate(metrics):
            row = index // 2
            col = index % 2
            card = ttk.Frame(frame, padding=(10, 8), style="Metric.TFrame")
            card.grid(row=row, column=col, sticky="nsew", padx=4, pady=4)
            card.columnconfigure(0, weight=1)
            ttk.Label(card, text=label.upper(), style="SummaryLabel.TLabel").grid(row=0, column=0, sticky="w")
            ttk.Label(card, textvariable=self.summary_vars[key], style=value_style).grid(row=1, column=0, sticky="w")

    def _build_table(self, parent: ttk.Frame) -> None:
        frame = self.create_card(parent, "Resultados")
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
        y_scroll.grid(row=0, column=1, sticky="ns", padx=(6, 0))
        x_scroll.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        self.table.bind("<<TreeviewSelect>>", self.on_result_selected)
        self.apply_table_tags()

    def _build_detail_panel(self, parent: ttk.Frame) -> None:
        frame = self.create_card(parent, "Detalle del IOC seleccionado")
        frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        frame.columnconfigure(1, weight=1)
        self.detail_vars = {
            "ioc": tk.StringVar(value="-"),
            "type": tk.StringVar(value="-"),
            "decision": tk.StringVar(value="-"),
            "action": tk.StringVar(value="-"),
            "risk": tk.StringVar(value="-"),
            "sources": tk.StringVar(value="-"),
            "block_value": tk.StringVar(value="No bloqueable"),
            "confidence": tk.StringVar(value="-"),
            "protection": tk.StringVar(value="-"),
        }
        rows = (
            ("IOC", "ioc"),
            ("Tipo", "type"),
            ("Decisión", "decision"),
            ("Acción recomendada", "action"),
            ("Riesgo de falso positivo", "risk"),
            ("Fuentes OSINT", "sources"),
            ("Valor para bloqueo", "block_value"),
            ("Confianza", "confidence"),
            ("Protección", "protection"),
        )
        for index, (label, key) in enumerate(rows):
            ttk.Label(frame, text=f"{label}:", style="Field.TLabel").grid(row=index, column=0, sticky="nw", padx=(0, 10), pady=3)
            if key == "ioc":
                ioc_row = ttk.Frame(frame, style="CardBody.TFrame")
                ioc_row.grid(row=index, column=1, sticky="ew", pady=3)
                ioc_row.columnconfigure(0, weight=1)
                ttk.Label(ioc_row, textvariable=self.detail_vars[key], wraplength=830, style="HighlightValue.TLabel").grid(row=0, column=0, sticky="ew")
                self.detail_copy_ioc_button = ttk.Button(ioc_row, text="📋 Copiar IOC", command=self.copy_selected_ioc, state="disabled", style="Copy.TButton")
                self.detail_copy_ioc_button.grid(row=0, column=1, sticky="e", padx=(10, 0))
            else:
                style = "HighlightValue.TLabel" if key in {"decision", "block_value"} else "Value.TLabel"
                ttk.Label(frame, textvariable=self.detail_vars[key], wraplength=940, style=style).grid(row=index, column=1, sticky="ew", pady=3)
        ttk.Label(frame, text="Motivo:", style="Field.TLabel").grid(row=len(rows), column=0, sticky="nw", padx=(0, 10), pady=(8, 2))
        self.reason_text = tk.Text(
            frame,
            height=4,
            wrap="word",
            font=("Segoe UI", 9),
            state="disabled",
            bg="#0a1424",
            fg=COLORS["text"],
            relief="flat",
            borderwidth=0,
            padx=10,
            pady=8,
        )
        self.reason_text.grid(row=len(rows), column=1, sticky="nsew", pady=(8, 2))

    def _build_actions_panel(self, parent: ttk.Frame) -> None:
        frame = self.create_card(parent, "Acciones rápidas")
        frame.grid(row=0, column=1, sticky="nsew")
        frame.columnconfigure(0, weight=1)

        self.use_osint = tk.BooleanVar(value=False)
        self.osint_url_lookups = tk.BooleanVar(value=False)
        self.analyze_button = ttk.Button(frame, text="🔍 Analizar IOCs", command=self.analyze, style="Primary.TButton")
        self.export_button = ttk.Button(frame, text="⬇ Exportar resultados", command=self.export, style="Secondary.TButton")
        self.clear_button = ttk.Button(frame, text="🧹 Limpiar", command=self.clear, style="Dark.TButton")
        self.copy_ioc_button = ttk.Button(frame, text="📋 Copiar IOC", command=self.copy_selected_ioc, state="disabled", style="Copy.TButton")
        self.copy_block_button = ttk.Button(frame, text="🛡 Copiar para bloqueo", command=self.copy_blockable_ioc, state="disabled", style="Danger.TButton")
        self.copy_ticket_button = ttk.Button(frame, text="🧾 Copiar resumen para ticket", command=self.copy_ticket_summary, state="disabled", style="Secondary.TButton")
        self.osint_check = ttk.Checkbutton(frame, text="Consultar OSINT externo", variable=self.use_osint)
        self.osint_url_check = ttk.Checkbutton(
            frame,
            text="Incluir URL completa en OSINT (urlscan/PhishTank)",
            variable=self.osint_url_lookups,
        )

        for index, button in enumerate(
            (self.analyze_button, self.export_button, self.clear_button, self.copy_ioc_button, self.copy_block_button, self.copy_ticket_button)
        ):
            button.grid(row=index, column=0, sticky="ew", pady=(0, 8))
        self.osint_check.grid(row=6, column=0, sticky="w", pady=(8, 0))
        self.osint_url_check.grid(row=7, column=0, sticky="w", pady=(2, 0))
        ttk.Label(frame, text="(puede exponer IOCs a terceros)", style="SmallMuted.TLabel").grid(row=7, column=0, sticky="w", pady=(2, 0))

    def analyze(self) -> None:
        context = self.context_text.get("1.0", "end").strip()
        iocs = self.iocs_text.get("1.0", "end").strip()
        if not context and not iocs:
            messagebox.showinfo("Sin datos", "Pega contexto o IOCs observados antes de analizar.")
            return
        self.status.set("Analizando...")
        self._set_analysis_state("disabled")
        thread = threading.Thread(target=self._analyze_worker, args=(context, iocs, self.use_osint.get(), self.osint_url_lookups.get()), daemon=True)
        thread.start()
        self.after(200, self._poll_worker)

    def _analyze_worker(self, context: str, iocs: str, use_osint: bool, include_url_lookups: bool = False) -> None:
        try:
            extracted = extract_iocs(context, iocs)
            allowlist = load_allowlist()
            decided = []
            classified: list = []
            fallback_items: list = []
            try:
                # Clasificación conjunta: el análisis contextual necesita ver
                # todos los IOCs a la vez para asociar señales por frase.
                classified = classify_many(extracted, context, allowlist)
            except Exception:
                for extracted_item in extracted:
                    try:
                        classified.append(classify_ioc(extracted_item, context, allowlist))
                    except Exception as exc:
                        fallback_items.append(self._fallback_review_item(extracted_item, exc))
            for item in classified:
                try:
                    if use_osint:
                        collect_osint(item, include_url_lookups=include_url_lookups)
                    decided.extend(decide_many([item]))
                except Exception as exc:
                    decided.append(self._fallback_review_item(item, exc))
            decided.extend(fallback_items)
            self.worker_queue.put(("ok", decided))
        except Exception as exc:
            self.worker_queue.put(("error", exc))

    @staticmethod
    def _fallback_review_item(extracted_item, exc: Exception):
        value = refang(getattr(extracted_item, "refanged", "") or getattr(extracted_item, "original", ""))
        safe_value = value or getattr(extracted_item, "original", "")
        return SimpleNamespace(
            original=getattr(extracted_item, "original", safe_value),
            normalized=safe_value,
            defanged=defang(safe_value) if safe_value else "",
            source=getattr(extracted_item, "source", ""),
            ioc_type="unknown",
            domain="",
            root_domain="",
            subdomain="",
            path="",
            role="unknown",
            is_allowlisted=False,
            score=0,
            osint_results=[
                {
                    "source": "local_parser",
                    "status": "error",
                    "score_delta": 0,
                    "evidence": str(exc),
                }
            ],
            decision="REVIEW",
            recommended_action="Revisión manual",
            reason="IOC no parseable automáticamente; requiere revisión manual",
            false_positive_risk="Medio",
        )

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
            iid = self.table.insert("", "end", values=self._row_values(item), tags=(self._tag_for_decision(self._field(item, "decision"), self._field(item, "review_priority")),))
            self.result_by_iid[iid] = item
        self.apply_table_tags()

    def _row_values(self, item) -> tuple:
        decision = str(self._field(item, "decision")).upper()
        return (
            self._field(item, "original"),
            self._field(item, "normalized"),
            self._field(item, "defanged"),
            self._field(item, "ioc_type", "type"),
            self._field(item, "root_domain"),
            self._field(item, "role"),
            self._field(item, "score", default=0),
            decision,
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
        blockable_value = self.get_blockable_value(item)
        self.detail_vars["ioc"].set(self._field(item, "normalized") or self._field(item, "original") or "-")
        self.detail_vars["type"].set(self._field(item, "ioc_type", "type") or "-")
        self.detail_vars["decision"].set(self._field(item, "decision") or "-")
        self.detail_vars["action"].set(self._field(item, "recommended_action", "action") or "-")
        self.detail_vars["risk"].set(self._field(item, "false_positive_risk", "fp_risk") or "-")
        self.detail_vars["sources"].set(self._sources(item))
        self.detail_vars["block_value"].set(blockable_value or "No bloqueable")
        self.detail_vars["confidence"].set(self._field(item, "confidence") or "-")
        self.detail_vars["protection"].set(self._protection_label(item))
        decision_display = self._field(item, "decision") or "-"
        priority = self._field(item, "review_priority")
        if decision_display == "REVIEW" and priority:
            decision_display = f"REVIEW (prioridad {priority})"
        self.detail_vars["decision"].set(decision_display)
        reason = self._field(item, "reason") or "-"
        conclusion = self._field(item, "soc_conclusion")
        reasoning = self._field(item, "analyst_reasoning")
        if conclusion:
            reason = f"Conclusión SOC: {conclusion}\n\n{reason}"
        if reasoning:
            reason = f"{reason}\n\n{reasoning}"
        self._set_reason(reason)

        self.copy_ioc_button.configure(state="normal")
        self.detail_copy_ioc_button.configure(state="normal")
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
        positives = self._field(item, "positive_signals", default=[]) or []
        negatives = self._field(item, "negative_signals", default=[]) or []
        evidence = self._field(item, "evidence", default=[]) or []
        if isinstance(evidence, str):
            evidence = [evidence]
        positive_evidence = [e for e in evidence if not self._is_negative_evidence(e)]
        negative_evidence = [e.replace("[cautela] ", "", 1) for e in evidence if self._is_negative_evidence(e)]
        block_value = self._field(item, "block_value") or self.get_blockable_value(item) or "No bloqueable"
        sources = self._field(item, "sources_used", default=[]) or []
        sources_text = ", ".join(sources) if isinstance(sources, list) else str(sources or self._sources(item))
        decision_display = self._field(item, "decision")
        priority = self._field(item, "review_priority")
        if decision_display == "REVIEW" and priority:
            decision_display = f"REVIEW (prioridad {priority})"
        lines = [
            f"IOC: {self._field(item, 'normalized') or self._field(item, 'original')}",
            f"Tipo: {self._field(item, 'ioc_type', 'type')}",
            f"Dominio raíz: {self._field(item, 'root_domain') or '-'}",
            f"Rol: {self._field(item, 'role') or '-'}",
            f"Decisión: {decision_display}",
            f"Confianza: {self._field(item, 'confidence') or '-'}",
            f"Score: {self._field(item, 'score', default=0)}",
            f"Valor para bloqueo: {block_value}",
            f"Riesgo de falso positivo: {self._field(item, 'false_positive_risk', 'fp_risk')}",
            f"Protección: {self._protection_label(item)}",
            f"Fuentes consultadas: {sources_text or self._sources(item)}",
            "Evidencias positivas (a favor de bloquear):",
        ]
        lines.extend([f"- {e}" for e in positive_evidence] or ["- Ninguna."])
        lines.append("Evidencias negativas / cautelas:")
        lines.extend([f"- {e}" for e in negative_evidence] or ["- Ninguna."])
        conclusion = self._field(item, "soc_conclusion")
        if conclusion:
            lines.extend(["Conclusión SOC:", conclusion])
        reasoning = self._field(item, "analyst_reasoning")
        if reasoning:
            lines.extend(["Razonamiento:", reasoning])
        lines.append(f"Acción recomendada: {self._field(item, 'recommended_action', 'action')}")
        lines.append("Nota: La recomendación debe validarse antes de aplicar bloqueo.")
        summary = "\n".join(lines)
        self.clipboard_clear()
        self.clipboard_append(summary)
        self.status.set("Resumen del IOC copiado para ticket.")

    @staticmethod
    def _is_negative_evidence(entry: str) -> bool:
        return str(entry).startswith("[cautela]")

    def apply_table_tags(self) -> None:
        self.table.tag_configure("block", background=COLORS["red_bg"], foreground="#ffe8eb")
        self.table.tag_configure("review", background=COLORS["yellow_bg"], foreground="#fff1c1")
        self.table.tag_configure("review_high", background=COLORS["orange_bg"], foreground=COLORS["orange"])
        self.table.tag_configure("do_not_block", background=COLORS["green_bg"], foreground="#ddfbe8")
        self.table.tag_configure("observed", background=COLORS["observed_bg"], foreground="#d8eaff")
        self.table.tag_configure("default", background="#0b1626", foreground=COLORS["text"])

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
        self.detail_vars["block_value"].set("No bloqueable")
        self._set_reason("")
        self.copy_ioc_button.configure(state="disabled")
        self.detail_copy_ioc_button.configure(state="disabled")
        self.copy_block_button.configure(state="disabled")
        self.copy_ticket_button.configure(state="disabled")

    def _set_reason(self, value: str) -> None:
        self.reason_text.configure(state="normal")
        self.reason_text.delete("1.0", "end")
        self.reason_text.insert("1.0", value)
        self.reason_text.configure(state="disabled")

    @staticmethod
    def _protection_label(item) -> str:
        protected_by = ""
        if item is not None and not isinstance(item, dict):
            protected_by = getattr(item, "protected_by", "") or ""
        elif isinstance(item, dict):
            protected_by = item.get("protected_by", "") or ""
        labels = {
            "client_allowlist": "🛡 Protegido por allowlist de cliente (Fluidra)",
            "client_sender_allowlist": "🛡 Protegido por allowlist de remitentes de cliente (Fluidra)",
            "client_tenant_allowlist": "🛡 Protegido por allowlist de tenants corporativos (Fluidra)",
            "trusted_saas": "Plataforma SaaS confiable (trusted_saas)",
            "allowlist": "Allowlist técnica general",
            "review_only": "Review-only: nunca bloqueo automático",
        }
        return labels.get(protected_by, "Sin protección de allowlist")

    @staticmethod
    def _tag_for_decision(decision: str, priority: str = "") -> str:
        if decision in BLOCKING_DECISIONS:
            return "block"
        if decision == "REVIEW":
            if str(priority).lower() in {"alta", "high"}:
                return "review_high"
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
