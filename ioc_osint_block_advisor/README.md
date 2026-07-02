# IOC OSINT Block Advisor

Herramienta local en Python para ayudar a analistas SOC a revisar IOCs observados y convertirlos en recomendaciones seguras de bloqueo.

Regla principal: **IOC observado no significa IOC bloqueable.**

La aplicación no bloquea nada automáticamente. Normaliza IOCs, aplica refang/defang, clasifica el rol del IOC, respeta una allowlist local y genera decisiones justificadas.

## Instalación

Requisitos: Python 3.11+.

```bash
cd ioc_osint_block_advisor
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

En Windows, si `python` abre Microsoft Store o no aparece en PATH, instala Python 3.11+ desde python.org y marca la opción **Add python.exe to PATH**.

## Uso

```bash
python main.py
```

También puedes ejecutar `python main.py` desde la carpeta superior del workspace; ese archivo actúa como lanzador hacia la aplicación.

Pega el contexto de la investigación, pega los IOCs observados y pulsa **Analizar IOCs**. Las consultas OSINT externas están desactivadas por defecto porque pueden exponer IOCs a servicios de terceros.

## Exportación

El botón **Exportar resultados** genera:

- `output/blocklist_domains.txt`
- `output/blocklist_urls.txt`
- `output/blocklist_senders.txt`
- `output/blocklist_hashes.txt`
- `output/review_items.csv`
- `output/full_report.md`
- `output/ticket_summary.txt`

Las blocklists solo incluyen decisiones de bloqueo:

- `blocklist_domains.txt`: solo `BLOCK_DOMAIN`
- `blocklist_urls.txt`: solo `BLOCK_URL_EXACT`
- `blocklist_senders.txt`: solo `BLOCK_SENDER_EXACT`
- `blocklist_hashes.txt`: solo `BLOCK_HASH`

`DO_NOT_BLOCK`, `OBSERVED_ONLY` y `REVIEW` nunca se exportan a blocklists.

## Configuración `.env`

Copia `.env.example` a `.env` si quieres usar APIs opcionales:

```text
OTX_API_KEY=
URLSCAN_API_KEY=
URLSCAN_AUTO_SUBMIT=false
```

Por diseño, `URLSCAN_AUTO_SUBMIT=false` evita enviar URLs nuevas a escaneo público.

## Fuentes OSINT

- DNS con `dnspython`
- RDAP vía `rdap.org`
- crt.sh
- URLhaus
- ThreatFox
- MalwareBazaar para hashes
- PhishTank como módulo opcional no consultado en el MVP
- AlienVault OTX con API key opcional
- urlscan.io buscando scans existentes

Todas las fuentes tienen timeout y control de errores. Si una fuente falla, la aplicación continúa. Un resultado sin detección en OSINT no se interpreta como benigno.

## Decisiones

Decisiones posibles:

- `BLOCK_DOMAIN`
- `BLOCK_URL_EXACT`
- `BLOCK_SENDER_EXACT`
- `BLOCK_HASH`
- `DO_NOT_BLOCK`
- `OBSERVED_ONLY`
- `REVIEW`

La allowlist prevalece sobre el score. Dominios como `zoom.us`, `events.zoom.us`, `microsoft.com`, `google.com`, `highspot.com` y similares no se recomiendan como bloqueo de dominio completo. Si una URL concreta en una plataforma legítima se confirma como abusada, la herramienta orienta a revisión o bloqueo exacto de URL.

Un sender observado no debe bloquearse solo por aparecer en un correo sospechoso. Un dominio recién creado suma riesgo, pero por sí solo no justifica bloqueo.

## Seguridad y privacidad

La herramienta:

- No bloquea automáticamente.
- No ejecuta JavaScript.
- No descarga archivos.
- No abre adjuntos.
- No detona muestras.
- No sigue redirecciones.
- No envía URLs nuevas a urlscan por defecto.
- Avisa en la interfaz cuando se activa OSINT externo.

## Generar ejecutable

```powershell
pip install pyinstaller
.\build_exe.ps1
```

El script usa:

```powershell
pyinstaller --onefile --windowed --name IOC_OSINT_Block_Advisor --add-data "config;config" main.py
```

El ejecutable escribe los resultados en una carpeta `output` junto al `.exe`.

## Tests

```bash
pytest
```

## Limitaciones

Este MVP prioriza recomendaciones conservadoras y explicables. OSINT externo puede ser incompleto, rate-limited o no responder. OTX no debe usarse como única fuente para bloqueo. La decisión final debe validarla un analista.

## Motor de decisión contextual (v2)

El análisis lee el contexto de la investigación frase a frase y asocia señales a cada IOC:

- **Señales fuertes** (elevan el bloqueo): landing final (+40), captura/solicitud de credenciales (+35), suplantación (+30), dominio recientemente creado (+25), phishing/portal fraudulento (+25), redirección final (+20), no relacionado con proveedor legítimo (+20), abuso confirmado (+30), formulario/portal de login (+15), autenticación SPF/DKIM/DMARC fallida (+15).
- **Señales de cautela** (reducen el bloqueo): dominio raíz SaaS confiable (-50), dominio en allowlist (-40), dominio remitente legítimo (-30), autenticación de correo válida (-25), infraestructura legítima mencionada (-25), solo observado (-20), infraestructura cloud compartida (-20).

Una señal es **directa** si la frase menciona explícitamente el IOC (o su dominio/raíz). Las decisiones `BLOCK_*` exigen score ≥ 80, al menos dos señales fuertes y al menos una directa; entre 40 y 79 el IOC queda en `REVIEW`; por debajo, `OBSERVED_ONLY` o `DO_NOT_BLOCK`.

Reglas de protección:

- Los dominios en `config/allowlist_domains.txt` o `config/trusted_saas_domains.txt` **nunca** producen `BLOCK_DOMAIN`. Una URL exacta abusada sobre esos dominios puede ser `REVIEW` o `BLOCK_URL_EXACT` si el abuso está confirmado.
- Los senders solo producen `BLOCK_SENDER_EXACT` con evidencia fuerte y explícita (abuso confirmado, spoofing, fallo de autenticación) más confirmación OSINT.
- Las IPs nunca pasan de `REVIEW` (no existe blocklist de IPs en la exportación).

Cada resultado incluye `evidence`, `positive_signals`, `negative_signals`, `score_breakdown`, `confidence`, `block_value`, `why_blockable`, `why_not_blockable` y `analyst_reasoning`, visibles en el informe completo, el CSV de revisión y el resumen para ticket.

Las blocklists exportadas siguen conteniendo únicamente decisiones `BLOCK_*`; `REVIEW`, `DO_NOT_BLOCK` y `OBSERVED_ONLY` nunca se exportan como bloqueo.
